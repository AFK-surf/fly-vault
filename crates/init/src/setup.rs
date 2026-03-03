use crate::fuse::{ensure_image_file, mount_crypto_fs, CryptoMount};
use anyhow::{anyhow, Context, Result};
use crypto::XtsKey;
use nix::mount::{mount, MsFlags};
use nix::sched::{clone, CloneFlags};
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag};
use nix::unistd::{chdir, chroot, execv, Pid};
use protocol::VmState;
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tokio::task;
use tracing::warn;

#[derive(Debug)]
pub struct SetupManager {
    fuse_mount_dir: PathBuf,
    root_mount_dir: PathBuf,
    init_binary: PathBuf,
    encrypted_img: PathBuf,
    provisioned_marker: PathBuf,
    test_mode: bool,
    runtime: Option<RuntimeState>,
}

#[derive(Debug)]
struct RuntimeState {
    _mount: Option<CryptoMount>,
    _loop_device: PathBuf,
    _inner_init_pid: Option<Pid>,
}

impl SetupManager {
    pub fn new(
        data_dir: PathBuf,
        fuse_mount_dir: PathBuf,
        root_mount_dir: PathBuf,
        init_binary: PathBuf,
        test_mode: bool,
    ) -> Result<Self> {
        let encrypted_img = data_dir.join("encrypted.img");
        let provisioned_marker = data_dir.join(".provisioned");
        Ok(Self {
            fuse_mount_dir,
            root_mount_dir,
            init_binary,
            encrypted_img,
            provisioned_marker,
            test_mode,
            runtime: None,
        })
    }

    pub fn root_mount_dir(&self) -> &Path {
        &self.root_mount_dir
    }

    pub fn inner_init_pid(&self) -> Option<Pid> {
        self.runtime.as_ref().and_then(|r| r._inner_init_pid)
    }

    pub fn detect_state(&self) -> Result<VmState> {
        if self.runtime.is_some() {
            return Ok(VmState::Ready);
        }
        if self.provisioned_marker.exists() {
            Ok(VmState::Locked)
        } else {
            Ok(VmState::Cold)
        }
    }

    pub async fn unlock_and_prepare(
        &mut self,
        key: XtsKey,
        rootfs_tarball: Option<Vec<u8>>,
    ) -> Result<()> {
        if self.runtime.is_some() {
            return Ok(());
        }

        let was_cold = !self.provisioned_marker.exists();
        let key_hash: [u8; 32] = Sha256::digest(key.as_bytes()).into();

        if !was_cold {
            let stored = fs::read(&self.provisioned_marker).context("read provisioned marker")?;
            if stored.len() != 32 || stored.as_slice() != key_hash {
                return Err(anyhow!("key hash mismatch — refusing to decrypt"));
            }
        }

        let encrypted_img = self.encrypted_img.clone();
        task::spawn_blocking(move || ensure_image_file(&encrypted_img))
            .await
            .context("join ensure image file")??;

        if was_cold && rootfs_tarball.is_none() {
            return Err(anyhow!("cold boot requires ProvisionRootfs payload"));
        }

        if self.test_mode {
            if was_cold {
                fs::write(&self.provisioned_marker, key_hash)
                    .context("write provisioned marker")?;
            }
            self.runtime = Some(RuntimeState {
                _mount: None,
                _loop_device: PathBuf::from("/dev/loop-test"),
                _inner_init_pid: None,
            });
            return Ok(());
        }

        let crypto_mount = task::spawn_blocking({
            let encrypted_img = self.encrypted_img.clone();
            let fuse_mount_dir = self.fuse_mount_dir.clone();
            move || mount_crypto_fs(encrypted_img, fuse_mount_dir, key)
        })
        .await
        .context("join mount crypto fs")??;

        let decrypted_img = crypto_mount.decrypted_path.clone();
        let loop_device = attach_loop_device(&decrypted_img)?;

        if was_cold {
            run_cmd(
                Command::new("mkfs.ext4")
                    .args(["-F", "-E", "nodiscard"])
                    .arg(&loop_device),
                "mkfs.ext4",
            )?;
        }

        fs::create_dir_all(&self.root_mount_dir)
            .with_context(|| format!("create {}", self.root_mount_dir.display()))?;

        mount(
            Some(loop_device.as_path()),
            self.root_mount_dir.as_path(),
            Some("ext4"),
            MsFlags::empty(),
            None::<&str>,
        )
        .context("mount decrypted filesystem")?;

        run_cmd(
            Command::new("resize2fs").arg(&loop_device),
            "resize2fs",
        )?;

        if let Some(data) = rootfs_tarball {
            extract_rootfs(&self.root_mount_dir, &data)?;
        }

        if was_cold {
            fs::write(&self.provisioned_marker, key_hash).context("write provisioned marker")?;
        }

        let inner_init_pid = {
            let init_in_chroot = self.root_mount_dir.join(
                self.init_binary
                    .strip_prefix("/")
                    .unwrap_or(&self.init_binary),
            );
            if !init_in_chroot.exists() {
                warn!(
                    path = %self.init_binary.display(),
                    "init binary not found in rootfs, skipping inner init"
                );
                None
            } else {
                match launch_namespaced_init(&self.root_mount_dir, &self.init_binary) {
                    Ok(pid) => Some(pid),
                    Err(err) => {
                        warn!(error = ?err, "inner init launch failed, continuing without it");
                        None
                    }
                }
            }
        };

        self.runtime = Some(RuntimeState {
            _mount: Some(crypto_mount),
            _loop_device: loop_device,
            _inner_init_pid: inner_init_pid,
        });

        Ok(())
    }
}

fn attach_loop_device(backing_file: &Path) -> Result<PathBuf> {
    let output = Command::new("losetup")
        .arg("--find")
        .arg("--show")
        .arg(backing_file)
        .output()
        .context("run losetup")?;

    if !output.status.success() {
        return Err(anyhow!(
            "losetup failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let dev = String::from_utf8(output.stdout)
        .context("parse losetup stdout utf-8")?
        .trim()
        .to_string();

    if dev.is_empty() {
        return Err(anyhow!("losetup returned empty loop device path"));
    }

    Ok(PathBuf::from(dev))
}

fn extract_rootfs(target_root: &Path, data: &[u8]) -> Result<()> {
    let decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(data));
    let mut archive = tar::Archive::new(decoder);
    archive
        .unpack(target_root)
        .with_context(|| format!("extract rootfs into {}", target_root.display()))?;
    Ok(())
}

fn launch_namespaced_init(root: &Path, init_binary: &Path) -> Result<Pid> {
    prepare_mounts(root)?;

    let mut stack = vec![0u8; 1024 * 1024];
    let root = root.to_path_buf();
    let init_binary = init_binary.to_path_buf();

    let cb = Box::new(move || -> isize {
        if let Err(err) = child_bootstrap(&root, &init_binary) {
            eprintln!("child bootstrap failed: {err:#}");
            return 1;
        }
        0
    });

    let flags = CloneFlags::CLONE_NEWPID;
    let pid = unsafe { clone(cb, &mut stack, flags, Some(Signal::SIGCHLD as i32)) }
        .context("clone pid namespace")?;

    Ok(pid)
}

fn child_bootstrap(root: &Path, init_binary: &Path) -> Result<()> {
    chroot(root).with_context(|| format!("chroot {}", root.display()))?;
    chdir("/").context("chdir / after chroot")?;

    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::empty(),
        None::<&str>,
    )
    .context("mount /proc")?;

    mount(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        MsFlags::empty(),
        None::<&str>,
    )
    .context("mount /sys")?;

    let init = CString::new(init_binary.as_os_str().as_encoded_bytes().to_vec())
        .context("init path contains NUL")?;
    execv(&init, &[init.as_c_str()]).context("exec init")?;
    unreachable!()
}

fn prepare_mounts(root: &Path) -> Result<()> {
    let binds = [
        ("/dev", "dev"),
        ("/dev/pts", "dev/pts"),
        ("/dev/shm", "dev/shm"),
    ];
    for (src, dst_rel) in binds {
        let dst = root.join(dst_rel);
        fs::create_dir_all(&dst).with_context(|| format!("create {}", dst.display()))?;
        mount(
            Some(src),
            dst.as_path(),
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .with_context(|| format!("bind mount {src} -> {}", dst.display()))?;
    }

    let tmp = root.join("tmp");
    fs::create_dir_all(&tmp).with_context(|| format!("create {}", tmp.display()))?;
    mount(
        Some("tmpfs"),
        tmp.as_path(),
        Some("tmpfs"),
        MsFlags::empty(),
        Some("size=512m"),
    )
    .context("mount tmpfs /tmp")?;

    Ok(())
}

fn run_cmd(cmd: &mut Command, name: &str) -> Result<()> {
    let output = cmd.output().with_context(|| format!("spawn {name}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(anyhow!(
        "{name} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    ))
}

#[allow(dead_code)]
fn reap_pid(pid: Pid) -> Result<()> {
    let _ = waitpid(pid, Some(WaitPidFlag::empty())).context("waitpid")?;
    Ok(())
}
