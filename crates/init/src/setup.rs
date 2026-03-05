use anyhow::{anyhow, Context, Result};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{clone, CloneFlags};
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::waitpid;
use nix::unistd::{chdir, execv, pivot_root, Pid};
use protocol::VmState;
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};
use tokio::task;
use tracing::{info, warn};

#[derive(Debug)]
pub struct SetupManager {
    root_mount_dir: PathBuf,
    init_binary: PathBuf,
    token_hash_file: PathBuf,
    test_mode: bool,
    runtime: Option<RuntimeState>,
}

#[derive(Debug)]
struct RuntimeState {
    _inner_init_pid: Option<Pid>,
}

impl SetupManager {
    pub fn new(
        data_dir: PathBuf,
        root_mount_dir: PathBuf,
        init_binary: PathBuf,
        test_mode: bool,
    ) -> Result<Self> {
        let token_hash_file = data_dir.join(".access_token_hash");
        Ok(Self {
            root_mount_dir,
            init_binary,
            token_hash_file,
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

    pub fn runtime_started(&self) -> bool {
        self.runtime.is_some()
    }

    pub fn detect_state(&self) -> Result<VmState> {
        if self.runtime.is_some() || self.token_hash_file.exists() {
            Ok(VmState::Ready)
        } else {
            Ok(VmState::Cold)
        }
    }

    pub fn start_ready_runtime(&mut self) -> Result<()> {
        if self.detect_state()? != VmState::Ready {
            return Ok(());
        }
        self.ensure_runtime_started()
    }

    pub fn verify_token_hash(&self, token: &str) -> Result<bool> {
        let stored = match fs::read(&self.token_hash_file) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(err) => {
                return Err(err).with_context(|| format!("read {}", self.token_hash_file.display()))
            }
        };

        if stored.len() != 32 {
            return Err(anyhow!(
                "invalid access token hash size in {}: got {} expected 32",
                self.token_hash_file.display(),
                stored.len()
            ));
        }

        let incoming_hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        Ok(stored.as_slice() == incoming_hash)
    }

    pub async fn setup_and_prepare(
        &mut self,
        token: &str,
        rootfs_tarball: Option<Vec<u8>>,
    ) -> Result<()> {
        let was_cold = !self.token_hash_file.exists();
        let is_provisioning = rootfs_tarball.is_some();
        let is_reprovision = !was_cold && is_provisioning;

        if was_cold && !is_provisioning {
            return Err(anyhow!("cold boot requires ProvisionRootfs payload"));
        }

        if !was_cold && !self.verify_token_hash(token)? {
            return Err(anyhow!("access token hash mismatch"));
        }

        if is_reprovision {
            self.stop_runtime().await?;
            self.clear_provision_marker()?;
        }

        if self.test_mode {
            if is_provisioning {
                self.reset_root_mount_dir()?;
                self.store_token_hash(token)?;
            }
            self.ensure_runtime_started()?;
            return Ok(());
        }

        if let Some(data) = rootfs_tarball {
            self.reset_root_mount_dir()?;
            extract_rootfs(&self.root_mount_dir, &data)?;
            self.store_token_hash(token)?;
        }

        self.ensure_runtime_started()
    }

    pub async fn shutdown(&mut self) {
        if !self.runtime_started() {
            info!("shutdown: no active runtime, nothing to tear down");
            return;
        }
        let _ = self.stop_runtime().await;

        info!("shutdown: complete");
    }

    fn store_token_hash(&self, token: &str) -> Result<()> {
        let hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        fs::write(&self.token_hash_file, hash)
            .with_context(|| format!("write {}", self.token_hash_file.display()))
    }

    fn ensure_runtime_started(&mut self) -> Result<()> {
        if self.runtime.is_some() {
            return Ok(());
        }

        if self.test_mode {
            self.runtime = Some(RuntimeState {
                _inner_init_pid: None,
            });
            return Ok(());
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
            _inner_init_pid: inner_init_pid,
        });

        Ok(())
    }

    async fn stop_runtime(&mut self) -> Result<()> {
        let Some(runtime) = self.runtime.take() else {
            return Ok(());
        };

        if let Some(pid) = runtime._inner_init_pid {
            info!(
                pid = pid.as_raw(),
                "reprovision/shutdown: sending SIGKILL to inner init"
            );
            let _ = kill(pid, Signal::SIGKILL);
            let _ = task::spawn_blocking(move || {
                let _ = waitpid(pid, None);
                info!(
                    pid = pid.as_raw(),
                    "reprovision/shutdown: inner init reaped"
                );
            })
            .await;
        }

        Ok(())
    }

    fn clear_provision_marker(&self) -> Result<()> {
        match fs::remove_file(&self.token_hash_file) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => {
                Err(err).with_context(|| format!("remove {}", self.token_hash_file.display()))
            }
        }
    }

    fn reset_root_mount_dir(&self) -> Result<()> {
        if self.root_mount_dir.exists() {
            fs::remove_dir_all(&self.root_mount_dir)
                .with_context(|| format!("remove {}", self.root_mount_dir.display()))?;
        }
        fs::create_dir_all(&self.root_mount_dir)
            .with_context(|| format!("create {}", self.root_mount_dir.display()))
    }
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

    let flags = CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWNS;
    let pid = unsafe { clone(cb, &mut stack, flags, Some(Signal::SIGCHLD as i32)) }
        .context("clone pid+mount namespace")?;

    Ok(pid)
}

fn child_bootstrap(root: &Path, init_binary: &Path) -> Result<()> {
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .context("set mount propagation private")?;

    // pivot_root requires the new root to be a mount point. Since /data/rootfs
    // is now a plain directory on the data volume, bind-mount it onto itself first.
    mount(
        Some(root),
        root,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .with_context(|| format!("bind-mount new root {}", root.display()))?;

    prepare_mounts(root)?;

    let old_root = root.join(".old_root");
    fs::create_dir_all(&old_root).with_context(|| format!("create {}", old_root.display()))?;
    pivot_root(root, &old_root)
        .with_context(|| format!("pivot_root {} {}", root.display(), old_root.display()))?;
    chdir("/").context("chdir / after pivot_root")?;
    umount2("/.old_root", MntFlags::MNT_DETACH).context("detach old root")?;
    fs::remove_dir("/.old_root").context("remove /.old_root")?;

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
