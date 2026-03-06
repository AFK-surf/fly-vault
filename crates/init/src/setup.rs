use anyhow::{anyhow, Context, Result};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{clone, CloneFlags};
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::waitpid;
use nix::unistd::{chdir, execv, pivot_root, Pid};
use protocol::VmState;
use std::ffi::CString;
use std::fs;
use std::os::unix::fs as unix_fs;
use std::path::{Path, PathBuf};
use tokio::task;
use tracing::{info, warn};

#[derive(Debug)]
pub struct SetupManager {
    root_mount_dir: PathBuf,
    init_binary: PathBuf,
    provisioned_marker_file: PathBuf,
    persistent_mounts: Vec<PersistentMount>,
    test_mode: bool,
    runtime: Option<RuntimeState>,
}

#[derive(Debug)]
struct RuntimeState {
    _inner_init_pid: Option<Pid>,
}

#[derive(Debug, Clone)]
struct PersistentMount {
    source: PathBuf,
    target_relative: PathBuf,
}

impl SetupManager {
    pub fn new(
        data_dir: PathBuf,
        root_mount_dir: PathBuf,
        init_binary: PathBuf,
        test_mode: bool,
    ) -> Result<Self> {
        let provisioned_marker_file = data_dir.join(".provisioned");
        let persistent_state_dir = data_dir.join("persist");
        Ok(Self {
            root_mount_dir,
            init_binary,
            provisioned_marker_file,
            persistent_mounts: vec![
                PersistentMount {
                    source: persistent_state_dir.join("root"),
                    target_relative: PathBuf::from("root"),
                },
                PersistentMount {
                    source: persistent_state_dir.join("home"),
                    target_relative: PathBuf::from("home"),
                },
            ],
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
        if self.runtime.is_some() || self.provisioned_marker_file.exists() {
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

    pub async fn setup_and_prepare(&mut self, rootfs_tarball: Option<Vec<u8>>) -> Result<()> {
        let was_cold = !self.provisioned_marker_file.exists();
        let is_provisioning = rootfs_tarball.is_some();
        let is_reprovision = !was_cold && is_provisioning;

        if was_cold && !is_provisioning {
            return Err(anyhow!("cold boot requires ProvisionRootfs payload"));
        }

        if is_reprovision {
            self.stop_runtime().await?;
            self.clear_provision_marker()?;
        }

        if self.test_mode {
            if is_provisioning {
                self.reset_root_mount_dir()?;
                extract_rootfs_if_present(&self.root_mount_dir, rootfs_tarball.as_deref())?;
                self.prepare_persistent_layout()?;
                self.store_provision_marker()?;
            }
            self.ensure_runtime_started()?;
            return Ok(());
        }

        if let Some(data) = rootfs_tarball {
            self.reset_root_mount_dir()?;
            extract_rootfs(&self.root_mount_dir, &data)?;
            self.prepare_persistent_layout()?;
            self.store_provision_marker()?;
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

    fn store_provision_marker(&self) -> Result<()> {
        fs::write(&self.provisioned_marker_file, b"1")
            .with_context(|| format!("write {}", self.provisioned_marker_file.display()))
    }

    fn ensure_runtime_started(&mut self) -> Result<()> {
        if self.runtime.is_some() {
            return Ok(());
        }

        if self.test_mode {
            self.materialize_test_mode_persistent_links()?;
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
                match launch_namespaced_init(
                    &self.root_mount_dir,
                    &self.init_binary,
                    self.persistent_mounts.clone(),
                ) {
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
        match fs::remove_file(&self.provisioned_marker_file) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err)
                .with_context(|| format!("remove {}", self.provisioned_marker_file.display())),
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

    fn prepare_persistent_layout(&self) -> Result<()> {
        for persistent_mount in &self.persistent_mounts {
            let target = self.root_mount_dir.join(&persistent_mount.target_relative);
            self.ensure_persistent_source_dir(persistent_mount, &target)?;

            if self.test_mode {
                replace_with_symlink(&persistent_mount.source, &target)?;
            } else {
                ensure_directory(&target)?;
            }
        }
        Ok(())
    }

    fn ensure_persistent_source_dir(
        &self,
        persistent_mount: &PersistentMount,
        target: &Path,
    ) -> Result<()> {
        if !persistent_mount.source.exists() {
            if let Ok(metadata) = fs::symlink_metadata(target) {
                if metadata.is_dir() {
                    if let Some(parent) = persistent_mount.source.parent() {
                        fs::create_dir_all(parent)
                            .with_context(|| format!("create {}", parent.display()))?;
                    }
                    fs::rename(target, &persistent_mount.source).with_context(|| {
                        format!(
                            "move {} to {}",
                            target.display(),
                            persistent_mount.source.display()
                        )
                    })?;
                } else {
                    return Err(anyhow!(
                        "persistent target {} must be a directory",
                        target.display()
                    ));
                }
            }
        }

        ensure_directory(&persistent_mount.source)
    }

    fn materialize_test_mode_persistent_links(&self) -> Result<()> {
        for persistent_mount in &self.persistent_mounts {
            let target = self.root_mount_dir.join(&persistent_mount.target_relative);
            self.ensure_persistent_source_dir(persistent_mount, &target)?;
            replace_with_symlink(&persistent_mount.source, &target)?;
        }
        Ok(())
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

fn extract_rootfs_if_present(target_root: &Path, data: Option<&[u8]>) -> Result<()> {
    if let Some(data) = data {
        extract_rootfs(target_root, data)?;
    }
    Ok(())
}

fn launch_namespaced_init(
    root: &Path,
    init_binary: &Path,
    persistent_mounts: Vec<PersistentMount>,
) -> Result<Pid> {
    let mut stack = vec![0u8; 1024 * 1024];
    let root = root.to_path_buf();
    let init_binary = init_binary.to_path_buf();

    let cb = Box::new(move || -> isize {
        if let Err(err) = child_bootstrap(&root, &init_binary, &persistent_mounts) {
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

fn child_bootstrap(
    root: &Path,
    init_binary: &Path,
    persistent_mounts: &[PersistentMount],
) -> Result<()> {
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

    bind_persistent_mounts(root, persistent_mounts)?;

    let old_root = root.join(".old_root");
    if !old_root.exists() {
        fs::create_dir_all(&old_root)
            .with_context(|| format!("create old root dir {}", old_root.display()))?;
    }

    pivot_root(root, &old_root).with_context(|| format!("pivot_root to {}", root.display()))?;

    chdir("/").context("chdir /")?;

    umount2("/.old_root", MntFlags::MNT_DETACH).context("umount old root")?;
    let _ = fs::remove_dir("/.old_root");

    let init_c = CString::new(
        init_binary
            .to_str()
            .ok_or_else(|| anyhow!("init path contains non-utf8"))?,
    )
    .context("init cstring")?;
    let args = [init_c.clone()];

    execv(&init_c, &args).with_context(|| format!("exec {}", init_binary.display()))?;
    Ok(())
}

fn bind_persistent_mounts(root: &Path, persistent_mounts: &[PersistentMount]) -> Result<()> {
    for persistent_mount in persistent_mounts {
        ensure_directory(&persistent_mount.source)?;

        let target = root.join(&persistent_mount.target_relative);
        ensure_directory(&target)?;

        mount(
            Some(persistent_mount.source.as_path()),
            &target,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .with_context(|| {
            format!(
                "bind-mount persistent {} onto {}",
                persistent_mount.source.display(),
                target.display()
            )
        })?;
    }

    Ok(())
}

fn ensure_directory(path: &Path) -> Result<()> {
    if path.exists() {
        let metadata =
            fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
        if metadata.is_dir() {
            return Ok(());
        }
        return Err(anyhow!("{} must be a directory", path.display()));
    }

    fs::create_dir_all(path).with_context(|| format!("create {}", path.display()))
}

fn replace_with_symlink(source: &Path, target: &Path) -> Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(target) {
        let file_type = metadata.file_type();
        if file_type.is_symlink() || file_type.is_file() {
            fs::remove_file(target).with_context(|| format!("remove {}", target.display()))?;
        } else if metadata.is_dir() {
            fs::remove_dir_all(target).with_context(|| format!("remove {}", target.display()))?;
        } else {
            return Err(anyhow!(
                "cannot replace unsupported target type at {}",
                target.display()
            ));
        }
    }

    unix_fs::symlink(source, target)
        .with_context(|| format!("symlink {} -> {}", target.display(), source.display()))
}
