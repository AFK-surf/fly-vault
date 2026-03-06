use anyhow::{anyhow, Context, Result};
use nix::errno::Errno;
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{clone, CloneFlags};
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{chdir, execv, pivot_root, Pid};
use protocol::VmState;
use std::ffi::CString;
use std::fs;
use std::os::unix::fs as unix_fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
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
    inner_init_pid: Pid,
}

#[derive(Debug, Clone)]
struct PersistentMount {
    source: PathBuf,
    target_relative: PathBuf,
}

#[derive(Debug, Clone, Copy)]
enum LaunchMode {
    SystemInitThenFallback,
    FallbackOnly,
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

    pub fn ensure_live_inner_init_pid(&mut self) -> Result<Pid> {
        self.ensure_runtime_started()?;

        if self.test_mode {
            return self
                .runtime
                .as_ref()
                .map(|runtime| runtime.inner_init_pid)
                .ok_or_else(|| anyhow!("test runtime missing after startup"));
        }

        let Some(runtime) = self.runtime.as_ref() else {
            return Err(anyhow!("runtime missing after startup"));
        };

        match poll_runtime(runtime.inner_init_pid)? {
            RuntimePoll::Alive => Ok(runtime.inner_init_pid),
            RuntimePoll::Exited(reason) => {
                info!(
                    pid = runtime.inner_init_pid.as_raw(),
                    %reason,
                    "inner pid 1 exited; starting fallback init in a fresh namespace"
                );
                self.runtime.take();
                self.launch_runtime(LaunchMode::FallbackOnly)
            }
        }
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
                inner_init_pid: Pid::from_raw(std::process::id() as i32),
            });
            return Ok(());
        }

        self.launch_runtime(LaunchMode::SystemInitThenFallback)?;
        Ok(())
    }

    fn launch_runtime(&mut self, launch_mode: LaunchMode) -> Result<Pid> {
        let inner_init_pid = launch_namespaced_init(
            &self.root_mount_dir,
            &self.init_binary,
            self.persistent_mounts.clone(),
            launch_mode,
        )
        .with_context(|| format!("launch namespaced runtime in mode {:?}", launch_mode))?;

        self.runtime = Some(RuntimeState { inner_init_pid });
        Ok(inner_init_pid)
    }

    async fn stop_runtime(&mut self) -> Result<()> {
        let Some(runtime) = self.runtime.take() else {
            return Ok(());
        };

        if self.test_mode {
            return Ok(());
        }

        let pid = runtime.inner_init_pid;
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
    launch_mode: LaunchMode,
) -> Result<Pid> {
    let mut stack = vec![0u8; 1024 * 1024];
    let root = root.to_path_buf();
    let init_binary = init_binary.to_path_buf();

    let cb = Box::new(move || -> isize {
        if let Err(err) = child_bootstrap(&root, &init_binary, &persistent_mounts, launch_mode) {
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
    launch_mode: LaunchMode,
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

    match launch_mode {
        LaunchMode::SystemInitThenFallback => exec_system_init_or_run_fallback(init_binary),
        LaunchMode::FallbackOnly => run_fallback_init(None),
    }
}

fn exec_system_init_or_run_fallback(init_binary: &Path) -> Result<()> {
    let init_c = CString::new(
        init_binary
            .to_str()
            .ok_or_else(|| anyhow!("init path contains non-utf8"))?,
    )
    .context("init cstring")?;
    let args = [init_c.clone()];

    match execv(&init_c, &args) {
        Ok(_) => unreachable!("execv returned success without replacing process"),
        Err(err) => {
            warn!(
                path = %init_binary.display(),
                error = ?err,
                "exec of /sbin/init failed; running fallback init as pid 1"
            );
            run_fallback_init(Some(format!(
                "exec {} failed: {err}",
                init_binary.display()
            )))
        }
    }
}

fn run_fallback_init(reason: Option<String>) -> Result<()> {
    if let Some(reason) = reason {
        warn!(%reason, "fallback init active");
    } else {
        warn!("fallback init active");
    }

    loop {
        match waitpid(None, None) {
            Ok(WaitStatus::Exited(pid, status)) => {
                info!(pid = pid.as_raw(), status, "fallback init reaped child");
            }
            Ok(WaitStatus::Signaled(pid, signal, _)) => {
                info!(
                    pid = pid.as_raw(),
                    ?signal,
                    "fallback init reaped signaled child"
                );
            }
            Ok(WaitStatus::Stopped(_, _))
            | Ok(WaitStatus::PtraceEvent(_, _, _))
            | Ok(WaitStatus::PtraceSyscall(_))
            | Ok(WaitStatus::Continued(_)) => {}
            Ok(WaitStatus::StillAlive) => {}
            Err(Errno::ECHILD) => std::thread::sleep(Duration::from_millis(250)),
            Err(err) => return Err(err).context("fallback init waitpid"),
        }
    }
}

enum RuntimePoll {
    Alive,
    Exited(String),
}

fn poll_runtime(pid: Pid) -> Result<RuntimePoll> {
    match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
        Ok(WaitStatus::StillAlive) => Ok(RuntimePoll::Alive),
        Ok(WaitStatus::Exited(_, status)) => {
            Ok(RuntimePoll::Exited(format!("exit status {status}")))
        }
        Ok(WaitStatus::Signaled(_, signal, _)) => {
            Ok(RuntimePoll::Exited(format!("signal {signal}")))
        }
        Ok(WaitStatus::Stopped(_, _))
        | Ok(WaitStatus::Continued(_))
        | Ok(WaitStatus::PtraceEvent(_, _, _))
        | Ok(WaitStatus::PtraceSyscall(_)) => Ok(RuntimePoll::Alive),
        Err(Errno::ECHILD) => Ok(RuntimePoll::Exited("already reaped".to_string())),
        Err(err) => Err(err).with_context(|| format!("poll inner pid {}", pid.as_raw())),
    }
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
