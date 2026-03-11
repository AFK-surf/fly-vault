mod attest;
mod firewall;
mod forward;
mod quic;
mod setup;

#[cfg(test)]
mod tests;

use anyhow::Context;
use clap::Parser;
use protocol::VmState;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::Mutex;
use tracing::{info, warn};

#[derive(Debug, Parser, Clone)]
#[command(name = "init")]
struct Args {
    #[arg(long, default_value = "[::]:8443", env = "VAULT_LISTEN")]
    listen: String,

    #[arg(long, default_value = "/data")]
    data_dir: PathBuf,

    #[arg(long, default_value = "/data/rootfs")]
    root_mount_dir: PathBuf,

    #[arg(long, default_value = "/sbin/init")]
    init_binary: PathBuf,

    #[arg(long, default_value_t = false)]
    test_mode: bool,
}

#[derive(Debug)]
pub struct SharedState {
    pub vm_state: VmState,
    pub setup: setup::SetupManager,
    pub access_token: Option<String>,
    pub console: Arc<forward::SharedConsoleManager>,
    pub exec_sessions: Arc<forward::ExecSessionManager>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    if !args.test_mode {
        let listen_port = args
            .listen
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok())
            .context("parse listen port from address")?;
        firewall::setup(listen_port).context("set up nftables firewall")?;
    }

    let mut setup = setup::SetupManager::new(
        args.data_dir.clone(),
        args.root_mount_dir.clone(),
        args.init_binary.clone(),
        args.test_mode,
    )?;

    let access_token = std::env::var("ACCESS_TOKEN").ok();
    std::env::remove_var("ACCESS_TOKEN");
    if access_token.is_some() {
        info!("ACCESS_TOKEN set");
    } else {
        warn!("ACCESS_TOKEN not set; provisioning/reconnect will be rejected");
    }

    let initial_state = setup.detect_state()?;
    info!(state = ?initial_state, "boot state detected");
    if initial_state == VmState::Ready {
        setup
            .start_ready_runtime()
            .context("start namespaced init for ready state")?;
    }
    let initial_state = setup.detect_state()?;

    let shared = Arc::new(Mutex::new(SharedState {
        vm_state: initial_state,
        setup,
        access_token,
        console: Arc::new(forward::SharedConsoleManager::new()),
        exec_sessions: forward::ExecSessionManager::new_arced(),
    }));

    let mut sigterm = signal(SignalKind::terminate()).context("install SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("install SIGTERM handler")?;

    tokio::select! {
        result = quic::serve(args, Arc::clone(&shared)) => result?,
        _ = sigterm.recv() => {
            info!("SIGTERM received, shutting down");
        }
        _ = sigint.recv() => {
            info!("SIGINT received, shutting down");
        }
    }

    info!("running shutdown");
    shared.lock().await.setup.shutdown().await;
    info!("shutdown complete, exiting");
    Ok(())
}
