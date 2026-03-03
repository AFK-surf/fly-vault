mod attest;
mod forward;
mod fuse;
mod quic;
mod setup;

#[cfg(test)]
mod tests;

use clap::Parser;
use protocol::VmState;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn};

#[derive(Debug, Parser, Clone)]
#[command(name = "init")]
struct Args {
    #[arg(long, default_value = "[::]:8443", env = "VAULT_LISTEN")]
    listen: String,

    #[arg(long, default_value = "/data")]
    data_dir: PathBuf,

    #[arg(long, default_value = "/tmp/fuse")]
    fuse_mount_dir: PathBuf,

    #[arg(long, default_value = "/mnt/root")]
    root_mount_dir: PathBuf,

    #[arg(long, default_value = "/sbin/init")]
    init_binary: PathBuf,

    #[arg(long, default_value_t = 20 * 1024 * 1024 * 1024_u64)]
    image_size_bytes: u64,

    #[arg(long, default_value = "fly-vault-channel-binding")]
    channel_binding_label: String,

    #[arg(long, default_value_t = false)]
    test_mode: bool,
}

#[derive(Debug)]
pub struct SharedState {
    pub vm_state: VmState,
    pub setup: setup::SetupManager,
    pub provision_token: Option<String>,
    pub key_hash: Option<[u8; 32]>,
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

    let setup = setup::SetupManager::new(
        args.data_dir.clone(),
        args.fuse_mount_dir.clone(),
        args.root_mount_dir.clone(),
        args.init_binary.clone(),
        args.image_size_bytes,
        args.test_mode,
    )?;

    let provision_token = std::env::var("PROVISION_TOKEN").ok();
    std::env::remove_var("PROVISION_TOKEN");
    if provision_token.is_some() {
        info!("PROVISION_TOKEN set");
    } else {
        warn!("PROVISION_TOKEN not set; cold boot provisioning will be rejected");
    }

    let initial_state = setup.detect_state()?;
    info!(state = ?initial_state, "boot state detected");

    let shared = Arc::new(Mutex::new(SharedState {
        vm_state: initial_state,
        setup,
        provision_token,
        key_hash: None,
    }));

    quic::serve(args, shared).await
}
