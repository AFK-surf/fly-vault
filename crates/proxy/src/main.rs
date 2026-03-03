mod machines;
mod proxy;
mod session;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};
use tracing::info;

#[derive(Debug, Parser)]
#[command(name = "vault-proxy")]
struct Args {
    /// Frontend listen port
    #[arg(long, default_value_t = 8443)]
    port: u16,

    /// Backend vault machine port
    #[arg(long, default_value_t = 8443)]
    backend_port: u16,

    /// Machines API poll interval in seconds
    #[arg(long, default_value_t = 15)]
    refresh_interval_secs: u64,

    /// Idle session expiry in seconds
    #[arg(long, default_value_t = 120)]
    session_timeout_secs: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    let fly_app = std::env::var("FLY_APP").context("FLY_APP env var required")?;
    let fly_api_token = std::env::var("FLY_API_TOKEN").context("FLY_API_TOKEN env var required")?;
    let fly_org = std::env::var("FLY_ORG").unwrap_or_default();

    info!(
        app = %fly_app,
        org = %fly_org,
        port = args.port,
        backend_port = args.backend_port,
        refresh_interval_secs = args.refresh_interval_secs,
        session_timeout_secs = args.session_timeout_secs,
        "starting vault-proxy"
    );

    let machine_map: machines::MachineMap = Arc::new(RwLock::new(HashMap::new()));
    let full_machine_map: machines::FullMachineMap = Arc::new(RwLock::new(HashMap::new()));
    let sessions: session::SessionMap = Arc::new(RwLock::new(HashMap::new()));
    let starting: proxy::StartingSet = Arc::new(Mutex::new(HashSet::new()));

    let http_client = reqwest::Client::new();

    // Initial machine map fetch before accepting traffic
    machines::refresh_once(
        &http_client,
        &fly_api_token,
        &fly_app,
        &machine_map,
        &full_machine_map,
    )
    .await;

    let frontend = Arc::new(
        UdpSocket::bind(format!("fly-global-services:{}", args.port))
            .await
            .context("bind frontend socket")?,
    );
    info!(port = args.port, "frontend socket bound");

    let refresh_interval = Duration::from_secs(args.refresh_interval_secs);
    let session_timeout = Duration::from_secs(args.session_timeout_secs);

    tokio::select! {
        _ = machines::poll_machines(
            http_client.clone(),
            fly_api_token.clone(),
            fly_app.clone(),
            machine_map.clone(),
            full_machine_map.clone(),
            refresh_interval,
        ) => {}
        _ = proxy::run_proxy(
            frontend,
            machine_map,
            full_machine_map,
            sessions.clone(),
            args.backend_port,
            http_client,
            fly_api_token,
            fly_app,
            starting,
        ) => {}
        _ = session::cleanup_sessions(sessions, session_timeout) => {}
    }

    Ok(())
}
