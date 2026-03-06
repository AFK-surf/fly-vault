use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{info, warn};

pub type MachineMap = Arc<RwLock<HashMap<String, IpAddr>>>;

#[derive(Clone, Debug)]
pub struct MachineInfo {
    pub state: String,
}

pub type FullMachineMap = Arc<RwLock<HashMap<String, MachineInfo>>>;

#[derive(Deserialize)]
struct MachineEntry {
    id: String,
    state: String,
    private_ip: Option<String>,
}

pub async fn refresh_once(
    client: &Client,
    api_token: &str,
    app: &str,
    map: &MachineMap,
    full_map: &FullMachineMap,
) {
    match fetch_machines(client, api_token, app).await {
        Ok(entries) => {
            let mut new_map = HashMap::new();
            let mut new_full = HashMap::new();
            for entry in entries {
                let ip = entry
                    .private_ip
                    .as_ref()
                    .and_then(|s| s.parse::<IpAddr>().ok());
                new_full.insert(
                    entry.id.clone(),
                    MachineInfo {
                        state: entry.state.clone(),
                    },
                );
                if entry.state == "started" {
                    if let Some(ip) = ip {
                        new_map.insert(entry.id.clone(), ip);
                    }
                }
            }
            info!(
                started = new_map.len(),
                total = new_full.len(),
                "refreshed machine map"
            );
            *map.write().await = new_map;
            *full_map.write().await = new_full;
        }
        Err(e) => {
            warn!(error = %e, "failed to refresh machine map, keeping previous");
        }
    }
}

async fn fetch_machines(
    client: &Client,
    api_token: &str,
    app: &str,
) -> anyhow::Result<Vec<MachineEntry>> {
    let url = format!("https://api.machines.dev/v1/apps/{}/machines", app);
    client
        .get(url)
        .bearer_auth(api_token)
        .send()
        .await
        .context("fetch machines list")?
        .error_for_status()
        .context("machines api error status")?
        .json::<Vec<MachineEntry>>()
        .await
        .context("parse machines response")
}

pub async fn start_machine(
    client: &Client,
    api_token: &str,
    app: &str,
    machine_id: &str,
) -> anyhow::Result<()> {
    let url = format!(
        "https://api.machines.dev/v1/apps/{}/machines/{}/start",
        app, machine_id
    );
    client
        .post(&url)
        .bearer_auth(api_token)
        .send()
        .await
        .context("start machine request")?
        .error_for_status()
        .context("start machine error status")?;
    Ok(())
}

pub async fn wait_for_started(
    client: &Client,
    api_token: &str,
    app: &str,
    machine_id: &str,
) -> anyhow::Result<()> {
    let url = format!(
        "https://api.machines.dev/v1/apps/{}/machines/{}/wait",
        app, machine_id
    );
    client
        .get(&url)
        .bearer_auth(api_token)
        .query(&[("state", "started"), ("timeout", "30")])
        .send()
        .await
        .context("wait for machine started")?
        .error_for_status()
        .context("wait for started error status")?;
    Ok(())
}

pub async fn poll_machines(
    client: Client,
    api_token: String,
    app: String,
    map: MachineMap,
    full_map: FullMachineMap,
    interval: Duration,
) {
    loop {
        tokio::time::sleep(interval).await;
        refresh_once(&client, &api_token, &app, &map, &full_map).await;
    }
}
