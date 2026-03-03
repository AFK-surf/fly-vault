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

#[derive(Deserialize)]
struct MachineEntry {
    id: String,
    state: String,
    private_ip: Option<String>,
}

pub async fn refresh_once(client: &Client, api_token: &str, app: &str, map: &MachineMap) {
    match fetch_machines(client, api_token, app).await {
        Ok(entries) => {
            let mut new_map = HashMap::new();
            for entry in entries {
                if entry.state != "started" {
                    continue;
                }
                if let Some(ip_str) = &entry.private_ip {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        new_map.insert(entry.id.clone(), ip);
                    }
                }
            }
            info!(count = new_map.len(), "refreshed machine map");
            *map.write().await = new_map;
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

pub async fn poll_machines(
    client: Client,
    api_token: String,
    app: String,
    map: MachineMap,
    interval: Duration,
) {
    loop {
        tokio::time::sleep(interval).await;
        refresh_once(&client, &api_token, &app, &map).await;
    }
}
