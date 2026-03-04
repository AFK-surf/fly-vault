use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use reqwest::Client;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::machines::{self, FullMachineMap, MachineMap};
use crate::session::{self, SessionMap};

pub type StartingSet = Arc<Mutex<HashSet<String>>>;

pub async fn run_proxy(
    frontend: Arc<UdpSocket>,
    machine_map: MachineMap,
    full_machine_map: FullMachineMap,
    sessions: SessionMap,
    backend_port: u16,
    http_client: Client,
    api_token: String,
    app: String,
    starting: StartingSet,
) {
    let mut buf = vec![0u8; 65535];

    loop {
        let (n, client_addr) = match frontend.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "recv_from failed");
                continue;
            }
        };

        let packet = &buf[..n];

        // Parse header: [machine_id_len: u64 LE (8 bytes)][machine_id][payload...]
        if packet.len() < 8 {
            debug!(%client_addr, len = n, "packet too short for header");
            continue;
        }

        let id_len = u64::from_le_bytes(packet[..8].try_into().unwrap()) as usize;

        if packet.len() < 8 + id_len {
            debug!(%client_addr, id_len, len = n, "packet too short for machine id");
            continue;
        }

        let machine_id = match std::str::from_utf8(&packet[8..8 + id_len]) {
            Ok(s) => s,
            Err(_) => {
                debug!(%client_addr, "invalid utf-8 in machine id");
                continue;
            }
        };

        let payload = &packet[8 + id_len..];
        if payload.is_empty() {
            debug!(%client_addr, %machine_id, "empty payload after header");
            continue;
        }

        // Look up backend IP
        let backend_addr = {
            let map = machine_map.read().await;
            match map.get(machine_id) {
                Some(ip) => SocketAddr::new(*ip, backend_port),
                None => {
                    // Machine not in started map — check if it's stopped and kick off a start
                    maybe_start_machine(
                        machine_id,
                        &full_machine_map,
                        &starting,
                        &http_client,
                        &api_token,
                        &app,
                        &machine_map,
                    );
                    debug!(%client_addr, %machine_id, "machine not ready, dropping packet");
                    continue;
                }
            }
        };

        // Get or create session and forward
        let session =
            session::get_or_create_session(&sessions, &frontend, client_addr, backend_addr).await;

        if let Err(e) = session.backend_sock.send(payload).await {
            warn!(%client_addr, %machine_id, error = %e, "send to backend failed");
        }
    }
}

/// If the machine exists but is stopped or suspended, spawn a background task
/// to start it via the Machines API. Uses `starting` set to deduplicate
/// concurrent start attempts for the same machine.
fn maybe_start_machine(
    machine_id: &str,
    full_map: &FullMachineMap,
    starting: &StartingSet,
    client: &Client,
    api_token: &str,
    app: &str,
    machine_map: &MachineMap,
) {
    let full_map = full_map.clone();
    let starting = starting.clone();
    let client = client.clone();
    let api_token = api_token.to_string();
    let app = app.to_string();
    let machine_map = machine_map.clone();
    let machine_id = machine_id.to_string();

    tokio::spawn(async move {
        // Check if machine is in a startable state
        let state = {
            let map = full_map.read().await;
            map.get(&machine_id).map(|info| info.state.clone())
        };

        let should_start = matches!(state.as_deref(), Some("stopped" | "suspended" | "created"));
        if !should_start {
            return;
        }

        // Acquire starting guard (only one start per machine at a time)
        {
            let mut set = starting.lock().await;
            if set.contains(&machine_id) {
                return;
            }
            set.insert(machine_id.clone());
        }

        info!(%machine_id, state = state.as_deref().unwrap_or("?"), "starting stopped machine");

        if let Err(e) = machines::start_machine(&client, &api_token, &app, &machine_id).await {
            warn!(%machine_id, error = %e, "failed to start machine");
            starting.lock().await.remove(&machine_id);
            return;
        }

        if let Err(e) = machines::wait_for_started(&client, &api_token, &app, &machine_id).await {
            warn!(%machine_id, error = %e, "machine failed to reach started state");
            starting.lock().await.remove(&machine_id);
            return;
        }

        info!(%machine_id, "machine started, refreshing map");
        machines::refresh_once(&client, &api_token, &app, &machine_map, &full_map).await;
        starting.lock().await.remove(&machine_id);
    });
}
