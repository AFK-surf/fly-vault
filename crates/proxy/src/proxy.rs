use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tracing::{debug, warn};

use crate::machines::MachineMap;
use crate::session::{self, SessionMap};

pub async fn run_proxy(
    frontend: Arc<UdpSocket>,
    machine_map: MachineMap,
    sessions: SessionMap,
    backend_port: u16,
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
                    debug!(%client_addr, %machine_id, "unknown machine id");
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
