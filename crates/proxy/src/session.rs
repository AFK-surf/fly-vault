use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

pub struct Session {
    pub backend_sock: Arc<UdpSocket>,
    pub backend_addr: SocketAddr,
    pub last_activity: Arc<AtomicU64>,
    pub relay_handle: JoinHandle<()>,
}

pub type SessionMap = Arc<RwLock<HashMap<SocketAddr, Arc<Session>>>>;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub async fn get_or_create_session(
    sessions: &SessionMap,
    frontend: &Arc<UdpSocket>,
    client_addr: SocketAddr,
    backend_addr: SocketAddr,
) -> Arc<Session> {
    // Fast path: read lock
    {
        let map = sessions.read().await;
        if let Some(session) = map.get(&client_addr) {
            if session.backend_addr == backend_addr {
                session.last_activity.store(now_secs(), Ordering::Relaxed);
                return Arc::clone(session);
            }
            // Backend changed — fall through to recreate
        } else {
            // No session — fall through to create
            drop(map);
            return create_session(sessions, frontend, client_addr, backend_addr).await;
        }
    }

    // Backend addr changed: remove old, create new
    {
        let mut map = sessions.write().await;
        if let Some(old) = map.remove(&client_addr) {
            old.relay_handle.abort();
            debug!(%client_addr, "removed stale session (backend changed)");
        }
    }

    create_session(sessions, frontend, client_addr, backend_addr).await
}

async fn create_session(
    sessions: &SessionMap,
    frontend: &Arc<UdpSocket>,
    client_addr: SocketAddr,
    backend_addr: SocketAddr,
) -> Arc<Session> {
    let mut map = sessions.write().await;

    // Double-check after acquiring write lock
    if let Some(session) = map.get(&client_addr) {
        if session.backend_addr == backend_addr {
            session.last_activity.store(now_secs(), Ordering::Relaxed);
            return Arc::clone(session);
        }
        // Still mismatched — remove
        if let Some(old) = map.remove(&client_addr) {
            old.relay_handle.abort();
        }
    }

    let backend_sock = Arc::new(
        UdpSocket::bind("[::]:0")
            .await
            .expect("bind backend socket"),
    );
    backend_sock
        .connect(backend_addr)
        .await
        .expect("connect backend socket");

    let last_activity = Arc::new(AtomicU64::new(now_secs()));

    let relay_handle = spawn_relay(
        Arc::clone(&backend_sock),
        Arc::clone(frontend),
        client_addr,
        Arc::clone(&last_activity),
    );

    let session = Arc::new(Session {
        backend_sock,
        backend_addr,
        last_activity,
        relay_handle,
    });

    debug!(%client_addr, %backend_addr, "created new session");
    map.insert(client_addr, Arc::clone(&session));
    session
}

fn spawn_relay(
    backend_sock: Arc<UdpSocket>,
    frontend: Arc<UdpSocket>,
    client_addr: SocketAddr,
    last_activity: Arc<AtomicU64>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match backend_sock.recv(&mut buf).await {
                Ok(n) => {
                    last_activity.store(now_secs(), Ordering::Relaxed);
                    if let Err(e) = frontend.send_to(&buf[..n], client_addr).await {
                        warn!(%client_addr, error = %e, "relay send_to failed");
                        break;
                    }
                }
                Err(e) => {
                    debug!(%client_addr, error = %e, "relay recv failed");
                    break;
                }
            }
        }
    })
}

pub async fn cleanup_sessions(sessions: SessionMap, timeout: Duration) {
    let sweep_interval = Duration::from_secs(30);
    loop {
        tokio::time::sleep(sweep_interval).await;
        let now = now_secs();
        let timeout_secs = timeout.as_secs();

        let mut map = sessions.write().await;
        let before = map.len();
        map.retain(|client_addr, session| {
            let last = session.last_activity.load(Ordering::Relaxed);
            if now.saturating_sub(last) > timeout_secs {
                session.relay_handle.abort();
                info!(%client_addr, "expired idle session");
                false
            } else {
                true
            }
        });
        let removed = before - map.len();
        if removed > 0 {
            info!(removed, remaining = map.len(), "session cleanup sweep");
        }
    }
}
