use crate::attest;
use crate::forward;
use crate::{Args, SharedState};
use anyhow::{anyhow, Context, Result};
use protocol::{
    AttestationPayload, ControlMessage, RootfsSource, SetupRequest, VmState, CHANNEL_BINDING_LABEL,
    PROTOCOL_VERSION, STREAM_CONSOLE, STREAM_CONTROL, STREAM_PORT_FORWARD,
};
use quinn::{crypto::rustls::QuicServerConfig, Endpoint, ServerConfig};
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

pub async fn serve(args: Args, shared: Arc<Mutex<SharedState>>) -> Result<()> {
    let server_config = build_server_config()?;
    let addr: SocketAddr = args
        .listen
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve --listen address: {}", args.listen))?
        .next()
        .with_context(|| format!("invalid --listen address: {}", args.listen))?;

    let endpoint = Endpoint::server(server_config, addr).context("start quic endpoint")?;
    info!(listen = %args.listen, "init quic server listening");

    loop {
        let Some(connecting) = endpoint.accept().await else {
            return Err(anyhow!("quic endpoint stopped accepting"));
        };

        let args_clone = args.clone();
        let shared_clone = Arc::clone(&shared);
        tokio::spawn(async move {
            if let Err(err) = handle_connection(connecting, args_clone, shared_clone).await {
                error!(error = ?err, "connection failed");
            }
        });
    }
}

fn build_server_config() -> Result<ServerConfig> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .context("generate self-signed cert")?;
    let cert_der = cert.cert.der().clone();
    let key_der = cert.key_pair.serialize_der();

    let cert_chain = vec![rustls_pki_types::CertificateDer::from(cert_der)];
    let key = rustls_pki_types::PrivatePkcs8KeyDer::from(key_der);

    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key.into())
        .context("build rustls server config")?;
    tls.alpn_protocols = vec![b"fly-vault".to_vec()];

    let mut transport = quinn::TransportConfig::default();
    transport.initial_mtu(1200);
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    transport.max_idle_timeout(Some(
        Duration::from_secs(60).try_into().context("idle timeout")?,
    ));
    transport.mtu_discovery_config(None);
    transport.keep_alive_interval(Some(Duration::from_secs(5)));

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(tls).context("build quic rustls server config")?,
    ));
    server_config.transport_config(Arc::new(transport));
    Ok(server_config)
}

async fn handle_connection(
    incoming: quinn::Incoming,
    args: Args,
    shared: Arc<Mutex<SharedState>>,
) -> Result<()> {
    let connecting = incoming
        .accept()
        .map_err(|e| anyhow!("accept incoming: {e}"))?;
    let conn = connecting.await.context("accept quic connection")?;
    info!(remote = %conn.remote_address(), "client connected");

    let mut authenticated = false;

    loop {
        let Ok((mut send, mut recv)) = conn.accept_bi().await else {
            break;
        };
        let stream_ty = recv.read_u8().await.context("read stream type")?;

        match stream_ty {
            STREAM_CONTROL => {
                authenticated =
                    handle_control_stream(&conn, &args, &shared, &mut send, &mut recv).await?;
            }
            STREAM_PORT_FORWARD if !authenticated => {
                warn!("rejecting unauthenticated port-forward stream");
                let _ = send.reset(quinn::VarInt::from_u32(1));
            }
            STREAM_PORT_FORWARD => {
                tokio::spawn(async move {
                    if let Err(err) = forward::handle_port_forward_stream(send, recv).await {
                        warn!(error = ?err, "port-forward stream failed");
                    }
                });
            }
            STREAM_CONSOLE if !authenticated => {
                warn!("rejecting unauthenticated console stream");
                let _ = send.reset(quinn::VarInt::from_u32(1));
            }
            STREAM_CONSOLE => {
                let (root_dir, inner_pid) = {
                    let mut guard = shared.lock().await;
                    let inner_pid = match guard.setup.ensure_live_inner_init_pid() {
                        Ok(pid) => pid,
                        Err(err) => {
                            warn!(error = ?err, "console stream could not ensure live inner pid");
                            let _ = send.reset(quinn::VarInt::from_u32(1));
                            continue;
                        }
                    };
                    (guard.setup.root_mount_dir().to_path_buf(), inner_pid)
                };
                tokio::spawn(async move {
                    if let Err(err) =
                        forward::handle_console_stream(send, recv, &root_dir, inner_pid).await
                    {
                        warn!(error = ?err, "console stream failed");
                    }
                });
            }
            other => {
                warn!(stream_type = other, "unknown stream type");
                break;
            }
        }
    }

    info!(remote = %conn.remote_address(), "client disconnected");
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum ControlPhase {
    AwaitAttestation,
    AwaitSetupRequest { state: VmState },
}

async fn handle_control_stream(
    conn: &quinn::Connection,
    args: &Args,
    shared: &Arc<Mutex<SharedState>>,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
) -> Result<bool> {
    let mut phase = ControlPhase::AwaitAttestation;

    loop {
        let message = match ControlMessage::read_from(recv).await {
            Ok(message) => message,
            Err(err) => {
                if let Err(send_err) =
                    send_error(send, format!("control stream read error: {err:#}")).await
                {
                    warn!(error = ?send_err, "failed sending control error");
                }
                return Ok(false);
            }
        };

        phase = match (phase, message) {
            (ControlPhase::AwaitAttestation, ControlMessage::RequestAttestation) => {
                let payload = build_attestation(conn, args, shared).await?;
                ControlMessage::Attestation(payload).write_to(send).await?;
                let state = shared.lock().await.vm_state;
                ControlPhase::AwaitSetupRequest { state }
            }
            (ControlPhase::AwaitAttestation, other) => {
                send_error(send, format!("expected attestation request, got {other:?}")).await?;
                return Ok(false);
            }
            (ControlPhase::AwaitSetupRequest { state }, ControlMessage::SetupRequest(request)) => {
                match apply_setup_request(shared, state, request).await {
                    Ok(()) => {
                        ControlMessage::SetupComplete.write_to(send).await?;
                        return Ok(true);
                    }
                    Err(err) => {
                        send_error(send, format!("setup failed: {err:#}")).await?;
                        return Ok(false);
                    }
                }
            }
            (ControlPhase::AwaitSetupRequest { .. }, other) => {
                send_error(send, format!("expected setup request, got {other:?}")).await?;
                return Ok(false);
            }
        };
    }
}

async fn build_attestation(
    conn: &quinn::Connection,
    args: &Args,
    shared: &Arc<Mutex<SharedState>>,
) -> Result<AttestationPayload> {
    let mut ekm = [0u8; 32];
    conn.export_keying_material(&mut ekm, CHANNEL_BINDING_LABEL.as_bytes(), &[])
        .map_err(|_| anyhow!("export tls keying material failed"))?;

    let aud = hex::encode(ekm);
    let jwt = if args.test_mode {
        format!("test-mode-jwt:{aud}")
    } else {
        attest::fetch_oidc_token(&aud).await?
    };

    let mut guard = shared.lock().await;
    guard.vm_state = guard.setup.detect_state()?;
    if guard.vm_state == VmState::Ready {
        guard
            .setup
            .ensure_live_inner_init_pid()
            .context("ensure live runtime before attestation")?;
        guard.vm_state = guard.setup.detect_state()?;
    }
    Ok(AttestationPayload {
        protocol_version: PROTOCOL_VERSION,
        state: guard.vm_state,
        runtime_status: guard.setup.runtime_status()?,
        jwt,
    })
}

async fn apply_setup_request(
    shared: &Arc<Mutex<SharedState>>,
    state: VmState,
    request: SetupRequest,
) -> Result<()> {
    let expected = {
        let guard = shared.lock().await;
        guard.access_token.clone()
    };
    verify_access_token(expected.as_deref(), &request.access_token)?;

    let rootfs_tarball = resolve_rootfs_source(request.rootfs).await?;
    validate_rootfs_request(state, rootfs_tarball.as_ref())?;

    let mut guard = shared.lock().await;
    guard.setup.setup_and_prepare(rootfs_tarball).await?;
    guard.vm_state = guard.setup.detect_state()?;
    let runtime_status = guard.setup.runtime_status()?;
    let state = guard.vm_state;
    info!(
        state = ?state,
        runtime_status = ?runtime_status,
        "setup complete"
    );
    Ok(())
}

fn verify_access_token(expected: Option<&str>, provided: &str) -> Result<()> {
    match expected {
        Some(expected) if token_matches_constant_time(expected, provided) => Ok(()),
        Some(_) => Err(anyhow!("access token verification failed")),
        None => Err(anyhow!("no ACCESS_TOKEN configured on this machine")),
    }
}

fn validate_rootfs_request(state: VmState, rootfs_tarball: Option<&Vec<u8>>) -> Result<()> {
    if state == VmState::Cold && rootfs_tarball.is_none() {
        return Err(anyhow!("cold boot requires a rootfs payload"));
    }
    Ok(())
}

async fn resolve_rootfs_source(source: RootfsSource) -> Result<Option<Vec<u8>>> {
    match source {
        RootfsSource::None => Ok(None),
        RootfsSource::Inline(data) => Ok(Some(data)),
        RootfsSource::Url(url) => Ok(Some(download_rootfs_tarball(&url).await?)),
    }
}

async fn download_rootfs_tarball(url_str: &str) -> Result<Vec<u8>> {
    let url =
        reqwest::Url::parse(url_str).with_context(|| format!("parse rootfs URL {url_str}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(anyhow!(
            "rootfs URL scheme must be http or https, got {}",
            url.scheme()
        ));
    }

    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .build()
        .context("build reqwest client for rootfs download")?;
    let response = client
        .get(url.clone())
        .send()
        .await
        .with_context(|| format!("download rootfs from {url}"))?
        .error_for_status()
        .with_context(|| format!("rootfs download returned non-success status from {url}"))?;
    let bytes = response
        .bytes()
        .await
        .with_context(|| format!("read rootfs download response body from {url}"))?;
    Ok(bytes.to_vec())
}

async fn send_error(send: &mut quinn::SendStream, msg: String) -> Result<()> {
    ControlMessage::Error(msg).write_to(send).await
}

fn token_matches_constant_time(expected: &str, provided: &str) -> bool {
    let expected_bytes = expected.as_bytes();
    let provided_bytes = provided.as_bytes();

    let mut diff = expected_bytes.len() ^ provided_bytes.len();
    for (idx, expected_byte) in expected_bytes.iter().enumerate() {
        let provided_byte = provided_bytes.get(idx).copied().unwrap_or(0);
        diff |= usize::from(*expected_byte ^ provided_byte);
    }

    diff == 0
}

#[cfg(test)]
mod unit_tests {
    use super::token_matches_constant_time;

    #[test]
    fn token_matches_constant_time_behaves_correctly() {
        assert!(token_matches_constant_time("secret", "secret"));
        assert!(!token_matches_constant_time("secret", "secreT"));
        assert!(!token_matches_constant_time("secret", "short"));
        assert!(!token_matches_constant_time("secret", "secret-longer"));
    }
}
