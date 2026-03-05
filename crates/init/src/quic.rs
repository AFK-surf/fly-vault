use crate::attest;
use crate::forward;
use crate::{Args, SharedState};
use anyhow::{anyhow, Context, Result};
use protocol::{
    AttestationPayload, ControlFrame, VmState, CONTROL_ACCESS_TOKEN, CONTROL_ATTESTATION,
    CONTROL_ERROR, CONTROL_PROVISION_ROOTFS, CONTROL_PROVISION_ROOTFS_URL,
    CONTROL_REQUEST_ATTESTATION, CONTROL_SETUP_COMPLETE, STREAM_CONSOLE, STREAM_CONTROL,
    STREAM_PORT_FORWARD,
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
                    let guard = shared.lock().await;
                    (
                        guard.setup.root_mount_dir().to_path_buf(),
                        guard.setup.inner_init_pid(),
                    )
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

async fn handle_control_stream(
    conn: &quinn::Connection,
    args: &Args,
    shared: &Arc<Mutex<SharedState>>,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
) -> Result<bool> {
    let mut rootfs_source: Option<RootfsSource> = None;
    let mut token_verified = false;

    loop {
        let frame = match ControlFrame::read_from(recv).await {
            Ok(frame) => frame,
            Err(err) => {
                if let Err(send_err) =
                    send_error(send, format!("control stream read error: {err:#}")).await
                {
                    warn!(error = ?send_err, "failed sending control error");
                }
                return Ok(false);
            }
        };

        match frame.ty {
            CONTROL_REQUEST_ATTESTATION => {
                let mut ekm = [0u8; 32];
                conn.export_keying_material(&mut ekm, args.channel_binding_label.as_bytes(), &[])
                    .map_err(|_| anyhow!("export tls keying material failed"))?;

                let aud = hex::encode(ekm);
                let jwt = if args.test_mode {
                    format!("test-mode-jwt:{aud}")
                } else {
                    attest::fetch_oidc_token(&aud).await?
                };

                let state = {
                    let guard = shared.lock().await;
                    guard.vm_state
                };

                let payload = AttestationPayload { state, jwt }.to_bytes();
                ControlFrame::new(CONTROL_ATTESTATION, payload)
                    .write_to(send)
                    .await?;
            }
            CONTROL_ACCESS_TOKEN => {
                let client_token =
                    String::from_utf8(frame.payload).context("access token not utf-8")?;

                let state = {
                    let guard = shared.lock().await;
                    guard.vm_state
                };

                match state {
                    VmState::Cold => {
                        let expected = {
                            let guard = shared.lock().await;
                            guard.access_token.clone()
                        };

                        match expected {
                            Some(expected)
                                if token_matches_constant_time(&expected, &client_token) =>
                            {
                                token_verified = true;
                                info!("access token accepted for cold boot");
                            }
                            Some(_) => {
                                send_error(send, "access token mismatch".to_string()).await?;
                                return Ok(false);
                            }
                            None => {
                                send_error(
                                    send,
                                    "no ACCESS_TOKEN configured on this machine".to_string(),
                                )
                                .await?;
                                return Ok(false);
                            }
                        }
                    }
                    VmState::Ready => {
                        let expected = {
                            let guard = shared.lock().await;
                            guard.access_token.clone()
                        };

                        match expected {
                            Some(expected)
                                if token_matches_constant_time(&expected, &client_token) =>
                            {
                                token_verified = true;
                                info!("access token verified for ready-state session");
                            }
                            Some(_) => {
                                send_error(send, "access token verification failed".to_string())
                                    .await?;
                                return Ok(false);
                            }
                            None => {
                                send_error(
                                    send,
                                    "no ACCESS_TOKEN configured on this machine".to_string(),
                                )
                                .await?;
                                return Ok(false);
                            }
                        }

                        if rootfs_source.is_none() {
                            ControlFrame::new(CONTROL_SETUP_COMPLETE, vec![])
                                .write_to(send)
                                .await?;
                            return Ok(true);
                        }
                    }
                }
            }
            CONTROL_PROVISION_ROOTFS => {
                let state = {
                    let guard = shared.lock().await;
                    guard.vm_state
                };
                if state == VmState::Cold && !token_verified {
                    send_error(
                        send,
                        "access token required before provisioning rootfs".to_string(),
                    )
                    .await?;
                    return Ok(false);
                }
                rootfs_source = Some(RootfsSource::Inline(frame.payload));
            }
            CONTROL_PROVISION_ROOTFS_URL => {
                let state = {
                    let guard = shared.lock().await;
                    guard.vm_state
                };
                if state == VmState::Cold && !token_verified {
                    send_error(
                        send,
                        "access token required before provisioning rootfs".to_string(),
                    )
                    .await?;
                    return Ok(false);
                }
                let rootfs_url =
                    String::from_utf8(frame.payload).context("rootfs url payload not utf-8")?;
                rootfs_source = Some(RootfsSource::Url(rootfs_url));
            }
            _ => {
                send_error(send, format!("unknown control type: {}", frame.ty)).await?;
                continue;
            }
        }

        if !token_verified || rootfs_source.is_none() {
            continue;
        }

        let rootfs_tarball = match resolve_rootfs_source(rootfs_source.take()).await {
            Ok(data) => data,
            Err(err) => {
                send_error(send, format!("resolve rootfs source failed: {err:#}")).await?;
                return Ok(false);
            }
        };

        let mut guard = shared.lock().await;
        match guard.setup.setup_and_prepare(rootfs_tarball).await {
            Ok(()) => {
                guard.vm_state = VmState::Ready;
                drop(guard);
                info!("setup complete");
                ControlFrame::new(CONTROL_SETUP_COMPLETE, vec![])
                    .write_to(send)
                    .await?;
                return Ok(true);
            }
            Err(err) => {
                drop(guard);
                send_error(send, format!("setup failed: {err:#}")).await?;
                return Ok(false);
            }
        }
    }
}

#[derive(Debug)]
enum RootfsSource {
    Inline(Vec<u8>),
    Url(String),
}

async fn resolve_rootfs_source(source: Option<RootfsSource>) -> Result<Option<Vec<u8>>> {
    match source {
        None => Ok(None),
        Some(RootfsSource::Inline(data)) => Ok(Some(data)),
        Some(RootfsSource::Url(url)) => Ok(Some(download_rootfs_tarball(&url).await?)),
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
    ControlFrame::new(CONTROL_ERROR, msg.into_bytes())
        .write_to(send)
        .await
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
