use crate::attest;
use crate::forward;
use crate::{Args, SharedState};
use anyhow::{anyhow, Context, Result};
use crypto::{XtsKey, XTS_KEY_SIZE};
use protocol::{
    AttestationPayload, ControlFrame, VmState, CONTROL_ATTESTATION, CONTROL_ERROR,
    CONTROL_PROVISION_ROOTFS, CONTROL_PROVISION_ROOTFS_URL, CONTROL_PROVISION_TOKEN,
    CONTROL_RELEASE_KEY, CONTROL_REQUEST_ATTESTATION, CONTROL_SETUP_COMPLETE, STREAM_CONSOLE,
    STREAM_CONTROL, STREAM_PORT_FORWARD,
};
use quinn::{crypto::rustls::QuicServerConfig, Endpoint, ServerConfig};
use sha2::{Digest, Sha256};
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
        Duration::from_secs(120)
            .try_into()
            .context("idle timeout")?,
    ));
    transport.keep_alive_interval(Some(Duration::from_secs(10)));

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

/// Handles the control stream for a single connection.
/// Returns `Ok(true)` if the client successfully authenticated (key verified).
async fn handle_control_stream(
    conn: &quinn::Connection,
    args: &Args,
    shared: &Arc<Mutex<SharedState>>,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
) -> Result<bool> {
    let mut pending_key: Option<XtsKey> = None;
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
            CONTROL_PROVISION_TOKEN => {
                let client_token =
                    String::from_utf8(frame.payload).context("provision token not utf-8")?;
                let guard = shared.lock().await;
                match &guard.provision_token {
                    Some(expected) if expected == &client_token => {
                        drop(guard);
                        token_verified = true;
                        info!("provision token accepted");
                    }
                    Some(_) => {
                        drop(guard);
                        send_error(send, "provision token mismatch".to_string()).await?;
                    }
                    None => {
                        drop(guard);
                        send_error(
                            send,
                            "no PROVISION_TOKEN configured on this machine".to_string(),
                        )
                        .await?;
                    }
                }
            }
            CONTROL_RELEASE_KEY => {
                if frame.payload.len() != XTS_KEY_SIZE {
                    send_error(send, "invalid key length".to_string()).await?;
                    continue;
                }
                pending_key = Some(XtsKey::from_slice(&frame.payload)?);
            }
            CONTROL_PROVISION_ROOTFS => {
                rootfs_source = Some(RootfsSource::Inline(frame.payload));
            }
            CONTROL_PROVISION_ROOTFS_URL => {
                let rootfs_url =
                    String::from_utf8(frame.payload).context("rootfs url payload not utf-8")?;
                rootfs_source = Some(RootfsSource::Url(rootfs_url));
            }
            _ => {
                send_error(send, format!("unknown control type: {}", frame.ty)).await?;
                continue;
            }
        }

        if let Some(ref key) = pending_key {
            let state = {
                let guard = shared.lock().await;
                guard.vm_state
            };

            if state == VmState::Ready {
                let incoming_hash: [u8; 32] = Sha256::digest(key.as_bytes()).into();
                let guard = shared.lock().await;
                let verified = guard
                    .key_hash
                    .as_ref()
                    .map_or(false, |stored| stored == &incoming_hash);
                drop(guard);

                if verified {
                    info!("key verified for ready-state reconnect");
                    ControlFrame::new(CONTROL_SETUP_COMPLETE, vec![])
                        .write_to(send)
                        .await?;
                    return Ok(true);
                } else {
                    warn!("key verification failed for ready-state reconnect");
                    send_error(send, "key verification failed".to_string()).await?;
                    return Ok(false);
                }
            }

            if state == VmState::Cold && rootfs_source.is_none() {
                // Cold boot needs both key and rootfs before setup.
                continue;
            }

            if state == VmState::Cold && !token_verified {
                // Cold boot requires a valid provision token before setup.
                if rootfs_source.is_some() {
                    send_error(send, "provision token required for cold boot".to_string()).await?;
                    rootfs_source = None;
                    pending_key = None;
                }
                continue;
            }

            if state == VmState::Locked && rootfs_source.is_some() && !token_verified {
                send_error(
                    send,
                    "provision token required for re-provisioning".to_string(),
                )
                .await?;
                rootfs_source = None;
                pending_key = None;
                continue;
            }

            let key = pending_key
                .take()
                .ok_or_else(|| anyhow!("pending key unexpectedly missing"))?;

            let key_hash: [u8; 32] = Sha256::digest(key.as_bytes()).into();
            let rootfs_tarball = match resolve_rootfs_source(rootfs_source.take()).await {
                Ok(data) => data,
                Err(err) => {
                    send_error(send, format!("resolve rootfs source failed: {err:#}")).await?;
                    return Ok(false);
                }
            };

            let mut guard = shared.lock().await;
            match guard.setup.unlock_and_prepare(key, rootfs_tarball).await {
                Ok(()) => {
                    guard.vm_state = VmState::Ready;
                    guard.key_hash = Some(key_hash);
                    drop(guard);
                    info!("setup complete, key hash stored");
                    ControlFrame::new(CONTROL_SETUP_COMPLETE, vec![])
                        .write_to(send)
                        .await?;
                    return Ok(true);
                }
                Err(err) => {
                    guard.vm_state = VmState::Locked;
                    drop(guard);
                    send_error(send, format!("setup failed: {err:#}")).await?;
                    return Ok(false);
                }
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
