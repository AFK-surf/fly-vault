use super::*;
use anyhow::{anyhow, Context, Result};
use protocol::{
    AttestationPayload, ControlFrame, VmState, CONTROL_ATTESTATION, CONTROL_ERROR,
    CONTROL_PROVISION_ROOTFS, CONTROL_PROVISION_ROOTFS_URL, CONTROL_PROVISION_TOKEN,
    CONTROL_RELEASE_KEY, CONTROL_REQUEST_ATTESTATION, CONTROL_SETUP_COMPLETE, STREAM_CONTROL,
};
use quinn::{ClientConfig, Connection, Endpoint};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};
use std::net::{Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cold_boot_to_ready_and_reconnect() -> Result<()> {
    let temp = TempDir::new().context("create temp dir")?;
    let port = choose_udp_port()?;
    let args = args_for_test(&temp, port, false)?;
    let shared = shared_state_for_args(&args, Some("test-provision-token".to_string())).await?;
    let server = tokio::spawn(quic::serve(args.clone(), shared));

    let endpoint = test_endpoint()?;
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    let conn = connect_with_retry(&endpoint, addr).await?;
    let (mut send, mut recv) = open_control_stream(&conn).await?;

    let att = request_attestation(&mut send, &mut recv).await?;
    assert_eq!(att.state, VmState::Cold);

    ControlFrame::new(CONTROL_PROVISION_TOKEN, b"test-provision-token".to_vec())
        .write_to(&mut send)
        .await
        .context("send provision token")?;
    ControlFrame::new(CONTROL_RELEASE_KEY, vec![7u8; 64])
        .write_to(&mut send)
        .await
        .context("send key")?;
    ControlFrame::new(CONTROL_PROVISION_ROOTFS, b"fake-rootfs".to_vec())
        .write_to(&mut send)
        .await
        .context("send rootfs")?;
    wait_setup_complete(&mut recv).await?;

    // Control stream returned after setup. Open a new one to check state.
    let (mut send2, mut recv2) = open_control_stream(&conn).await?;
    let att2 = request_attestation(&mut send2, &mut recv2).await?;
    assert_eq!(att2.state, VmState::Ready);

    // Reconnect on a fresh connection requires key verification.
    let conn2 = connect_with_retry(&endpoint, addr).await?;
    let (mut send3, mut recv3) = open_control_stream(&conn2).await?;
    let att3 = request_attestation(&mut send3, &mut recv3).await?;
    assert_eq!(att3.state, VmState::Ready);

    ControlFrame::new(CONTROL_RELEASE_KEY, vec![7u8; 64])
        .write_to(&mut send3)
        .await
        .context("send key on reconnect")?;
    wait_setup_complete(&mut recv3).await?;

    server.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cold_boot_with_rootfs_url() -> Result<()> {
    let temp = TempDir::new().context("create temp dir")?;
    let port = choose_udp_port()?;
    let args = args_for_test(&temp, port, false)?;
    let shared = shared_state_for_args(&args, Some("test-provision-token".to_string())).await?;
    let server = tokio::spawn(quic::serve(args.clone(), shared));

    let (rootfs_url, rootfs_server) = spawn_rootfs_http_server(b"fake-rootfs".to_vec()).await?;

    let endpoint = test_endpoint()?;
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    let conn = connect_with_retry(&endpoint, addr).await?;
    let (mut send, mut recv) = open_control_stream(&conn).await?;

    let att = request_attestation(&mut send, &mut recv).await?;
    assert_eq!(att.state, VmState::Cold);

    ControlFrame::new(CONTROL_PROVISION_TOKEN, b"test-provision-token".to_vec())
        .write_to(&mut send)
        .await
        .context("send provision token")?;
    ControlFrame::new(CONTROL_RELEASE_KEY, vec![7u8; 64])
        .write_to(&mut send)
        .await
        .context("send key")?;
    ControlFrame::new(CONTROL_PROVISION_ROOTFS_URL, rootfs_url.into_bytes())
        .write_to(&mut send)
        .await
        .context("send rootfs url")?;
    wait_setup_complete(&mut recv).await?;

    // Control stream returned after setup. Open a new one to check state.
    let (mut send2, mut recv2) = open_control_stream(&conn).await?;
    let att2 = request_attestation(&mut send2, &mut recv2).await?;
    assert_eq!(att2.state, VmState::Ready);

    rootfs_server.abort();
    server.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn locked_boot_to_ready() -> Result<()> {
    let temp = TempDir::new().context("create temp dir")?;
    let port = choose_udp_port()?;
    let args = args_for_test(&temp, port, true)?;
    let shared = shared_state_for_args(&args, None).await?;
    let server = tokio::spawn(quic::serve(args.clone(), shared));

    let endpoint = test_endpoint()?;
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    let conn = connect_with_retry(&endpoint, addr).await?;
    let (mut send, mut recv) = open_control_stream(&conn).await?;

    let att = request_attestation(&mut send, &mut recv).await?;
    assert_eq!(att.state, VmState::Locked);

    ControlFrame::new(CONTROL_RELEASE_KEY, vec![9u8; 64])
        .write_to(&mut send)
        .await
        .context("send key")?;
    wait_setup_complete(&mut recv).await?;

    // Control stream returned after setup. Open a new one to check state.
    let (mut send2, mut recv2) = open_control_stream(&conn).await?;
    let att2 = request_attestation(&mut send2, &mut recv2).await?;
    assert_eq!(att2.state, VmState::Ready);

    server.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cold_boot_rejected_without_provision_token() -> Result<()> {
    let temp = TempDir::new().context("create temp dir")?;
    let port = choose_udp_port()?;
    let args = args_for_test(&temp, port, false)?;
    let shared = shared_state_for_args(&args, Some("correct-token".to_string())).await?;
    let server = tokio::spawn(quic::serve(args.clone(), shared));

    let endpoint = test_endpoint()?;
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    let conn = connect_with_retry(&endpoint, addr).await?;
    let (mut send, mut recv) = open_control_stream(&conn).await?;

    let att = request_attestation(&mut send, &mut recv).await?;
    assert_eq!(att.state, VmState::Cold);

    // Send key and rootfs without provision token — should be rejected.
    ControlFrame::new(CONTROL_RELEASE_KEY, vec![7u8; 64])
        .write_to(&mut send)
        .await
        .context("send key")?;
    ControlFrame::new(CONTROL_PROVISION_ROOTFS, b"fake-rootfs".to_vec())
        .write_to(&mut send)
        .await
        .context("send rootfs")?;

    let frame = ControlFrame::read_from(&mut recv)
        .await
        .context("read error frame")?;
    assert_eq!(frame.ty, CONTROL_ERROR);
    let msg = String::from_utf8(frame.payload).unwrap();
    assert!(
        msg.contains("provision token"),
        "expected provision token error, got: {msg}"
    );

    server.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cold_boot_rejected_with_wrong_provision_token() -> Result<()> {
    let temp = TempDir::new().context("create temp dir")?;
    let port = choose_udp_port()?;
    let args = args_for_test(&temp, port, false)?;
    let shared = shared_state_for_args(&args, Some("correct-token".to_string())).await?;
    let server = tokio::spawn(quic::serve(args.clone(), shared));

    let endpoint = test_endpoint()?;
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    let conn = connect_with_retry(&endpoint, addr).await?;
    let (mut send, mut recv) = open_control_stream(&conn).await?;

    let att = request_attestation(&mut send, &mut recv).await?;
    assert_eq!(att.state, VmState::Cold);

    // Send wrong provision token.
    ControlFrame::new(CONTROL_PROVISION_TOKEN, b"wrong-token".to_vec())
        .write_to(&mut send)
        .await
        .context("send wrong provision token")?;

    let frame = ControlFrame::read_from(&mut recv)
        .await
        .context("read error frame")?;
    assert_eq!(frame.ty, CONTROL_ERROR);
    let msg = String::from_utf8(frame.payload).unwrap();
    assert!(
        msg.contains("mismatch"),
        "expected mismatch error, got: {msg}"
    );

    server.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ready_rejects_wrong_key() -> Result<()> {
    let temp = TempDir::new().context("create temp dir")?;
    let port = choose_udp_port()?;
    let args = args_for_test(&temp, port, false)?;
    let shared = shared_state_for_args(&args, Some("test-provision-token".to_string())).await?;
    let server = tokio::spawn(quic::serve(args.clone(), shared));

    let endpoint = test_endpoint()?;
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, port));

    // First connection: provision with the correct key.
    let conn = connect_with_retry(&endpoint, addr).await?;
    let (mut send, mut recv) = open_control_stream(&conn).await?;
    let att = request_attestation(&mut send, &mut recv).await?;
    assert_eq!(att.state, VmState::Cold);

    ControlFrame::new(CONTROL_PROVISION_TOKEN, b"test-provision-token".to_vec())
        .write_to(&mut send)
        .await?;
    ControlFrame::new(CONTROL_RELEASE_KEY, vec![7u8; 64])
        .write_to(&mut send)
        .await?;
    ControlFrame::new(CONTROL_PROVISION_ROOTFS, b"fake-rootfs".to_vec())
        .write_to(&mut send)
        .await?;
    wait_setup_complete(&mut recv).await?;

    // Second connection: try reconnecting with a WRONG key.
    let conn2 = connect_with_retry(&endpoint, addr).await?;
    let (mut send2, mut recv2) = open_control_stream(&conn2).await?;
    let att2 = request_attestation(&mut send2, &mut recv2).await?;
    assert_eq!(att2.state, VmState::Ready);

    ControlFrame::new(CONTROL_RELEASE_KEY, vec![99u8; 64])
        .write_to(&mut send2)
        .await?;
    let frame = ControlFrame::read_from(&mut recv2)
        .await
        .context("read error frame")?;
    assert_eq!(frame.ty, CONTROL_ERROR);
    let msg = String::from_utf8(frame.payload).unwrap();
    assert!(
        msg.contains("key verification failed"),
        "expected key verification error, got: {msg}"
    );

    server.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unauthenticated_stream_rejected() -> Result<()> {
    let temp = TempDir::new().context("create temp dir")?;
    let port = choose_udp_port()?;
    let args = args_for_test(&temp, port, false)?;
    let shared = shared_state_for_args(&args, Some("tok".to_string())).await?;
    let server = tokio::spawn(quic::serve(args.clone(), shared));

    let endpoint = test_endpoint()?;
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    let conn = connect_with_retry(&endpoint, addr).await?;

    // Open a console stream without authenticating first.
    let (mut send, mut recv) = conn.open_bi().await.context("open bi")?;
    send.write_u8(protocol::STREAM_CONSOLE)
        .await
        .context("write console tag")?;

    // The server should reset the stream. Reading should fail.
    let mut buf = [0u8; 64];
    match recv.read(&mut buf).await {
        Ok(None) | Err(_) => {} // Expected: stream closed or reset.
        Ok(Some(_)) => panic!("expected stream to be rejected, but got data"),
    }

    server.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn locked_reprovision_with_token() -> Result<()> {
    let temp = TempDir::new().context("create temp dir")?;
    let port = choose_udp_port()?;
    let args = args_for_test(&temp, port, true)?;
    let shared = shared_state_for_args(&args, Some("test-provision-token".to_string())).await?;
    let server = tokio::spawn(quic::serve(args.clone(), shared));

    let endpoint = test_endpoint()?;
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    let conn = connect_with_retry(&endpoint, addr).await?;
    let (mut send, mut recv) = open_control_stream(&conn).await?;

    let att = request_attestation(&mut send, &mut recv).await?;
    assert_eq!(att.state, VmState::Locked);

    // Re-provision: send token, rootfs, then key (key last to trigger setup).
    ControlFrame::new(CONTROL_PROVISION_TOKEN, b"test-provision-token".to_vec())
        .write_to(&mut send)
        .await
        .context("send provision token")?;
    ControlFrame::new(CONTROL_PROVISION_ROOTFS, b"fake-rootfs".to_vec())
        .write_to(&mut send)
        .await
        .context("send rootfs")?;
    ControlFrame::new(CONTROL_RELEASE_KEY, vec![9u8; 64])
        .write_to(&mut send)
        .await
        .context("send key")?;
    wait_setup_complete(&mut recv).await?;

    // Verify the server transitioned to Ready.
    let (mut send2, mut recv2) = open_control_stream(&conn).await?;
    let att2 = request_attestation(&mut send2, &mut recv2).await?;
    assert_eq!(att2.state, VmState::Ready);

    server.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn locked_reprovision_rejected_without_token() -> Result<()> {
    let temp = TempDir::new().context("create temp dir")?;
    let port = choose_udp_port()?;
    let args = args_for_test(&temp, port, true)?;
    let shared = shared_state_for_args(&args, Some("test-provision-token".to_string())).await?;
    let server = tokio::spawn(quic::serve(args.clone(), shared));

    let endpoint = test_endpoint()?;
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    let conn = connect_with_retry(&endpoint, addr).await?;
    let (mut send, mut recv) = open_control_stream(&conn).await?;

    let att = request_attestation(&mut send, &mut recv).await?;
    assert_eq!(att.state, VmState::Locked);

    // Send rootfs and key without provision token — should be rejected.
    ControlFrame::new(CONTROL_PROVISION_ROOTFS, b"fake-rootfs".to_vec())
        .write_to(&mut send)
        .await
        .context("send rootfs")?;
    ControlFrame::new(CONTROL_RELEASE_KEY, vec![9u8; 64])
        .write_to(&mut send)
        .await
        .context("send key")?;

    let frame = ControlFrame::read_from(&mut recv)
        .await
        .context("read error frame")?;
    assert_eq!(frame.ty, CONTROL_ERROR);
    let msg = String::from_utf8(frame.payload).unwrap();
    assert!(
        msg.contains("provision token"),
        "expected provision token error, got: {msg}"
    );

    server.abort();
    Ok(())
}

fn args_for_test(temp: &TempDir, port: u16, locked: bool) -> Result<Args> {
    let data_dir = temp.path().join("data");
    let fuse_dir = temp.path().join("fuse");
    let root_dir = temp.path().join("root");
    std::fs::create_dir_all(&data_dir).with_context(|| format!("create {}", data_dir.display()))?;
    std::fs::create_dir_all(&fuse_dir).with_context(|| format!("create {}", fuse_dir.display()))?;
    std::fs::create_dir_all(&root_dir).with_context(|| format!("create {}", root_dir.display()))?;

    if locked {
        let encrypted = data_dir.join("encrypted.img");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&encrypted)
            .with_context(|| format!("create {}", encrypted.display()))?;
        file.set_len(4096)
            .with_context(|| format!("set_len {}", encrypted.display()))?;
        // Write SHA-256 of the key that locked_boot_to_ready will use ([9u8; 64]).
        let key_hash: [u8; 32] = Sha256::digest([9u8; 64]).into();
        std::fs::write(data_dir.join(".provisioned"), key_hash)
            .context("write provisioned marker for test")?;
    }

    Ok(Args {
        listen: SocketAddr::from((Ipv6Addr::LOCALHOST, port)).to_string(),
        data_dir,
        fuse_mount_dir: fuse_dir,
        root_mount_dir: root_dir,
        init_binary: "/sbin/init".into(),
        image_size_bytes: 20 * 1024 * 1024,
        channel_binding_label: "fly-vault-channel-binding".to_string(),
        test_mode: true,
    })
}

async fn shared_state_for_args(
    args: &Args,
    provision_token: Option<String>,
) -> Result<Arc<Mutex<SharedState>>> {
    let setup = setup::SetupManager::new(
        args.data_dir.clone(),
        args.fuse_mount_dir.clone(),
        args.root_mount_dir.clone(),
        args.init_binary.clone(),
        args.image_size_bytes,
        args.test_mode,
    )?;
    let vm_state = setup.detect_state()?;
    Ok(Arc::new(Mutex::new(SharedState {
        vm_state,
        setup,
        provision_token,
        key_hash: None,
    })))
}

async fn open_control_stream(conn: &Connection) -> Result<(quinn::SendStream, quinn::RecvStream)> {
    let (mut send, recv) = conn.open_bi().await.context("open control stream")?;
    send.write_u8(STREAM_CONTROL)
        .await
        .context("write control stream tag")?;
    Ok((send, recv))
}

async fn request_attestation(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
) -> Result<AttestationPayload> {
    ControlFrame::new(CONTROL_REQUEST_ATTESTATION, vec![])
        .write_to(send)
        .await
        .context("send RequestAttestation")?;

    let frame = ControlFrame::read_from(recv)
        .await
        .context("read attestation frame")?;
    if frame.ty != CONTROL_ATTESTATION {
        return Err(anyhow!(
            "expected CONTROL_ATTESTATION, got type {}",
            frame.ty
        ));
    }
    AttestationPayload::from_bytes(&frame.payload)
}

async fn wait_setup_complete(recv: &mut quinn::RecvStream) -> Result<()> {
    loop {
        let frame = ControlFrame::read_from(recv)
            .await
            .context("read setup frame")?;
        match frame.ty {
            CONTROL_SETUP_COMPLETE => return Ok(()),
            CONTROL_ERROR => {
                let msg = String::from_utf8_lossy(&frame.payload);
                return Err(anyhow!("init setup failed: {msg}"));
            }
            _ => continue,
        }
    }
}

fn test_endpoint() -> Result<Endpoint> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut endpoint = Endpoint::client(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)))
        .context("create quinn client endpoint")?;
    endpoint.set_default_client_config(insecure_client_config()?);
    Ok(endpoint)
}

async fn connect_with_retry(endpoint: &Endpoint, addr: SocketAddr) -> Result<Connection> {
    for _ in 0..80 {
        let connecting = match endpoint.connect(addr, "localhost") {
            Ok(c) => c,
            Err(_) => {
                sleep(Duration::from_millis(50)).await;
                continue;
            }
        };

        match connecting.await {
            Ok(conn) => return Ok(conn),
            Err(_) => sleep(Duration::from_millis(50)).await,
        }
    }
    Err(anyhow!("timed out connecting to init on {addr}"))
}

fn insecure_client_config() -> Result<ClientConfig> {
    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"fly-vault".to_vec()];

    let cfg = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|e| anyhow!("build quinn rustls client config: {e}"))?;
    Ok(ClientConfig::new(Arc::new(cfg)))
}

fn choose_udp_port() -> Result<u16> {
    let sock = UdpSocket::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)))
        .context("bind local UDP socket for port selection")?;
    Ok(sock
        .local_addr()
        .context("read local UDP socket address")?
        .port())
}

async fn spawn_rootfs_http_server(body: Vec<u8>) -> Result<(String, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)))
        .await
        .context("bind rootfs HTTP listener")?;
    let addr = listener
        .local_addr()
        .context("read rootfs HTTP listener addr")?;
    let url = format!("http://{addr}/rootfs.tar.gz");

    let handle = tokio::spawn(async move {
        let Ok((mut stream, _peer)) = listener.accept().await else {
            return;
        };

        let mut req_buf = [0u8; 1024];
        let _ = stream.read(&mut req_buf).await;

        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/gzip\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(header.as_bytes()).await;
        let _ = stream.write_all(&body).await;
        let _ = stream.shutdown().await;
    });

    Ok((url, handle))
}

#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
        ]
    }
}
