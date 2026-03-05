use super::*;
use anyhow::{anyhow, Context, Result};
use protocol::{
    AttestationPayload, ControlFrame, VmState, CONTROL_ACCESS_TOKEN, CONTROL_ATTESTATION,
    CONTROL_ERROR, CONTROL_PROVISION_ROOTFS, CONTROL_PROVISION_ROOTFS_URL,
    CONTROL_REQUEST_ATTESTATION, CONTROL_SETUP_COMPLETE, STREAM_CONTROL,
};
use quinn::{ClientConfig, Connection, Endpoint};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use std::net::{Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;

#[test]
fn startup_in_ready_state_starts_runtime() -> Result<()> {
    let temp = TempDir::new().context("create temp dir")?;
    let data_dir = temp.path().join("data");
    let root_dir = temp.path().join("root");
    std::fs::create_dir_all(&data_dir).with_context(|| format!("create {}", data_dir.display()))?;
    std::fs::create_dir_all(&root_dir).with_context(|| format!("create {}", root_dir.display()))?;
    std::fs::write(data_dir.join(".provisioned"), b"1").context("write provision marker")?;

    let mut setup = setup::SetupManager::new(
        data_dir,
        root_dir,
        "/sbin/init".into(),
        true, // test_mode
    )?;
    assert_eq!(setup.detect_state()?, VmState::Ready);
    assert!(!setup.runtime_started());

    setup.start_ready_runtime()?;
    assert!(setup.runtime_started());
    Ok(())
}

#[tokio::test]
async fn cold_provisioning_resets_existing_rootfs() -> Result<()> {
    let temp = TempDir::new().context("create temp dir")?;
    let data_dir = temp.path().join("data");
    let root_dir = temp.path().join("root");
    std::fs::create_dir_all(&data_dir).with_context(|| format!("create {}", data_dir.display()))?;
    std::fs::create_dir_all(&root_dir).with_context(|| format!("create {}", root_dir.display()))?;
    let stale = root_dir.join("stale.txt");
    std::fs::write(&stale, "old").context("write stale file")?;

    let mut setup = setup::SetupManager::new(
        data_dir.clone(),
        root_dir.clone(),
        "/sbin/init".into(),
        true, // test_mode
    )?;

    setup
        .setup_and_prepare(Some(vec![1, 2, 3]))
        .await
        .context("cold provision")?;

    assert!(
        !stale.exists(),
        "rootfs dir should be reset before provisioning"
    );
    assert!(data_dir.join(".provisioned").exists());
    Ok(())
}

#[tokio::test]
async fn reprovisioning_kills_runtime_and_resets_rootfs() -> Result<()> {
    let temp = TempDir::new().context("create temp dir")?;
    let data_dir = temp.path().join("data");
    let root_dir = temp.path().join("root");
    std::fs::create_dir_all(&data_dir).with_context(|| format!("create {}", data_dir.display()))?;
    std::fs::create_dir_all(&root_dir).with_context(|| format!("create {}", root_dir.display()))?;

    let mut setup = setup::SetupManager::new(
        data_dir.clone(),
        root_dir.clone(),
        "/sbin/init".into(),
        true, // test_mode
    )?;
    setup
        .setup_and_prepare(Some(vec![1, 2, 3]))
        .await
        .context("initial provision")?;
    assert!(setup.runtime_started());

    let stale = root_dir.join("stale.txt");
    std::fs::write(&stale, "old").context("write stale file")?;

    setup
        .setup_and_prepare(Some(vec![4, 5, 6]))
        .await
        .context("reprovision")?;

    assert!(
        !stale.exists(),
        "rootfs dir should be reset before reprovisioning"
    );
    assert!(setup.runtime_started(), "runtime should be started again");
    assert!(data_dir.join(".provisioned").exists());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cold_boot_to_ready_and_reconnect() -> Result<()> {
    let temp = TempDir::new().context("create temp dir")?;
    let port = choose_udp_port()?;
    let args = args_for_test(&temp, port)?;
    let shared = shared_state_for_args(&args, Some("test-access-token".to_string())).await?;
    let server = tokio::spawn(quic::serve(args.clone(), shared));

    let endpoint = test_endpoint()?;
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    let conn = connect_with_retry(&endpoint, addr).await?;

    provision_cold(
        &conn,
        "test-access-token",
        ControlRootfs::Inline(b"fake-rootfs".to_vec()),
    )
    .await?;

    let (mut send2, mut recv2) = open_control_stream(&conn).await?;
    let att2 = request_attestation(&mut send2, &mut recv2).await?;
    assert_eq!(att2.state, VmState::Ready);

    ControlFrame::new(CONTROL_ACCESS_TOKEN, b"test-access-token".to_vec())
        .write_to(&mut send2)
        .await
        .context("send access token")?;
    wait_setup_complete(&mut recv2).await?;

    server.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cold_boot_with_rootfs_url() -> Result<()> {
    let temp = TempDir::new().context("create temp dir")?;
    let port = choose_udp_port()?;
    let args = args_for_test(&temp, port)?;
    let shared = shared_state_for_args(&args, Some("test-access-token".to_string())).await?;
    let server = tokio::spawn(quic::serve(args.clone(), shared));

    let (rootfs_url, rootfs_server) = spawn_rootfs_http_server(b"fake-rootfs".to_vec()).await?;

    let endpoint = test_endpoint()?;
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    let conn = connect_with_retry(&endpoint, addr).await?;

    provision_cold(&conn, "test-access-token", ControlRootfs::Url(rootfs_url)).await?;

    let (mut send2, mut recv2) = open_control_stream(&conn).await?;
    let att2 = request_attestation(&mut send2, &mut recv2).await?;
    assert_eq!(att2.state, VmState::Ready);

    rootfs_server.abort();
    server.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cold_boot_rejected_without_access_token() -> Result<()> {
    let temp = TempDir::new().context("create temp dir")?;
    let port = choose_udp_port()?;
    let args = args_for_test(&temp, port)?;
    let shared = shared_state_for_args(&args, Some("correct-token".to_string())).await?;
    let server = tokio::spawn(quic::serve(args.clone(), shared));

    let endpoint = test_endpoint()?;
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    let conn = connect_with_retry(&endpoint, addr).await?;
    let (mut send, mut recv) = open_control_stream(&conn).await?;

    let att = request_attestation(&mut send, &mut recv).await?;
    assert_eq!(att.state, VmState::Cold);

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
        msg.contains("access token"),
        "expected access token error, got: {msg}"
    );

    server.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cold_boot_rejected_with_wrong_access_token() -> Result<()> {
    let temp = TempDir::new().context("create temp dir")?;
    let port = choose_udp_port()?;
    let args = args_for_test(&temp, port)?;
    let shared = shared_state_for_args(&args, Some("correct-token".to_string())).await?;
    let server = tokio::spawn(quic::serve(args.clone(), shared));

    let endpoint = test_endpoint()?;
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    let conn = connect_with_retry(&endpoint, addr).await?;
    let (mut send, mut recv) = open_control_stream(&conn).await?;

    let att = request_attestation(&mut send, &mut recv).await?;
    assert_eq!(att.state, VmState::Cold);

    ControlFrame::new(CONTROL_ACCESS_TOKEN, b"wrong-token".to_vec())
        .write_to(&mut send)
        .await
        .context("send wrong access token")?;

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
async fn ready_rejects_wrong_access_token() -> Result<()> {
    let temp = TempDir::new().context("create temp dir")?;
    let port = choose_udp_port()?;
    let args = args_for_test(&temp, port)?;
    let shared = shared_state_for_args(&args, Some("test-access-token".to_string())).await?;
    let server = tokio::spawn(quic::serve(args.clone(), shared));

    let endpoint = test_endpoint()?;
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    let conn = connect_with_retry(&endpoint, addr).await?;

    provision_cold(
        &conn,
        "test-access-token",
        ControlRootfs::Inline(b"fake-rootfs".to_vec()),
    )
    .await?;

    let (mut send2, mut recv2) = open_control_stream(&conn).await?;
    let att2 = request_attestation(&mut send2, &mut recv2).await?;
    assert_eq!(att2.state, VmState::Ready);

    ControlFrame::new(CONTROL_ACCESS_TOKEN, b"wrong-token".to_vec())
        .write_to(&mut send2)
        .await
        .context("send wrong access token")?;
    let frame = ControlFrame::read_from(&mut recv2)
        .await
        .context("read error frame")?;
    assert_eq!(frame.ty, CONTROL_ERROR);
    let msg = String::from_utf8(frame.payload).unwrap();
    assert!(
        msg.contains("verification failed"),
        "expected access token verification error, got: {msg}"
    );

    server.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unauthenticated_stream_rejected() -> Result<()> {
    let temp = TempDir::new().context("create temp dir")?;
    let port = choose_udp_port()?;
    let args = args_for_test(&temp, port)?;
    let shared = shared_state_for_args(&args, Some("tok".to_string())).await?;
    let server = tokio::spawn(quic::serve(args.clone(), shared));

    let endpoint = test_endpoint()?;
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    let conn = connect_with_retry(&endpoint, addr).await?;

    let (mut send, mut recv) = conn.open_bi().await.context("open bi")?;
    send.write_u8(protocol::STREAM_CONSOLE)
        .await
        .context("write console tag")?;

    let mut buf = [0u8; 64];
    match recv.read(&mut buf).await {
        Ok(None) | Err(_) => {}
        Ok(Some(_)) => panic!("expected stream to be rejected, but got data"),
    }

    server.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ready_reprovision_with_access_token() -> Result<()> {
    let temp = TempDir::new().context("create temp dir")?;
    let port = choose_udp_port()?;
    let args = args_for_test(&temp, port)?;
    let shared = shared_state_for_args(&args, Some("test-access-token".to_string())).await?;
    let server = tokio::spawn(quic::serve(args.clone(), shared));

    let endpoint = test_endpoint()?;
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    let conn = connect_with_retry(&endpoint, addr).await?;

    provision_cold(
        &conn,
        "test-access-token",
        ControlRootfs::Inline(b"fake-rootfs-v1".to_vec()),
    )
    .await?;

    let (mut send2, mut recv2) = open_control_stream(&conn).await?;
    let att2 = request_attestation(&mut send2, &mut recv2).await?;
    assert_eq!(att2.state, VmState::Ready);

    ControlFrame::new(CONTROL_PROVISION_ROOTFS, b"fake-rootfs-v2".to_vec())
        .write_to(&mut send2)
        .await
        .context("send reprovision rootfs")?;
    ControlFrame::new(CONTROL_ACCESS_TOKEN, b"test-access-token".to_vec())
        .write_to(&mut send2)
        .await
        .context("send access token")?;
    wait_setup_complete(&mut recv2).await?;

    server.abort();
    Ok(())
}

enum ControlRootfs {
    Inline(Vec<u8>),
    Url(String),
}

async fn provision_cold(conn: &Connection, token: &str, rootfs: ControlRootfs) -> Result<()> {
    let (mut send, mut recv) = open_control_stream(conn).await?;

    let att = request_attestation(&mut send, &mut recv).await?;
    assert_eq!(att.state, VmState::Cold);

    ControlFrame::new(CONTROL_ACCESS_TOKEN, token.as_bytes().to_vec())
        .write_to(&mut send)
        .await
        .context("send access token")?;

    match rootfs {
        ControlRootfs::Inline(data) => {
            ControlFrame::new(CONTROL_PROVISION_ROOTFS, data)
                .write_to(&mut send)
                .await
                .context("send rootfs")?;
        }
        ControlRootfs::Url(url) => {
            ControlFrame::new(CONTROL_PROVISION_ROOTFS_URL, url.into_bytes())
                .write_to(&mut send)
                .await
                .context("send rootfs url")?;
        }
    }

    wait_setup_complete(&mut recv).await
}

fn args_for_test(temp: &TempDir, port: u16) -> Result<Args> {
    let data_dir = temp.path().join("data");
    let root_dir = temp.path().join("root");
    std::fs::create_dir_all(&data_dir).with_context(|| format!("create {}", data_dir.display()))?;
    std::fs::create_dir_all(&root_dir).with_context(|| format!("create {}", root_dir.display()))?;

    Ok(Args {
        listen: SocketAddr::from((Ipv6Addr::LOCALHOST, port)).to_string(),
        data_dir,
        root_mount_dir: root_dir,
        init_binary: "/sbin/init".into(),
        channel_binding_label: "fly-vault-channel-binding".to_string(),
        test_mode: true,
    })
}

async fn shared_state_for_args(
    args: &Args,
    access_token: Option<String>,
) -> Result<Arc<Mutex<SharedState>>> {
    let setup = setup::SetupManager::new(
        args.data_dir.clone(),
        args.root_mount_dir.clone(),
        args.init_binary.clone(),
        args.test_mode,
    )?;
    let vm_state = setup.detect_state()?;
    Ok(Arc::new(Mutex::new(SharedState {
        vm_state,
        setup,
        access_token,
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
