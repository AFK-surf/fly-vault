use super::*;
use anyhow::{anyhow, Context, Result};
use flate2::write::GzEncoder;
use flate2::Compression;
use protocol::{
    AttestationPayload, ConsoleFrame, ControlMessage, ExecSessionList, ExecSessionRequest,
    RootfsSource, RuntimeStatus, SetupRequest, VmState, CONSOLE_DATA, CONSOLE_EXEC, CONSOLE_SHELL,
    PROTOCOL_VERSION, STREAM_CONSOLE, STREAM_CONTROL, STREAM_EXEC_LIST,
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
    let stale = root_dir.join("etc/stale.txt");
    std::fs::create_dir_all(stale.parent().unwrap()).context("create stale parent")?;
    std::fs::write(&stale, "old").context("write stale file")?;

    let mut setup = setup::SetupManager::new(
        data_dir.clone(),
        root_dir.clone(),
        "/sbin/init".into(),
        true, // test_mode
    )?;

    setup
        .setup_and_prepare(Some(test_rootfs("v1")?))
        .await
        .context("cold provision")?;

    assert!(
        !stale.exists(),
        "rootfs dir should be reset before provisioning"
    );
    assert_eq!(
        std::fs::read_to_string(root_dir.join("etc/rootfs-version"))
            .context("read version after cold provision")?,
        "v1"
    );
    assert_eq!(
        std::fs::read_to_string(root_dir.join("root/.profile"))
            .context("read persisted /root content")?,
        "root profile v1"
    );
    assert_eq!(
        std::fs::read_to_string(root_dir.join("home/dev/welcome.txt"))
            .context("read persisted /home content")?,
        "home welcome v1"
    );
    assert_eq!(
        std::fs::read_to_string(data_dir.join("persist/root/.profile"))
            .context("read root backing dir")?,
        "root profile v1"
    );
    assert_eq!(
        std::fs::read_to_string(data_dir.join("persist/home/dev/welcome.txt"))
            .context("read home backing dir")?,
        "home welcome v1"
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
        .setup_and_prepare(Some(test_rootfs("v1")?))
        .await
        .context("initial provision")?;
    assert!(setup.runtime_started());

    let persisted_root = root_dir.join("root/persisted.txt");
    std::fs::write(&persisted_root, "keep root").context("write persisted root file")?;
    let persisted_home = root_dir.join("home/dev/project.txt");
    std::fs::create_dir_all(persisted_home.parent().unwrap())
        .context("create persisted home parent")?;
    std::fs::write(&persisted_home, "keep home").context("write persisted home file")?;
    let stale = root_dir.join("etc/transient.txt");
    std::fs::create_dir_all(stale.parent().unwrap()).context("create stale parent")?;
    std::fs::write(&stale, "old").context("write stale file")?;

    setup
        .setup_and_prepare(Some(test_rootfs("v2")?))
        .await
        .context("reprovision")?;

    assert_eq!(
        std::fs::read_to_string(&persisted_root)
            .context("read persisted root after reprovision")?,
        "keep root"
    );
    assert_eq!(
        std::fs::read_to_string(&persisted_home)
            .context("read persisted home after reprovision")?,
        "keep home"
    );
    assert!(
        !stale.exists(),
        "non-persistent rootfs content should be reset before reprovisioning"
    );
    assert_eq!(
        std::fs::read_to_string(root_dir.join("etc/rootfs-version"))
            .context("read version after reprovision")?,
        "v2"
    );
    assert!(setup.runtime_started(), "runtime should be started again");
    assert!(data_dir.join(".provisioned").exists());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cold_boot_to_ready_and_reconnect() -> Result<()> {
    let temp = TempDir::new().context("create temp dir")?;
    let Some(port) = choose_udp_port()? else {
        return Ok(());
    };
    let args = args_for_test(&temp, port)?;
    let shared = shared_state_for_args(&args, Some("test-access-token".to_string())).await?;
    let server = tokio::spawn(quic::serve(args.clone(), shared));

    let endpoint = test_endpoint()?;
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    let conn = connect_with_retry(&endpoint, addr).await?;

    provision_cold(
        &conn,
        "test-access-token",
        ControlRootfs::Inline(test_rootfs("cold-reconnect")?),
    )
    .await?;

    let (mut send2, mut recv2) = open_control_stream(&conn).await?;
    let att2 = request_attestation(&mut send2, &mut recv2).await?;
    assert_eq!(att2.state, VmState::Ready);
    assert_eq!(att2.runtime_status, RuntimeStatus::SystemInit);

    send_setup_request(&mut send2, "test-access-token", RootfsSource::None).await?;
    wait_setup_complete(&mut recv2).await?;

    server.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_connect_shell_survives_connection_reconnect() -> Result<()> {
    let temp = TempDir::new().context("create temp dir")?;
    let Some(port) = choose_udp_port()? else {
        return Ok(());
    };
    let args = args_for_test(&temp, port)?;
    let shared = shared_state_for_args(&args, Some("test-access-token".to_string())).await?;
    let server = tokio::spawn(quic::serve(args.clone(), shared));

    let endpoint = test_endpoint()?;
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, port));

    let conn1 = connect_with_retry(&endpoint, addr).await?;
    provision_cold(
        &conn1,
        "test-access-token",
        ControlRootfs::Inline(test_rootfs("shared-console")?),
    )
    .await?;

    let marker = "shared-shell-marker-12345";
    let (mut console_send1, mut console_recv1) = open_console_shell_stream(&conn1).await?;
    send_console_input(
        &mut console_send1,
        &format!("export FLY_VAULT_SHARED_MARKER={marker}\n"),
    )
    .await?;
    send_console_input(&mut console_send1, "printf '__READY1__\\n'\n").await?;
    read_console_until(&mut console_recv1, "__READY1__").await?;
    drop(console_send1);
    drop(console_recv1);
    drop(conn1);

    let conn2 = ready_connection(&endpoint, addr, "test-access-token").await?;
    let (mut console_send2, mut console_recv2) = open_console_shell_stream(&conn2).await?;
    send_console_input(
        &mut console_send2,
        "printf '%s\\n' \"$FLY_VAULT_SHARED_MARKER\"\nprintf '__READY2__\\n'\n",
    )
    .await?;
    let output = read_console_until(&mut console_recv2, "__READY2__").await?;
    assert!(
        output.contains(marker),
        "expected shared shell env var to persist across reconnect, got: {output}"
    );

    server.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exec_session_survives_connection_reconnect_and_lists() -> Result<()> {
    let temp = TempDir::new().context("create temp dir")?;
    let Some(port) = choose_udp_port()? else {
        return Ok(());
    };
    let args = args_for_test(&temp, port)?;
    let shared = shared_state_for_args(&args, Some("test-access-token".to_string())).await?;
    let server = tokio::spawn(quic::serve(args.clone(), shared));

    let endpoint = test_endpoint()?;
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, port));

    let conn1 = connect_with_retry(&endpoint, addr).await?;
    provision_cold(
        &conn1,
        "test-access-token",
        ControlRootfs::Inline(test_rootfs("exec-session")?),
    )
    .await?;

    let session_id = "exec-session-1";
    let (exec_send1, mut exec_recv1) = open_exec_session_stream(
        &conn1,
        ExecSessionRequest {
            session_id: session_id.to_string(),
            argv: Some(vec![
                "/bin/sh".to_string(),
                "-lc".to_string(),
                "echo started; read line; echo again:$line".to_string(),
            ]),
            context: Some("debugging a stuck deploy".to_string()),
        },
    )
    .await?;
    read_console_until(&mut exec_recv1, "started").await?;
    drop(exec_send1);
    drop(exec_recv1);
    drop(conn1);

    let conn2 = ready_connection(&endpoint, addr, "test-access-token").await?;
    let sessions = list_exec_sessions(&conn2).await?;
    let session = sessions
        .sessions
        .iter()
        .find(|session| session.session_id == session_id)
        .context("find exec session in list")?;
    assert_eq!(
        session.argv,
        vec![
            "/bin/sh".to_string(),
            "-lc".to_string(),
            "echo started; read line; echo again:$line".to_string(),
        ]
    );
    assert_eq!(session.context.as_deref(), Some("debugging a stuck deploy"));
    assert!(!session.attached);
    assert_eq!(session.exit_code, None);

    let (mut exec_send2, mut exec_recv2) = open_exec_session_stream(
        &conn2,
        ExecSessionRequest {
            session_id: session_id.to_string(),
            argv: None,
            context: None,
        },
    )
    .await?;
    send_console_input(&mut exec_send2, "hello\n").await?;
    let output = read_console_until(&mut exec_recv2, "again:hello").await?;
    assert!(output.contains("again:hello"));
    wait_for_console_exit(&mut exec_recv2).await?;

    for _ in 0..20 {
        let sessions = list_exec_sessions(&conn2).await?;
        if sessions
            .sessions
            .iter()
            .all(|session| session.session_id != session_id)
        {
            server.abort();
            return Ok(());
        }
        sleep(Duration::from_millis(20)).await;
    }
    return Err(anyhow!(
        "exec session {session_id} was not removed after exit"
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cold_boot_with_rootfs_url() -> Result<()> {
    let temp = TempDir::new().context("create temp dir")?;
    let Some(port) = choose_udp_port()? else {
        return Ok(());
    };
    let args = args_for_test(&temp, port)?;
    let shared = shared_state_for_args(&args, Some("test-access-token".to_string())).await?;
    let server = tokio::spawn(quic::serve(args.clone(), shared));

    let (rootfs_url, rootfs_server) = spawn_rootfs_http_server(test_rootfs("cold-url")?).await?;

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
    let Some(port) = choose_udp_port()? else {
        return Ok(());
    };
    let args = args_for_test(&temp, port)?;
    let shared = shared_state_for_args(&args, Some("correct-token".to_string())).await?;
    let server = tokio::spawn(quic::serve(args.clone(), shared));

    let endpoint = test_endpoint()?;
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    let conn = connect_with_retry(&endpoint, addr).await?;
    let (mut send, mut recv) = open_control_stream(&conn).await?;

    let att = request_attestation(&mut send, &mut recv).await?;
    assert_eq!(att.state, VmState::Cold);
    assert_eq!(att.runtime_status, RuntimeStatus::NotStarted);

    send_setup_request(
        &mut send,
        "",
        RootfsSource::Inline(test_rootfs("missing-token")?),
    )
    .await?;

    let msg = read_error_message(&mut recv).await?;
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
    let Some(port) = choose_udp_port()? else {
        return Ok(());
    };
    let args = args_for_test(&temp, port)?;
    let shared = shared_state_for_args(&args, Some("correct-token".to_string())).await?;
    let server = tokio::spawn(quic::serve(args.clone(), shared));

    let endpoint = test_endpoint()?;
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    let conn = connect_with_retry(&endpoint, addr).await?;
    let (mut send, mut recv) = open_control_stream(&conn).await?;

    let att = request_attestation(&mut send, &mut recv).await?;
    assert_eq!(att.state, VmState::Cold);

    send_setup_request(
        &mut send,
        "wrong-token",
        RootfsSource::Inline(test_rootfs("wrong-token")?),
    )
    .await?;

    let msg = read_error_message(&mut recv).await?;
    assert!(
        msg.contains("verification failed"),
        "expected verification error, got: {msg}"
    );

    server.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ready_rejects_wrong_access_token() -> Result<()> {
    let temp = TempDir::new().context("create temp dir")?;
    let Some(port) = choose_udp_port()? else {
        return Ok(());
    };
    let args = args_for_test(&temp, port)?;
    let shared = shared_state_for_args(&args, Some("test-access-token".to_string())).await?;
    let server = tokio::spawn(quic::serve(args.clone(), shared));

    let endpoint = test_endpoint()?;
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    let conn = connect_with_retry(&endpoint, addr).await?;

    provision_cold(
        &conn,
        "test-access-token",
        ControlRootfs::Inline(test_rootfs("ready-wrong-token")?),
    )
    .await?;

    let (mut send2, mut recv2) = open_control_stream(&conn).await?;
    let att2 = request_attestation(&mut send2, &mut recv2).await?;
    assert_eq!(att2.state, VmState::Ready);

    send_setup_request(&mut send2, "wrong-token", RootfsSource::None).await?;
    let msg = read_error_message(&mut recv2).await?;
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
    let Some(port) = choose_udp_port()? else {
        return Ok(());
    };
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
    let Some(port) = choose_udp_port()? else {
        return Ok(());
    };
    let args = args_for_test(&temp, port)?;
    let shared = shared_state_for_args(&args, Some("test-access-token".to_string())).await?;
    let server = tokio::spawn(quic::serve(args.clone(), shared));

    let endpoint = test_endpoint()?;
    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    let conn = connect_with_retry(&endpoint, addr).await?;

    provision_cold(
        &conn,
        "test-access-token",
        ControlRootfs::Inline(test_rootfs("ready-reprovision-v1")?),
    )
    .await?;

    let (mut send2, mut recv2) = open_control_stream(&conn).await?;
    let att2 = request_attestation(&mut send2, &mut recv2).await?;
    assert_eq!(att2.state, VmState::Ready);

    send_setup_request(
        &mut send2,
        "test-access-token",
        RootfsSource::Inline(test_rootfs("ready-reprovision-v2")?),
    )
    .await?;
    wait_setup_complete(&mut recv2).await?;

    server.abort();
    Ok(())
}

async fn provision_cold(conn: &Connection, token: &str, rootfs: ControlRootfs) -> Result<()> {
    let (mut send, mut recv) = open_control_stream(conn).await?;

    let att = request_attestation(&mut send, &mut recv).await?;
    assert_eq!(att.state, VmState::Cold);
    assert_eq!(att.runtime_status, RuntimeStatus::NotStarted);

    send_setup_request(
        &mut send,
        token,
        match rootfs {
            ControlRootfs::Inline(data) => RootfsSource::Inline(data),
            ControlRootfs::Url(url) => RootfsSource::Url(url),
        },
    )
    .await?;

    wait_setup_complete(&mut recv).await
}

enum ControlRootfs {
    Inline(Vec<u8>),
    Url(String),
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
        console: Arc::new(forward::SharedConsoleManager::new()),
        exec_sessions: Arc::new(forward::ExecSessionManager::new()),
    })))
}

async fn open_control_stream(conn: &Connection) -> Result<(quinn::SendStream, quinn::RecvStream)> {
    let (mut send, recv) = conn.open_bi().await.context("open control stream")?;
    send.write_u8(STREAM_CONTROL)
        .await
        .context("write control stream tag")?;
    Ok((send, recv))
}

async fn ready_connection(
    endpoint: &Endpoint,
    addr: SocketAddr,
    token: &str,
) -> Result<Connection> {
    let conn = connect_with_retry(endpoint, addr).await?;
    let (mut send, mut recv) = open_control_stream(&conn).await?;
    let attestation = request_attestation(&mut send, &mut recv).await?;
    assert_eq!(attestation.state, VmState::Ready);
    send_setup_request(&mut send, token, RootfsSource::None).await?;
    wait_setup_complete(&mut recv).await?;
    Ok(conn)
}

async fn open_console_shell_stream(
    conn: &Connection,
) -> Result<(quinn::SendStream, quinn::RecvStream)> {
    let (mut send, recv) = conn.open_bi().await.context("open console stream")?;
    send.write_u8(STREAM_CONSOLE)
        .await
        .context("write console stream tag")?;
    ConsoleFrame::new(CONSOLE_SHELL, vec![])
        .write_to(&mut send)
        .await
        .context("send console shell startup")?;
    Ok((send, recv))
}

async fn open_exec_session_stream(
    conn: &Connection,
    request: ExecSessionRequest,
) -> Result<(quinn::SendStream, quinn::RecvStream)> {
    let (mut send, recv) = conn.open_bi().await.context("open exec console stream")?;
    send.write_u8(STREAM_CONSOLE)
        .await
        .context("write exec console stream tag")?;
    ConsoleFrame::new(CONSOLE_EXEC, request.to_bytes())
        .write_to(&mut send)
        .await
        .context("send exec session startup")?;
    Ok((send, recv))
}

async fn list_exec_sessions(conn: &Connection) -> Result<ExecSessionList> {
    let (mut send, mut recv) = conn.open_bi().await.context("open exec-list stream")?;
    send.write_u8(STREAM_EXEC_LIST)
        .await
        .context("write exec-list stream tag")?;
    send.finish().context("finish exec-list request")?;
    ExecSessionList::read_from(&mut recv).await
}

async fn send_console_input(send: &mut quinn::SendStream, input: &str) -> Result<()> {
    ConsoleFrame::new(CONSOLE_DATA, input.as_bytes().to_vec())
        .write_to(send)
        .await
        .with_context(|| format!("send console input {:?}", input))
}

async fn read_console_until(recv: &mut quinn::RecvStream, needle: &str) -> Result<String> {
    let mut out = Vec::new();
    for _ in 0..200 {
        let frame = tokio::time::timeout(Duration::from_millis(250), ConsoleFrame::read_from(recv))
            .await
            .context("timed out waiting for console output")??;
        if frame.ty == CONSOLE_DATA {
            out.extend_from_slice(&frame.payload);
            let text = String::from_utf8_lossy(&out);
            if text.contains(needle) {
                return Ok(text.into_owned());
            }
        }
    }
    Err(anyhow!("console output did not contain marker {needle}"))
}

async fn wait_for_console_exit(recv: &mut quinn::RecvStream) -> Result<u32> {
    loop {
        let frame = tokio::time::timeout(Duration::from_millis(250), ConsoleFrame::read_from(recv))
            .await
            .context("timed out waiting for console exit")??;
        if frame.ty == protocol::CONSOLE_EXIT {
            return protocol::decode_exit(&frame.payload);
        }
    }
}

async fn request_attestation(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
) -> Result<AttestationPayload> {
    ControlMessage::RequestAttestation
        .write_to(send)
        .await
        .context("send RequestAttestation")?;

    match ControlMessage::read_from(recv)
        .await
        .context("read attestation frame")?
    {
        ControlMessage::Attestation(payload) => {
            assert_eq!(payload.protocol_version, PROTOCOL_VERSION);
            Ok(payload)
        }
        other => Err(anyhow!("expected attestation, got {other:?}")),
    }
}

async fn send_setup_request(
    send: &mut quinn::SendStream,
    access_token: &str,
    rootfs: RootfsSource,
) -> Result<()> {
    ControlMessage::SetupRequest(SetupRequest {
        access_token: access_token.to_string(),
        rootfs,
    })
    .write_to(send)
    .await
    .context("send setup request")
}

async fn wait_setup_complete(recv: &mut quinn::RecvStream) -> Result<()> {
    match ControlMessage::read_from(recv)
        .await
        .context("read setup frame")?
    {
        ControlMessage::SetupComplete => Ok(()),
        ControlMessage::Error(msg) => Err(anyhow!("init setup failed: {msg}")),
        other => Err(anyhow!("expected setup response, got {other:?}")),
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
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let cfg = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|e| anyhow!("build quinn rustls client config: {e}"))?;
    Ok(ClientConfig::new(Arc::new(cfg)))
}

fn choose_udp_port() -> Result<Option<u16>> {
    let sock = match UdpSocket::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0))) {
        Ok(sock) => sock,
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::AddrNotAvailable
            ) =>
        {
            return Ok(None);
        }
        Err(err) => return Err(err).context("bind local UDP socket for port selection"),
    };
    Ok(Some(
        sock.local_addr()
            .context("read local UDP socket address")?
            .port(),
    ))
}

async fn read_error_message(recv: &mut quinn::RecvStream) -> Result<String> {
    match ControlMessage::read_from(recv)
        .await
        .context("read error frame")?
    {
        ControlMessage::Error(message) => Ok(message),
        other => Err(anyhow!("expected error frame, got {other:?}")),
    }
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

fn test_rootfs(version: &str) -> Result<Vec<u8>> {
    let root_profile = format!("root profile {version}");
    let home_welcome = format!("home welcome {version}");
    rootfs_archive(&[
        ("etc/rootfs-version", version.as_bytes()),
        ("root/.profile", root_profile.as_bytes()),
        ("home/dev/welcome.txt", home_welcome.as_bytes()),
    ])
}

fn rootfs_archive(entries: &[(&str, &[u8])]) -> Result<Vec<u8>> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = tar::Builder::new(encoder);

    for (path, contents) in entries {
        let mut header = tar::Header::new_gnu();
        header
            .set_path(path)
            .with_context(|| format!("set tar path {path}"))?;
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append(&header, &mut std::io::Cursor::new(*contents))
            .with_context(|| format!("append tar entry {path}"))?;
    }

    builder.finish().context("finish tar builder")?;
    let encoder = builder
        .into_inner()
        .context("extract gzip encoder from tar builder")?;
    encoder.finish().context("finish gzip encoder")
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
