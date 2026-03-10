use crate::attest;
use crate::cache::{AttestationCache, CacheEntry};
use crate::console;
use crate::control;
use crate::forward;
use crate::proxy_udp::ProxyUdpSocket;
use crate::{TransportConfig, VaultConfig};
use anyhow::{anyhow, Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use protocol::{
    AttestationPayload, ControlMessage, ExecSessionInfo, ExecSessionList, RootfsSource,
    SetupRequest, VmState, CHANNEL_BINDING_LABEL, PROTOCOL_VERSION, STREAM_CONTROL,
    STREAM_EXEC_LIST,
};
use quinn::{default_runtime, ClientConfig, Endpoint, EndpointConfig};
use rand::RngCore;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};
use std::any::Any;
use std::io::IsTerminal;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, Notify};
use tracing::{info, warn};

#[derive(Clone)]
pub(crate) struct ReconnectableConnection {
    inner: Arc<ReconnectableConnectionInner>,
}

struct ReconnectableConnectionInner {
    cfg: VaultConfig,
    state: Mutex<ReconnectState>,
    notify: Notify,
}

#[derive(Clone)]
pub(crate) struct ConnectionLease {
    conn: quinn::Connection,
    generation: u64,
}

struct ReconnectState {
    current: Option<ConnectionLease>,
    next_generation: u64,
    connected_once: bool,
    reconnecting: bool,
    reprovision: bool,
}

impl ReconnectableConnection {
    pub(crate) fn new(cfg: VaultConfig, reprovision: bool) -> Self {
        Self {
            inner: Arc::new(ReconnectableConnectionInner {
                cfg,
                state: Mutex::new(ReconnectState {
                    current: None,
                    next_generation: 0,
                    connected_once: false,
                    reconnecting: false,
                    reprovision,
                }),
                notify: Notify::new(),
            }),
        }
    }

    pub(crate) async fn connect(&self) -> Result<ConnectionLease> {
        loop {
            let connect_attempt = {
                let mut state = self.inner.state.lock().await;
                if let Some(lease) = state.current.clone() {
                    return Ok(lease);
                }
                if state.reconnecting {
                    None
                } else {
                    state.reconnecting = true;
                    Some((state.connected_once, state.reprovision))
                }
            };

            let Some((connected_once, reprovision)) = connect_attempt else {
                self.inner.notify.notified().await;
                continue;
            };

            match connect_ready(&self.inner.cfg, reprovision).await {
                Ok(conn) => {
                    let lease = {
                        let mut state = self.inner.state.lock().await;
                        let lease = ConnectionLease {
                            conn,
                            generation: state.next_generation,
                        };
                        state.next_generation += 1;
                        state.connected_once = true;
                        state.reprovision = false;
                        state.reconnecting = false;
                        state.current = Some(lease.clone());
                        lease
                    };
                    self.inner.notify.notify_waiters();
                    return Ok(lease);
                }
                Err(err) => {
                    {
                        let mut state = self.inner.state.lock().await;
                        state.reconnecting = false;
                    }
                    self.inner.notify.notify_waiters();

                    if connected_once && console::is_reconnectable_transport(&err) {
                        warn!(error = ?err, "reconnect failed; retrying");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }

                    tracing::error!(error = ?err, "reconnect failed; not retrying");
                    return Err(err);
                }
            }
        }
    }

    pub(crate) async fn invalidate(&self, generation: u64) {
        let mut state = self.inner.state.lock().await;
        if state
            .current
            .as_ref()
            .is_some_and(|lease| lease.generation == generation)
        {
            state.current = None;
            self.inner.notify.notify_waiters();
        }
    }
}

impl ConnectionLease {
    pub(crate) fn conn(&self) -> quinn::Connection {
        self.conn.clone()
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
}

pub async fn connect_and_run(
    cfg: VaultConfig,
    forwards: Vec<String>,
    reprovision: bool,
    control_socket: Option<PathBuf>,
) -> Result<()> {
    let connections = ReconnectableConnection::new(cfg.clone(), reprovision);

    if forwards.is_empty() && control_socket.is_none() {
        run_console_with_reconnect(&connections).await?;
    } else {
        let console_connections = connections.clone();
        tokio::spawn(async move {
            if let Err(err) = run_console_with_reconnect(&console_connections).await {
                warn!(error = %err, "console exited");
            }
        });

        if let Some(path) = control_socket {
            let control_connections = connections.clone();
            tokio::spawn(async move {
                if let Err(err) = control::serve(control_connections, path).await {
                    warn!(error = %err, "control socket exited");
                }
            });
        }

        if forwards.is_empty() {
            tokio::signal::ctrl_c().await?;
        } else {
            forward::run_local_forwarders(connections, forwards).await?;
        }
    }

    Ok(())
}

pub async fn connect_and_exec(
    cfg: VaultConfig,
    session: Option<String>,
    context: Option<String>,
    command: Vec<String>,
) -> Result<u32> {
    let session_id = session.unwrap_or_else(generate_exec_session_id);
    let has_command = !command.is_empty();
    eprintln!("exec session {session_id}");
    let request = console::build_exec_request(
        session_id,
        if has_command { Some(command) } else { None },
        if has_command { context } else { None },
    );
    let connections = ReconnectableConnection::new(cfg, false);
    run_exec_with_reconnect(&connections, request).await
}

pub async fn list_exec_sessions(cfg: VaultConfig) -> Result<Vec<ExecSessionInfo>> {
    let conn = connect_ready(&cfg, false).await?;
    let (mut send, mut recv) = conn.open_bi().await.context("open exec-list stream")?;
    send.write_u8(STREAM_EXEC_LIST)
        .await
        .context("write exec-list stream tag")?;
    send.finish().context("finish exec-list request")?;
    let list = ExecSessionList::read_from(&mut recv).await?;
    Ok(list.sessions)
}

async fn run_console_with_reconnect(connections: &ReconnectableConnection) -> Result<()> {
    let mut rendered_bytes = 0;

    loop {
        let lease = connections.connect().await?;

        let progress = console::run_console(lease.conn(), rendered_bytes).await?;
        rendered_bytes = progress.rendered_bytes;
        match progress.outcome {
            console::ConsoleSessionOutcome::Exited(_) => return Ok(()),
            console::ConsoleSessionOutcome::Disconnected => {
                connections.invalidate(lease.generation()).await;
                warn!("console connection lost; reconnecting");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

async fn run_exec_with_reconnect(
    connections: &ReconnectableConnection,
    request: protocol::ExecSessionRequest,
) -> Result<u32> {
    let mut request = request;

    loop {
        let lease = connections.connect().await?;
        let progress = console::run_exec(lease.conn(), request.clone()).await?;
        request.rendered_bytes = progress.rendered_bytes;
        match progress.outcome {
            console::ConsoleSessionOutcome::Exited(exit_code) => return Ok(exit_code),
            console::ConsoleSessionOutcome::Disconnected => {
                connections.invalidate(lease.generation()).await;
                warn!(
                    session_id = %request.session_id,
                    "exec connection lost; reconnecting"
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

pub(crate) async fn run_exec_streaming_with_reconnect(
    connections: &ReconnectableConnection,
    request: protocol::ExecSessionRequest,
    output_tx: tokio::sync::mpsc::Sender<bytes::Bytes>,
) -> Result<u32> {
    let mut request = request;

    loop {
        let lease = connections.connect().await?;
        let progress =
            console::run_exec_streaming(lease.conn(), request.clone(), output_tx.clone()).await?;
        request.rendered_bytes = progress.rendered_bytes;
        match progress.outcome {
            console::ConsoleSessionOutcome::Exited(exit_code) => return Ok(exit_code),
            console::ConsoleSessionOutcome::Disconnected => {
                connections.invalidate(lease.generation()).await;
                warn!(
                    session_id = %request.session_id,
                    "streaming exec connection lost; reconnecting"
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

pub(crate) fn generate_exec_session_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[derive(Debug, Clone, Copy)]
enum ConnectPhase {
    ResolvingAddress,
    Handshaking,
    RequestingAttestation,
    VerifyingAttestation,
    SendingSetupRequest,
    WaitingForReady,
}

impl ConnectPhase {
    fn message(self) -> &'static str {
        match self {
            ConnectPhase::ResolvingAddress => "Resolving machine address",
            ConnectPhase::Handshaking => "Connecting to machine",
            ConnectPhase::RequestingAttestation => "Requesting machine attestation",
            ConnectPhase::VerifyingAttestation => "Verifying machine attestation",
            ConnectPhase::SendingSetupRequest => "Sending setup request",
            ConnectPhase::WaitingForReady => "Waiting for machine to become ready",
        }
    }
}

struct ConnectSpinner {
    bar: Option<ProgressBar>,
}

impl ConnectSpinner {
    fn new(cfg: &VaultConfig) -> Self {
        if !std::io::stderr().is_terminal() {
            return Self { bar: None };
        }

        let bar = ProgressBar::new_spinner();
        bar.set_style(
            ProgressStyle::with_template("{spinner} {msg}")
                .expect("spinner template should be valid"),
        );
        bar.enable_steady_tick(std::time::Duration::from_millis(100));
        bar.set_message(format!("Connecting to {}", cfg.app));

        Self { bar: Some(bar) }
    }

    fn set_phase(&self, phase: ConnectPhase) {
        if let Some(bar) = &self.bar {
            bar.set_message(phase.message());
        }
    }

    fn set_setup_message(&self, state: VmState, reprovision: bool) {
        let message = if state == VmState::Ready && !reprovision {
            "Authenticating with machine"
        } else if reprovision {
            "Loading replacement rootfs"
        } else {
            "Loading rootfs"
        };

        if let Some(bar) = &self.bar {
            bar.set_message(message);
        }
    }
}

impl Drop for ConnectSpinner {
    fn drop(&mut self) {
        if let Some(bar) = &self.bar {
            if !bar.is_finished() {
                bar.finish_and_clear();
            }
        }
    }
}

async fn connect_ready(cfg: &VaultConfig, reprovision: bool) -> Result<quinn::Connection> {
    let transport = cfg.transport();
    let spinner = ConnectSpinner::new(cfg);
    let mut endpoint = build_client_endpoint(&transport)?;
    endpoint.set_default_client_config(insecure_client_config()?);

    spinner.set_phase(ConnectPhase::ResolvingAddress);
    let remote = resolve_addr(&cfg.address)?;
    spinner.set_phase(ConnectPhase::Handshaking);
    let connect = endpoint
        .connect(remote, "fly-vault")
        .context("connect quic")?;
    let conn = connect.await.context("await quic connect")?;
    let tls_fingerprint = server_cert_fingerprint(&conn)?;
    let mut attestation_cache = load_attestation_cache();

    let aud = export_attestation_audience(&conn)?;
    spinner.set_phase(ConnectPhase::RequestingAttestation);
    let (mut send, mut recv) = conn.open_bi().await.context("open control stream")?;
    send.write_u8(STREAM_CONTROL)
        .await
        .context("write control stream tag")?;

    ControlMessage::RequestAttestation
        .write_to(&mut send)
        .await
        .context("request attestation")?;

    let attestation = match ControlMessage::read_from(&mut recv).await? {
        ControlMessage::Attestation(payload) => payload,
        other => return Err(anyhow!("expected attestation frame, got {other:?}")),
    };
    spinner.set_phase(ConnectPhase::VerifyingAttestation);
    validate_attestation(
        cfg,
        &transport,
        &attestation,
        &aud,
        &tls_fingerprint,
        &mut attestation_cache,
    )
    .await?;

    let access_token = cfg
        .access_token
        .clone()
        .ok_or_else(|| anyhow!("access_token is required"))?;
    spinner.set_setup_message(attestation.state, reprovision);
    let rootfs = provisioning_source(cfg, attestation.state, reprovision).await?;

    spinner.set_phase(ConnectPhase::SendingSetupRequest);
    ControlMessage::SetupRequest(SetupRequest {
        access_token,
        rootfs,
    })
    .write_to(&mut send)
    .await
    .context("send setup request")?;

    spinner.set_phase(ConnectPhase::WaitingForReady);
    match ControlMessage::read_from(&mut recv).await? {
        ControlMessage::SetupComplete => Ok(conn),
        ControlMessage::Error(message) => Err(anyhow!("server setup error: {message}")),
        other => Err(anyhow!("expected setup response, got {other:?}")),
    }
}

fn export_attestation_audience(conn: &quinn::Connection) -> Result<String> {
    let mut ekm = [0u8; 32];
    conn.export_keying_material(&mut ekm, CHANNEL_BINDING_LABEL.as_bytes(), &[])
        .map_err(|_| anyhow!("export keying material failed"))?;
    Ok(hex::encode(ekm))
}

async fn validate_attestation(
    cfg: &VaultConfig,
    transport: &TransportConfig,
    attestation: &AttestationPayload,
    aud: &str,
    tls_fingerprint: &str,
    attestation_cache: &mut AttestationCache,
) -> Result<()> {
    assert_protocol_version(attestation)?;

    if let Some(entry) = attestation_cache
        .lookup(cfg, transport, tls_fingerprint)
        .cloned()
    {
        if let Err(err) = attestation_cache.record_cache_hit(cfg, transport, tls_fingerprint) {
            warn!(error = ?err, "failed to update attestation cache hit timestamp");
        }
        log_cached_attestation_hit(attestation, tls_fingerprint, &entry);
        return Ok(());
    }

    let http_client = reqwest::Client::builder()
        .use_rustls_tls()
        .build()
        .context("build reqwest client")?;

    let claims =
        attest::verify_attestation_jwt(&http_client, &attestation.jwt, &cfg.org, aud).await?;
    assert_org_and_app(&claims.iss, &claims.app_name, cfg)?;
    assert_machine_id(&claims.machine_id, transport)?;
    if let Err(err) = attestation_cache.record_verified(cfg, &claims.machine_id, tls_fingerprint) {
        warn!(error = ?err, "failed to persist attestation cache entry");
    }
    info!(
        issuer = %claims.iss,
        app = %claims.app_name,
        machine = %claims.machine_id,
        tls_fingerprint,
        state = ?attestation.state,
        runtime_status = ?attestation.runtime_status,
        "attestation verified"
    );
    Ok(())
}

fn load_attestation_cache() -> AttestationCache {
    match AttestationCache::load_default() {
        Ok(cache) => cache,
        Err(err) => {
            warn!(error = ?err, "failed to load attestation cache; continuing without cache");
            AttestationCache::default()
        }
    }
}

fn assert_protocol_version(attestation: &AttestationPayload) -> Result<()> {
    if attestation.protocol_version != PROTOCOL_VERSION {
        return Err(anyhow!(
            "protocol version mismatch: server={} client={}",
            attestation.protocol_version,
            PROTOCOL_VERSION
        ));
    }

    Ok(())
}

fn server_cert_fingerprint(conn: &quinn::Connection) -> Result<String> {
    let identity = conn
        .peer_identity()
        .ok_or_else(|| anyhow!("missing peer identity"))?;
    server_cert_fingerprint_from_identity(identity)
}

fn server_cert_fingerprint_from_identity(identity: Box<dyn Any>) -> Result<String> {
    let certs = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| anyhow!("unexpected peer identity type"))?;
    let cert = certs
        .first()
        .ok_or_else(|| anyhow!("peer identity did not include a certificate"))?;
    Ok(hex::encode(Sha256::digest(cert.as_ref())))
}

fn log_cached_attestation_hit(
    attestation: &AttestationPayload,
    tls_fingerprint: &str,
    entry: &CacheEntry,
) {
    info!(
        app = %entry.app,
        machine = %entry.machine_id,
        tls_fingerprint,
        state = ?attestation.state,
        runtime_status = ?attestation.runtime_status,
        "reused cached attestation"
    );
}

async fn provisioning_source(
    cfg: &VaultConfig,
    state: VmState,
    reprovision: bool,
) -> Result<RootfsSource> {
    if state == VmState::Ready && !reprovision {
        return Ok(RootfsSource::None);
    }

    match (&cfg.rootfs, &cfg.rootfs_url) {
        (Some(_), Some(_)) => Err(anyhow!(
            "both rootfs and rootfs_url are set; configure exactly one"
        )),
        (None, None) => Err(anyhow!(
            "either rootfs path or rootfs_url is required for {}",
            if state == VmState::Cold {
                "cold boot"
            } else {
                "reprovision"
            }
        )),
        (Some(rootfs_path), None) => {
            let rootfs_bytes = tokio::fs::read(expand_tilde(rootfs_path)?)
                .await
                .with_context(|| format!("read rootfs {}", rootfs_path))?;
            Ok(RootfsSource::Inline(rootfs_bytes))
        }
        (None, Some(rootfs_url)) => {
            let parsed = url::Url::parse(rootfs_url)
                .with_context(|| format!("parse rootfs_url {}", rootfs_url))?;
            if !matches!(parsed.scheme(), "http" | "https") {
                return Err(anyhow!(
                    "rootfs_url must use http or https scheme, got {}",
                    parsed.scheme()
                ));
            }
            Ok(RootfsSource::Url(parsed.to_string()))
        }
    }
}

fn resolve_addr(addr: &str) -> Result<SocketAddr> {
    let resolved = addr
        .to_socket_addrs()
        .with_context(|| format!("resolve address {addr}"))?
        .next()
        .ok_or_else(|| anyhow!("address resolution returned no results for {addr}"))?;
    Ok(resolved)
}

fn build_client_endpoint(transport: &TransportConfig) -> Result<Endpoint> {
    match transport {
        TransportConfig::Direct => {
            Endpoint::client("[::]:0".parse().unwrap()).context("create quic client")
        }
        TransportConfig::Proxy { machine_id } => build_proxy_endpoint(machine_id),
    }
}

fn build_proxy_endpoint(machine_id: &str) -> Result<Endpoint> {
    let runtime = default_runtime().ok_or_else(|| anyhow!("no async runtime found"))?;
    let socket = std::net::UdpSocket::bind("[::]:0")
        .or_else(|_| std::net::UdpSocket::bind("0.0.0.0:0"))
        .context("bind proxy-mode udp socket")?;
    let wrapped = runtime
        .wrap_udp_socket(socket)
        .context("wrap proxy-mode udp socket")?;
    let proxy_socket = Arc::new(
        ProxyUdpSocket::new(wrapped, machine_id.to_string())
            .map_err(|e| anyhow!("configure proxy-mode udp socket: {e}"))?,
    );
    Endpoint::new_with_abstract_socket(EndpointConfig::default(), None, proxy_socket, runtime)
        .context("create quic client")
}

fn insecure_client_config() -> Result<ClientConfig> {
    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let mut transport = quinn::TransportConfig::default();
    transport.initial_mtu(1200);
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    transport.max_idle_timeout(Some(
        std::time::Duration::from_secs(30)
            .try_into()
            .context("idle timeout")?,
    ));
    transport.mtu_discovery_config(None);
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(2)));

    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .context("build quinn rustls client config")?,
    ));
    client_config.transport_config(Arc::new(transport));
    Ok(client_config)
}

fn expand_tilde(path: &str) -> Result<PathBuf> {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = dirs::home_dir().ok_or_else(|| anyhow!("unable to determine home dir"))?;
        return Ok(home.join(rest));
    }
    Ok(PathBuf::from(path))
}

fn assert_org_and_app(issuer: &str, app_name: &str, cfg: &VaultConfig) -> Result<()> {
    let expected_issuer = format!("https://oidc.fly.io/{}", cfg.org);
    if issuer != expected_issuer {
        return Err(anyhow!(
            "attestation org mismatch: issuer={} expected={}",
            issuer,
            expected_issuer
        ));
    }

    if app_name != cfg.app {
        return Err(anyhow!(
            "attestation app mismatch: app_name={} expected={}",
            app_name,
            cfg.app
        ));
    }

    Ok(())
}

fn assert_machine_id(attested_machine_id: &str, transport: &TransportConfig) -> Result<()> {
    if let TransportConfig::Proxy { machine_id } = transport {
        if attested_machine_id != machine_id {
            return Err(anyhow!(
                "attestation machine mismatch: machine_id={} expected={}",
                attested_machine_id,
                machine_id
            ));
        }
    }

    Ok(())
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

#[cfg(test)]
mod tests {
    use super::{
        assert_machine_id, assert_protocol_version, server_cert_fingerprint_from_identity,
    };
    use crate::{TransportConfig, VaultConfig};
    use protocol::{AttestationPayload, RuntimeStatus, VmState, PROTOCOL_VERSION};
    use rustls_pki_types::CertificateDer;

    fn make_cfg(transport: TransportConfig) -> VaultConfig {
        VaultConfig {
            address: "127.0.0.1:443".to_string(),
            org: "test-org".to_string(),
            app: "test-app".to_string(),
            machine_id: match transport {
                TransportConfig::Direct => None,
                TransportConfig::Proxy { machine_id } => Some(machine_id),
            },
            forward: vec![],
            rootfs: None,
            rootfs_url: None,
            access_token: None,
        }
    }

    #[test]
    fn machine_id_check_skips_when_direct_transport_is_configured() {
        let cfg = make_cfg(TransportConfig::Direct);
        assert_machine_id("machine-any", &cfg.transport())
            .expect("machine id should not be enforced");
    }

    #[test]
    fn machine_id_check_accepts_proxy_match() {
        let cfg = make_cfg(TransportConfig::Proxy {
            machine_id: "machine-123".to_string(),
        });
        assert_machine_id("machine-123", &cfg.transport())
            .expect("matching machine id should pass");
    }

    #[test]
    fn machine_id_check_rejects_proxy_mismatch() {
        let cfg = make_cfg(TransportConfig::Proxy {
            machine_id: "machine-123".to_string(),
        });
        let err =
            assert_machine_id("machine-999", &cfg.transport()).expect_err("mismatched machine id");
        assert!(err
            .to_string()
            .contains("attestation machine mismatch: machine_id=machine-999 expected=machine-123"));
    }

    #[test]
    fn protocol_version_check_accepts_current_version() {
        let attestation = AttestationPayload {
            protocol_version: PROTOCOL_VERSION,
            state: VmState::Ready,
            runtime_status: RuntimeStatus::SystemInit,
            jwt: "jwt".to_string(),
        };
        assert_protocol_version(&attestation).expect("matching protocol version should pass");
    }

    #[test]
    fn protocol_version_check_rejects_mismatch() {
        let attestation = AttestationPayload {
            protocol_version: PROTOCOL_VERSION + 1,
            state: VmState::Ready,
            runtime_status: RuntimeStatus::SystemInit,
            jwt: "jwt".to_string(),
        };
        let err =
            assert_protocol_version(&attestation).expect_err("mismatched protocol should fail");
        assert!(err.to_string().contains("protocol version mismatch"));
    }

    #[test]
    fn server_cert_fingerprint_uses_leaf_certificate() {
        let identity: Box<dyn std::any::Any> = Box::new(vec![
            CertificateDer::from(vec![1u8, 2, 3, 4]),
            CertificateDer::from(vec![9u8, 9, 9, 9]),
        ]);
        let fingerprint = server_cert_fingerprint_from_identity(identity)
            .expect("fingerprint should be derived from peer identity");
        assert_eq!(
            fingerprint,
            "9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a"
        );
    }

    #[test]
    fn server_cert_fingerprint_rejects_empty_chain() {
        let identity: Box<dyn std::any::Any> = Box::new(Vec::<CertificateDer<'static>>::new());
        let err = server_cert_fingerprint_from_identity(identity)
            .expect_err("empty certificate chain should fail");
        assert!(err.to_string().contains("did not include a certificate"));
    }
}
