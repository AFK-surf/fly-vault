use crate::attest;
use crate::console;
use crate::forward;
use crate::proxy_udp::ProxyUdpSocket;
use crate::{TransportConfig, VaultConfig};
use anyhow::{anyhow, Context, Result};
use protocol::{
    AttestationPayload, ControlMessage, RootfsSource, RuntimeStatus, SetupRequest, VmState,
    CHANNEL_BINDING_LABEL, PROTOCOL_VERSION, STREAM_CONTROL,
};
use quinn::{default_runtime, ClientConfig, Endpoint, EndpointConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tracing::info;

pub async fn connect_and_run(
    cfg: VaultConfig,
    forwards: Vec<String>,
    reprovision: bool,
) -> Result<()> {
    let conn = connect_ready(&cfg, reprovision).await?;

    if forwards.is_empty() {
        console::run_console(conn).await?;
    } else {
        let console_conn = conn.clone();
        tokio::spawn(async move {
            let _ = console::run_console(console_conn).await;
        });

        forward::run_local_forwarders(conn, forwards).await?;
    }

    Ok(())
}

pub async fn connect_and_exec(cfg: VaultConfig, command: Vec<String>) -> Result<u32> {
    let conn = connect_ready(&cfg, false).await?;
    console::run_exec(conn, command).await
}

async fn connect_ready(cfg: &VaultConfig, reprovision: bool) -> Result<quinn::Connection> {
    let transport = cfg.transport();
    let mut endpoint = build_client_endpoint(&transport)?;
    endpoint.set_default_client_config(insecure_client_config()?);

    let remote = resolve_addr(&cfg.address)?;
    let connect = endpoint
        .connect(remote, "fly-vault")
        .context("connect quic")?;
    let conn = connect.await.context("await quic connect")?;

    let aud = export_attestation_audience(&conn)?;
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
    validate_attestation(cfg, &transport, &attestation, &aud).await?;

    let access_token = cfg
        .access_token
        .clone()
        .ok_or_else(|| anyhow!("access_token is required"))?;
    let rootfs = provisioning_source(cfg, attestation.state, reprovision).await?;

    ControlMessage::SetupRequest(SetupRequest {
        access_token,
        rootfs,
    })
    .write_to(&mut send)
    .await
    .context("send setup request")?;

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
) -> Result<()> {
    if attestation.protocol_version != PROTOCOL_VERSION {
        return Err(anyhow!(
            "protocol version mismatch: server={} client={}",
            attestation.protocol_version,
            PROTOCOL_VERSION
        ));
    }

    let http_client = reqwest::Client::builder()
        .use_rustls_tls()
        .build()
        .context("build reqwest client")?;

    let claims =
        attest::verify_attestation_jwt(&http_client, &attestation.jwt, &cfg.org, aud).await?;
    assert_org_and_app(&claims.iss, &claims.app_name, cfg)?;
    assert_machine_id(&claims.machine_id, transport)?;
    assert_runtime_status(attestation)?;
    info!(
        issuer = %claims.iss,
        app = %claims.app_name,
        machine = %claims.machine_id,
        state = ?attestation.state,
        runtime_status = ?attestation.runtime_status,
        "attestation verified"
    );
    Ok(())
}

fn assert_runtime_status(attestation: &AttestationPayload) -> Result<()> {
    match (attestation.state, attestation.runtime_status) {
        (VmState::Cold, RuntimeStatus::NotStarted) => Ok(()),
        (VmState::Ready, RuntimeStatus::SystemInit) => Ok(()),
        (VmState::Ready, RuntimeStatus::FallbackInit) => {
            Err(anyhow!("server runtime degraded: fallback init is active"))
        }
        (VmState::Cold, status) => Err(anyhow!(
            "invalid cold-state runtime status reported by server: {status:?}"
        )),
        (VmState::Ready, status) => Err(anyhow!(
            "invalid ready-state runtime status reported by server: {status:?}"
        )),
    }
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
    tls.alpn_protocols = vec![b"fly-vault".to_vec()];

    let mut transport = quinn::TransportConfig::default();
    transport.initial_mtu(1200);
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    transport.max_idle_timeout(Some(
        std::time::Duration::from_secs(60)
            .try_into()
            .context("idle timeout")?,
    ));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(5)));

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
    use super::assert_machine_id;
    use crate::{TransportConfig, VaultConfig};

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
}
