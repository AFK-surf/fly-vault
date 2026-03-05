use crate::attest;
use crate::config_verify;
use crate::console;
use crate::forward;
use crate::proxy_udp::ProxyUdpSocket;
use crate::VaultConfig;
use anyhow::{anyhow, Context, Result};
use crypto::XtsKey;
use protocol::{
    AttestationPayload, ControlFrame, VmState, CONTROL_ATTESTATION, CONTROL_ERROR,
    CONTROL_PROVISION_ROOTFS, CONTROL_PROVISION_ROOTFS_URL, CONTROL_PROVISION_TOKEN,
    CONTROL_RELEASE_KEY, CONTROL_REQUEST_ATTESTATION, CONTROL_SETUP_COMPLETE, STREAM_CONTROL,
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
    vault_name: String,
    cfg: VaultConfig,
    key: XtsKey,
    forwards: Vec<String>,
    reprovision: bool,
    strict: bool,
) -> Result<()> {
    let mut endpoint = build_client_endpoint(cfg.machine_id.clone())?;
    endpoint.set_default_client_config(insecure_client_config()?);

    let remote = resolve_addr(&cfg.address)?;
    let connect = endpoint
        .connect(remote, "fly-vault")
        .context("connect quic")?;
    let conn = connect.await.context("await quic connect")?;

    let mut ekm = [0u8; 32];
    conn.export_keying_material(&mut ekm, b"fly-vault-channel-binding", &[])
        .map_err(|_| anyhow!("export keying material failed"))?;
    let aud = hex::encode(ekm);

    let (mut send, mut recv) = conn.open_bi().await.context("open control stream")?;
    send.write_u8(STREAM_CONTROL)
        .await
        .context("write control stream tag")?;

    ControlFrame::new(CONTROL_REQUEST_ATTESTATION, vec![])
        .write_to(&mut send)
        .await?;

    let frame = ControlFrame::read_from(&mut recv).await?;
    if frame.ty != CONTROL_ATTESTATION {
        return Err(anyhow!("expected attestation frame, got type {}", frame.ty));
    }

    let attestation = AttestationPayload::from_bytes(&frame.payload)?;

    let http_client = reqwest::Client::builder()
        .use_rustls_tls()
        .build()
        .context("build reqwest client")?;

    if strict {
        let claims = attest::verify_attestation_jwt_strict(
            &http_client,
            &attestation.jwt,
            &cfg.org,
            &aud,
            &cfg.allowed_digests,
        )
        .await?;
        assert_org_and_app(&claims.iss, &claims.app_name, &cfg)?;
        assert_machine_id(&claims.machine_id, &cfg)?;
        info!(
            issuer = %claims.iss,
            audience = %claims.aud,
            digest = %claims.image_digest,
            app = %claims.app_name,
            machine = %claims.machine_id,
            version = %claims.machine_version,
            exp = claims.exp,
            nbf = ?claims.nbf,
            "attestation verified (strict)"
        );

        let api_token = cfg
            .fly_api_token
            .clone()
            .or_else(|| std::env::var("FLY_API_TOKEN").ok())
            .ok_or_else(|| anyhow!("missing fly api token in config or FLY_API_TOKEN"))?;

        config_verify::verify_machine_config(
            &http_client,
            &api_token,
            &claims.app_name,
            &claims.machine_id,
            &claims.machine_version,
        )
        .await?;
    } else {
        let claims =
            attest::verify_attestation_jwt_relaxed(&http_client, &attestation.jwt, &cfg.org, &aud)
                .await?;
        assert_org_and_app(&claims.iss, &claims.app_name, &cfg)?;
        assert_machine_id(&claims.machine_id, &cfg)?;
        info!(
            issuer = %claims.iss,
            app = %claims.app_name,
            machine = %claims.machine_id,
            "attestation verified (relaxed: aud+org+app)"
        );
    }

    tracing::info!(state = ?attestation.state, "vm state");

    match attestation.state {
        VmState::Cold => {
            let token = cfg
                .provision_token
                .clone()
                .ok_or_else(|| anyhow!("provision_token is required for cold boot"))?;
            ControlFrame::new(CONTROL_PROVISION_TOKEN, token.into_bytes())
                .write_to(&mut send)
                .await?;

            ControlFrame::new(CONTROL_RELEASE_KEY, key.as_bytes().to_vec())
                .write_to(&mut send)
                .await?;

            send_rootfs_provision(&cfg, &mut send, "cold boot").await?;
            wait_for_setup_complete(&mut recv).await?;
        }
        VmState::Locked => {
            if reprovision {
                let token = cfg
                    .provision_token
                    .clone()
                    .ok_or_else(|| anyhow!("provision_token is required for --reprovision"))?;
                ControlFrame::new(CONTROL_PROVISION_TOKEN, token.into_bytes())
                    .write_to(&mut send)
                    .await?;
                send_rootfs_provision(&cfg, &mut send, "--reprovision").await?;
                ControlFrame::new(CONTROL_RELEASE_KEY, key.as_bytes().to_vec())
                    .write_to(&mut send)
                    .await?;
            } else {
                ControlFrame::new(CONTROL_RELEASE_KEY, key.as_bytes().to_vec())
                    .write_to(&mut send)
                    .await?;
            }
            wait_for_setup_complete(&mut recv).await?;
        }
        VmState::Ready => {
            ControlFrame::new(CONTROL_RELEASE_KEY, key.as_bytes().to_vec())
                .write_to(&mut send)
                .await?;
            wait_for_setup_complete(&mut recv).await?;
        }
    }

    if forwards.is_empty() {
        console::run_console(conn).await?;
    } else {
        let console_conn = conn.clone();
        tokio::spawn(async move {
            let _ = console::run_console(console_conn).await;
        });

        forward::run_local_forwarders(conn, forwards).await?;
    }

    let _ = vault_name;
    Ok(())
}

async fn send_rootfs_provision(
    cfg: &VaultConfig,
    send: &mut quinn::SendStream,
    phase: &str,
) -> Result<()> {
    match (&cfg.rootfs, &cfg.rootfs_url) {
        (Some(_), Some(_)) => Err(anyhow!(
            "both rootfs and rootfs_url are set; configure exactly one for {phase}"
        )),
        (None, None) => Err(anyhow!(
            "either rootfs path or rootfs_url is required for {phase}"
        )),
        (Some(rootfs_path), None) => {
            let rootfs_bytes = tokio::fs::read(expand_tilde(rootfs_path)?)
                .await
                .with_context(|| format!("read rootfs {}", rootfs_path))?;
            ControlFrame::new(CONTROL_PROVISION_ROOTFS, rootfs_bytes)
                .write_to(send)
                .await
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
            ControlFrame::new(
                CONTROL_PROVISION_ROOTFS_URL,
                parsed.as_str().as_bytes().to_vec(),
            )
            .write_to(send)
            .await
        }
    }
}

async fn wait_for_setup_complete(recv: &mut quinn::RecvStream) -> Result<()> {
    loop {
        let frame = ControlFrame::read_from(recv).await?;
        match frame.ty {
            CONTROL_SETUP_COMPLETE => return Ok(()),
            CONTROL_ERROR => {
                let msg = String::from_utf8(frame.payload)
                    .unwrap_or_else(|_| "<non-utf8 error>".to_string());
                return Err(anyhow!("server setup error: {msg}"));
            }
            _ => continue,
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

fn build_client_endpoint(machine_id: Option<String>) -> Result<Endpoint> {
    match machine_id {
        Some(machine_id) => build_proxy_endpoint(machine_id),
        None => Endpoint::client("[::]:0".parse().unwrap()).context("create quic client"),
    }
}

fn build_proxy_endpoint(machine_id: String) -> Result<Endpoint> {
    let runtime = default_runtime().ok_or_else(|| anyhow!("no async runtime found"))?;
    let socket = std::net::UdpSocket::bind("[::]:0")
        .or_else(|_| std::net::UdpSocket::bind("0.0.0.0:0"))
        .context("bind proxy-mode udp socket")?;
    let wrapped = runtime
        .wrap_udp_socket(socket)
        .context("wrap proxy-mode udp socket")?;
    let proxy_socket = Arc::new(
        ProxyUdpSocket::new(wrapped, machine_id)
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

fn assert_machine_id(attested_machine_id: &str, cfg: &VaultConfig) -> Result<()> {
    if let Some(expected_machine_id) = cfg.machine_id.as_deref() {
        if attested_machine_id != expected_machine_id {
            return Err(anyhow!(
                "attestation machine mismatch: machine_id={} expected={}",
                attested_machine_id,
                expected_machine_id
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
    use crate::VaultConfig;

    fn make_cfg(machine_id: Option<&str>) -> VaultConfig {
        VaultConfig {
            address: "127.0.0.1:443".to_string(),
            org: "test-org".to_string(),
            app: "test-app".to_string(),
            machine_id: machine_id.map(str::to_string),
            fly_api_token: None,
            allowed_digests: vec![],
            forward: vec![],
            rootfs: None,
            rootfs_url: None,
            provision_token: None,
        }
    }

    #[test]
    fn machine_id_check_skips_when_not_configured() {
        let cfg = make_cfg(None);
        assert_machine_id("machine-any", &cfg).expect("machine id should not be enforced");
    }

    #[test]
    fn machine_id_check_accepts_match() {
        let cfg = make_cfg(Some("machine-123"));
        assert_machine_id("machine-123", &cfg).expect("matching machine id should pass");
    }

    #[test]
    fn machine_id_check_rejects_mismatch() {
        let cfg = make_cfg(Some("machine-123"));
        let err = assert_machine_id("machine-999", &cfg).expect_err("mismatched machine id");
        assert!(err
            .to_string()
            .contains("attestation machine mismatch: machine_id=machine-999 expected=machine-123"));
    }
}
