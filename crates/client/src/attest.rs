use anyhow::{anyhow, Context, Result};
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use reqwest::Client;
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct AttestationClaims {
    pub iss: String,
    pub aud: String,
    pub image_digest: String,
    pub app_name: String,
    pub machine_id: String,
    pub machine_version: String,
    pub exp: usize,
    pub nbf: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct RawClaims {
    iss: String,
    aud: String,
    image_digest: String,
    app_name: String,
    machine_id: String,
    machine_version: String,
    exp: usize,
    nbf: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    jwks_uri: String,
}

pub async fn verify_attestation_jwt(
    client: &Client,
    jwt: &str,
    org: &str,
    expected_aud: &str,
    allowed_digests: &[String],
) -> Result<AttestationClaims> {
    let jwt = jwt.trim_end_matches('\n');
    tracing::debug!(jwt, "verifying attestation jwt");
    let issuer = format!("https://oidc.fly.io/{org}");
    let discovery_url = format!("{issuer}/.well-known/openid-configuration");

    let discovery = client
        .get(discovery_url)
        .send()
        .await
        .context("fetch oidc discovery")?
        .error_for_status()
        .context("oidc discovery error status")?
        .json::<OidcDiscovery>()
        .await
        .context("parse oidc discovery")?;

    let jwks = client
        .get(discovery.jwks_uri)
        .send()
        .await
        .context("fetch jwks")?
        .error_for_status()
        .context("jwks error status")?
        .json::<JwkSet>()
        .await
        .context("parse jwks")?;

    let header = decode_header(jwt).context("decode jwt header")?;
    let kid = header
        .kid
        .ok_or_else(|| anyhow!("jwt header missing kid"))?;

    let jwk = jwks
        .find(&kid)
        .ok_or_else(|| anyhow!("jwk with kid {kid} not found"))?;
    let decoding_key = DecodingKey::from_jwk(jwk).context("build decoding key from jwk")?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[issuer.as_str()]);
    validation.set_audience(&[expected_aud]);
    validation.validate_nbf = true;
    validation.required_spec_claims = ["exp", "iss", "aud"]
        .into_iter()
        .map(str::to_string)
        .collect();

    let data = decode::<RawClaims>(jwt, &decoding_key, &validation).context("verify jwt")?;

    if !allowed_digests
        .iter()
        .any(|d| d == &data.claims.image_digest)
    {
        return Err(anyhow!(
            "image digest {} is not in allowlist",
            data.claims.image_digest
        ));
    }

    Ok(AttestationClaims {
        iss: data.claims.iss,
        aud: data.claims.aud,
        image_digest: data.claims.image_digest,
        app_name: data.claims.app_name,
        machine_id: data.claims.machine_id,
        machine_version: data.claims.machine_version,
        exp: data.claims.exp,
        nbf: data.claims.nbf,
    })
}
