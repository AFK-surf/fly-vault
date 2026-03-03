use anyhow::{Context, Result};
use reqwest::Client;
use serde_json::json;

pub async fn fetch_oidc_token(aud: &str) -> Result<String> {
    let client = Client::builder()
        .unix_socket("/.fly/api")
        .build()
        .context("build unix socket client for fly local api")?;

    let resp = client
        .post("http://localhost/v1/tokens/oidc")
        .json(&json!({ "aud": aud }))
        .send()
        .await
        .context("request fly oidc token")?
        .error_for_status()
        .context("fly oidc token request failed")?;

    let token = resp.text().await.context("read oidc token response body")?;
    Ok(token)
}
