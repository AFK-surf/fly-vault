use std::collections::HashMap;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use reqwest::{Client, RequestBuilder, Response};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Clone)]
pub struct MachinesClient {
    http: Client,
    api_base: String,
    app: String,
    token: String,
}

impl MachinesClient {
    pub fn new(api_base: String, app: String, token: String) -> Self {
        Self {
            http: Client::new(),
            api_base: api_base.trim_end_matches('/').to_string(),
            app,
            token,
        }
    }

    pub fn app(&self) -> &str {
        &self.app
    }

    pub async fn list_machines(&self, query: &[(String, String)]) -> Result<Vec<Machine>> {
        let mut req = self
            .http
            .get(self.app_path("machines"))
            .bearer_auth(&self.token);

        if !query.is_empty() {
            req = req.query(query);
        }

        send(req).await
    }

    pub async fn get_machine(&self, machine_id: &str) -> Result<Machine> {
        send(
            self.http
                .get(self.machine_path(machine_id, ""))
                .bearer_auth(&self.token),
        )
        .await
    }

    pub async fn create_machine(&self, req: &CreateMachineRequest) -> Result<Machine> {
        send(
            self.http
                .post(self.app_path("machines"))
                .bearer_auth(&self.token)
                .json(req),
        )
        .await
    }

    pub async fn update_machine(
        &self,
        machine_id: &str,
        req: &UpdateMachineRequest,
        lease_nonce: Option<&str>,
    ) -> Result<Machine> {
        let mut http = self
            .http
            .post(self.machine_path(machine_id, ""))
            .bearer_auth(&self.token)
            .json(req);

        if let Some(nonce) = lease_nonce {
            http = http.header("fly-machine-lease-nonce", nonce);
        }

        send(http).await
    }

    pub async fn wait_for_state(
        &self,
        machine_id: &str,
        state: &str,
        timeout: Duration,
        instance_id: Option<&str>,
    ) -> Result<()> {
        // The API enforces timeout in [1s, 60s], so loop in 60s chunks.
        let mut remaining = timeout.as_secs().max(1);
        loop {
            let chunk = remaining.min(60);
            let mut query: Vec<(String, String)> = vec![
                ("state".to_string(), state.to_string()),
                ("timeout".to_string(), chunk.to_string()),
            ];
            if let Some(instance_id) = instance_id {
                query.push(("instance_id".to_string(), instance_id.to_string()));
            }

            let result = send_empty(
                self.http
                    .get(self.machine_path(machine_id, "wait"))
                    .bearer_auth(&self.token)
                    .query(&query),
            )
            .await;

            match result {
                Ok(()) => return Ok(()),
                Err(err) if remaining > chunk => {
                    // 408 means the server-side poll expired — retry with remaining time.
                    let msg = format!("{}", err);
                    if msg.contains("408") {
                        remaining -= chunk;
                        continue;
                    }
                    return Err(err);
                }
                Err(err) => return Err(err),
            }
        }
    }

    pub async fn stop_machine(&self, machine_id: &str) -> Result<()> {
        send_empty(
            self.http
                .post(self.machine_path(machine_id, "stop"))
                .bearer_auth(&self.token)
                .json(&json!({})),
        )
        .await
    }

    pub async fn delete_machine(&self, machine_id: &str, force: bool) -> Result<()> {
        send_empty(
            self.http
                .delete(self.machine_path(machine_id, ""))
                .bearer_auth(&self.token)
                .query(&[("force", force)]),
        )
        .await
    }

    pub async fn cordon_machine(
        &self,
        machine_id: &str,
        lease_nonce: Option<&str>,
    ) -> Result<()> {
        let mut req = self
            .http
            .post(self.machine_path(machine_id, "cordon"))
            .bearer_auth(&self.token)
            .json(&json!({}));
        if let Some(nonce) = lease_nonce {
            req = req.header("fly-machine-lease-nonce", nonce);
        }
        send_empty(req).await
    }

    pub async fn uncordon_machine(
        &self,
        machine_id: &str,
        lease_nonce: Option<&str>,
    ) -> Result<()> {
        let mut req = self
            .http
            .post(self.machine_path(machine_id, "uncordon"))
            .bearer_auth(&self.token)
            .json(&json!({}));
        if let Some(nonce) = lease_nonce {
            req = req.header("fly-machine-lease-nonce", nonce);
        }
        send_empty(req).await
    }

    pub async fn create_lease(&self, machine_id: &str, ttl_secs: u32) -> Result<MachineLease> {
        let response: LeaseResponse = send(
            self.http
                .post(self.machine_path(machine_id, "lease"))
                .bearer_auth(&self.token)
                .json(&json!({"ttl": ttl_secs})),
        )
        .await?;
        Ok(response.data)
    }

    pub async fn release_lease(&self, machine_id: &str, lease_nonce: &str) -> Result<()> {
        send_empty(
            self.http
                .delete(self.machine_path(machine_id, "lease"))
                .bearer_auth(&self.token)
                .header("fly-machine-lease-nonce", lease_nonce),
        )
        .await
    }

    pub async fn delete_volume(&self, volume_id: &str) -> Result<()> {
        send_empty(
            self.http
                .delete(format!(
                    "{}/v1/apps/{}/volumes/{}",
                    self.api_base, self.app, volume_id
                ))
                .bearer_auth(&self.token),
        )
        .await
    }

    pub async fn create_volume(&self, req: &CreateVolumeRequest) -> Result<Volume> {
        send(
            self.http
                .post(format!("{}/v1/apps/{}/volumes", self.api_base, self.app))
                .bearer_auth(&self.token)
                .json(req),
        )
        .await
    }

    fn app_path(&self, suffix: &str) -> String {
        format!("{}/v1/apps/{}/{}", self.api_base, self.app, suffix)
    }

    fn machine_path(&self, machine_id: &str, suffix: &str) -> String {
        if suffix.is_empty() {
            format!(
                "{}/v1/apps/{}/machines/{}",
                self.api_base, self.app, machine_id
            )
        } else {
            format!(
                "{}/v1/apps/{}/machines/{}/{}",
                self.api_base, self.app, machine_id, suffix
            )
        }
    }
}

async fn send<T: for<'de> Deserialize<'de>>(req: RequestBuilder) -> Result<T> {
    let response = req.send().await.context("machines api request")?;
    let response = error_for_status(response).await?;
    response
        .json::<T>()
        .await
        .context("parse machines api response")
}

async fn send_empty(req: RequestBuilder) -> Result<()> {
    let response = req.send().await.context("machines api request")?;
    let _ = error_for_status(response).await?;
    Ok(())
}

async fn error_for_status(response: Response) -> Result<Response> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }

    let body = response.text().await.unwrap_or_default();
    Err(anyhow!("machines api error {}: {}", status, body))
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateMachineRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    pub config: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_launch: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_service_registration: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lsvd: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateVolumeRequest {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_gb: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Volume {
    pub id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdateMachineRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    pub config: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_version: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LeaseResponse {
    pub data: MachineLease,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MachineLease {
    pub nonce: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Machine {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    pub state: String,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub instance_id: Option<String>,
    #[serde(default)]
    pub private_ip: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub image_ref: Option<ImageRef>,
    #[serde(default)]
    pub config: Value,
    #[serde(default)]
    pub checks: Value,
}

impl Machine {
    /// Extract metadata from `config.metadata`. The API returns metadata
    /// inside the config object, not as a top-level machine field.
    pub fn metadata(&self) -> HashMap<String, String> {
        self.config
            .as_object()
            .and_then(|obj| obj.get("metadata"))
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ImageRef {
    #[serde(default)]
    pub repository: Option<String>,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub digest: Option<String>,
}

pub fn with_metadata(config: &Value, metadata: HashMap<String, String>) -> Result<Value> {
    let mut out = config.clone();
    let obj = out
        .as_object_mut()
        .ok_or_else(|| anyhow!("machine config is not an object"))?;
    obj.insert(
        "metadata".to_string(),
        serde_json::to_value(metadata).context("serialize metadata")?,
    );
    Ok(out)
}

pub fn config_image(config: &Value) -> Option<String> {
    config
        .as_object()?
        .get("image")?
        .as_str()
        .map(ToOwned::to_owned)
}

pub fn with_image(config: &Value, image: &str) -> Result<Value> {
    let mut out = config.clone();
    let obj = out
        .as_object_mut()
        .ok_or_else(|| anyhow!("machine config is not an object"))?;
    obj.insert("image".to_string(), Value::String(image.to_string()));
    Ok(out)
}

pub fn mounted_volume_ids(machine: &Machine) -> Vec<String> {
    machine
        .config
        .as_object()
        .and_then(|obj| obj.get("mounts"))
        .and_then(Value::as_array)
        .map(|mounts| {
            mounts
                .iter()
                .filter_map(|mount| mount.as_object())
                .filter_map(|mount| mount.get("volume"))
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

pub fn checks_are_passing(checks: &Value) -> Option<bool> {
    let mut statuses = Vec::new();
    collect_statuses(checks, &mut statuses);
    if statuses.is_empty() {
        return None;
    }

    Some(statuses.iter().all(|status| {
        matches!(
            status.to_ascii_lowercase().as_str(),
            "passing" | "passed" | "healthy" | "ok"
        )
    }))
}

fn collect_statuses(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            if let Some(status) = map.get("status").and_then(Value::as_str) {
                out.push(status.to_string());
            }
            for nested in map.values() {
                collect_statuses(nested, out);
            }
        }
        Value::Array(items) => {
            for nested in items {
                collect_statuses(nested, out);
            }
        }
        _ => {}
    }
}
