use std::collections::HashMap;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use reqwest::{Client, RequestBuilder, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fmt;

#[derive(Clone)]
pub struct MachinesClient {
    http: Client,
    api_base: String,
    app: String,
    token: String,
}

pub const DEFAULT_VOLUME_SIZE_GIB: u32 = 30;

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
                Err(err) if remaining > chunk && is_wait_timeout(&err) => {
                    remaining -= chunk;
                    continue;
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

    pub async fn cordon_machine(&self, machine_id: &str, lease_nonce: Option<&str>) -> Result<()> {
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
    Err(ApiError { status, body }.into())
}

fn is_wait_timeout(err: &anyhow::Error) -> bool {
    err.downcast_ref::<ApiError>()
        .is_some_and(|api_error| api_error.status == reqwest::StatusCode::REQUEST_TIMEOUT)
}

#[derive(Debug)]
struct ApiError {
    status: reqwest::StatusCode,
    body: String,
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "machines api error {}: {}", self.status, self.body)
    }
}

impl std::error::Error for ApiError {}

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

impl CreateVolumeRequest {
    pub fn size_gib_or_default(&self) -> u32 {
        self.size_gb.unwrap_or(DEFAULT_VOLUME_SIZE_GIB)
    }
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

    pub fn usage_fact(&self) -> MachineUsageFact {
        MachineUsageFact {
            machine_id: self.id.clone(),
            state: self.state.clone(),
            region: self.region.clone(),
            instance_id: self.instance_id.clone(),
            started_at: None,
            stopped_at: None,
            deleted_at: None,
            created_at: self.created_at.clone(),
            updated_at: self.updated_at.clone(),
            metadata: self.metadata(),
            volumes: mounted_volume_facts(self),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedVolumeFact {
    pub volume_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mount_path: Option<String>,
    pub size_gib: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineUsageFact {
    pub machine_id: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stopped_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<MountedVolumeFact>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineAction {
    Stop,
    DeleteMachine,
    DeleteVolume,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineActionDisposition {
    AlreadyApplied,
    Retryable,
    Fatal,
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

pub fn mounted_volume_facts(machine: &Machine) -> Vec<MountedVolumeFact> {
    machine
        .config
        .as_object()
        .and_then(|obj| obj.get("mounts"))
        .and_then(Value::as_array)
        .map(|mounts| {
            mounts
                .iter()
                .filter_map(Value::as_object)
                .filter_map(|mount| {
                    let volume_id = mount
                        .get("volume")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|value| !value.is_empty())?
                        .to_string();
                    let name = mount
                        .get("name")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(ToOwned::to_owned);
                    let mount_path = mount
                        .get("path")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(ToOwned::to_owned);
                    let size_gib = mount
                        .get("size_gb")
                        .and_then(Value::as_u64)
                        .map(|value| value as u32)
                        .unwrap_or(DEFAULT_VOLUME_SIZE_GIB);

                    Some(MountedVolumeFact {
                        volume_id,
                        name,
                        mount_path,
                        size_gib,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn mounted_volume_ids(machine: &Machine) -> Vec<String> {
    mounted_volume_facts(machine)
        .into_iter()
        .map(|volume| volume.volume_id)
        .collect()
}

pub fn classify_machine_action_error(
    action: MachineAction,
    err: &anyhow::Error,
) -> MachineActionDisposition {
    let Some(api_error) = err.downcast_ref::<ApiError>() else {
        return MachineActionDisposition::Fatal;
    };

    match api_error.status {
        StatusCode::REQUEST_TIMEOUT
        | StatusCode::TOO_MANY_REQUESTS
        | StatusCode::BAD_GATEWAY
        | StatusCode::SERVICE_UNAVAILABLE
        | StatusCode::GATEWAY_TIMEOUT
        | StatusCode::INTERNAL_SERVER_ERROR => MachineActionDisposition::Retryable,
        StatusCode::NOT_FOUND => match action {
            MachineAction::Stop | MachineAction::DeleteMachine | MachineAction::DeleteVolume => {
                MachineActionDisposition::AlreadyApplied
            }
        },
        StatusCode::CONFLICT | StatusCode::UNPROCESSABLE_ENTITY => match action {
            MachineAction::Stop => MachineActionDisposition::AlreadyApplied,
            MachineAction::DeleteMachine | MachineAction::DeleteVolume => {
                MachineActionDisposition::Fatal
            }
        },
        _ => MachineActionDisposition::Fatal,
    }
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

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::{
        classify_machine_action_error, is_wait_timeout, mounted_volume_facts, mounted_volume_ids,
        ApiError, CreateVolumeRequest, Machine, MachineAction, MachineActionDisposition,
        DEFAULT_VOLUME_SIZE_GIB,
    };

    #[test]
    fn wait_timeout_detects_structured_408_error() {
        let err = anyhow::Error::new(ApiError {
            status: reqwest::StatusCode::REQUEST_TIMEOUT,
            body: "timeout".to_string(),
        });
        assert!(is_wait_timeout(&err));
    }

    #[test]
    fn wait_timeout_ignores_other_statuses() {
        let err = anyhow::Error::new(ApiError {
            status: reqwest::StatusCode::BAD_REQUEST,
            body: "bad request".to_string(),
        });
        assert!(!is_wait_timeout(&err));
    }

    #[test]
    fn mounted_volume_facts_extract_size_and_default() {
        let machine = Machine {
            id: "machine-1".to_string(),
            name: Some("worker".to_string()),
            state: "started".to_string(),
            region: Some("sjc".to_string()),
            instance_id: Some("inst-1".to_string()),
            private_ip: None,
            created_at: Some("2026-04-07T00:00:00Z".to_string()),
            updated_at: Some("2026-04-07T00:05:00Z".to_string()),
            image_ref: None,
            checks: Value::Null,
            config: json!({
                "metadata": { "fly_vault.tenant_id": "tenant-1" },
                "mounts": [
                    { "volume": "vol-explicit", "name": "data", "path": "/data", "size_gb": 64 },
                    { "volume": "vol-default", "path": "/cache" }
                ]
            }),
        };

        let facts = mounted_volume_facts(&machine);
        assert_eq!(facts.len(), 2);
        assert_eq!(facts[0].volume_id, "vol-explicit");
        assert_eq!(facts[0].name.as_deref(), Some("data"));
        assert_eq!(facts[0].mount_path.as_deref(), Some("/data"));
        assert_eq!(facts[0].size_gib, 64);
        assert_eq!(facts[1].volume_id, "vol-default");
        assert_eq!(facts[1].size_gib, DEFAULT_VOLUME_SIZE_GIB);
        assert_eq!(
            mounted_volume_ids(&machine),
            vec!["vol-explicit".to_string(), "vol-default".to_string()]
        );
    }

    #[test]
    fn machine_usage_fact_preserves_runtime_fields() {
        let machine = Machine {
            id: "machine-1".to_string(),
            name: Some("worker".to_string()),
            state: "stopped".to_string(),
            region: Some("sjc".to_string()),
            instance_id: Some("inst-1".to_string()),
            private_ip: None,
            created_at: Some("2026-04-07T00:00:00Z".to_string()),
            updated_at: Some("2026-04-07T00:05:00Z".to_string()),
            image_ref: None,
            checks: Value::Null,
            config: json!({
                "metadata": {
                    "fly_vault.tenant_id": "tenant-1",
                    "fly_vault.managed_by": "fly-vault-admin"
                },
                "mounts": [
                    { "volume": "vol-1", "size_gb": 80 }
                ]
            }),
        };

        let fact = machine.usage_fact();
        assert_eq!(fact.machine_id, "machine-1");
        assert_eq!(fact.state, "stopped");
        assert_eq!(fact.region.as_deref(), Some("sjc"));
        assert_eq!(fact.instance_id.as_deref(), Some("inst-1"));
        assert_eq!(fact.created_at.as_deref(), Some("2026-04-07T00:00:00Z"));
        assert_eq!(fact.updated_at.as_deref(), Some("2026-04-07T00:05:00Z"));
        assert_eq!(
            fact.metadata.get("fly_vault.tenant_id").map(String::as_str),
            Some("tenant-1")
        );
        assert_eq!(fact.volumes.len(), 1);
        assert_eq!(fact.volumes[0].volume_id, "vol-1");
        assert_eq!(fact.volumes[0].size_gib, 80);
    }

    #[test]
    fn classify_machine_action_error_treats_idempotent_paths_as_already_applied() {
        let not_found = anyhow::Error::new(ApiError {
            status: reqwest::StatusCode::NOT_FOUND,
            body: "missing".to_string(),
        });
        assert_eq!(
            classify_machine_action_error(MachineAction::DeleteMachine, &not_found),
            MachineActionDisposition::AlreadyApplied
        );
        assert_eq!(
            classify_machine_action_error(MachineAction::DeleteVolume, &not_found),
            MachineActionDisposition::AlreadyApplied
        );
        assert_eq!(
            classify_machine_action_error(MachineAction::Stop, &not_found),
            MachineActionDisposition::AlreadyApplied
        );

        let already_stopped = anyhow::Error::new(ApiError {
            status: reqwest::StatusCode::UNPROCESSABLE_ENTITY,
            body: "already stopped".to_string(),
        });
        assert_eq!(
            classify_machine_action_error(MachineAction::Stop, &already_stopped),
            MachineActionDisposition::AlreadyApplied
        );
    }

    #[test]
    fn classify_machine_action_error_marks_retryable_and_fatal_failures() {
        let timeout = anyhow::Error::new(ApiError {
            status: reqwest::StatusCode::REQUEST_TIMEOUT,
            body: "timeout".to_string(),
        });
        assert_eq!(
            classify_machine_action_error(MachineAction::DeleteMachine, &timeout),
            MachineActionDisposition::Retryable
        );

        let unavailable = anyhow::Error::new(ApiError {
            status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
            body: "busy".to_string(),
        });
        assert_eq!(
            classify_machine_action_error(MachineAction::DeleteVolume, &unavailable),
            MachineActionDisposition::Retryable
        );

        let bad_request = anyhow::Error::new(ApiError {
            status: reqwest::StatusCode::BAD_REQUEST,
            body: "bad request".to_string(),
        });
        assert_eq!(
            classify_machine_action_error(MachineAction::DeleteMachine, &bad_request),
            MachineActionDisposition::Fatal
        );
    }

    #[test]
    fn create_volume_request_uses_explicit_or_default_size() {
        let explicit = CreateVolumeRequest {
            name: "data".to_string(),
            region: Some("sjc".to_string()),
            size_gb: Some(80),
        };
        assert_eq!(explicit.size_gib_or_default(), 80);

        let defaulted = CreateVolumeRequest {
            name: "cache".to_string(),
            region: Some("sjc".to_string()),
            size_gb: None,
        };
        assert_eq!(defaulted.size_gib_or_default(), DEFAULT_VOLUME_SIZE_GIB);
    }
}
