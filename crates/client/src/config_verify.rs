use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
struct MachineResponse {
    instance_id: String,
    config: Option<Value>,
}

pub async fn verify_machine_config(
    client: &Client,
    api_token: &str,
    app_name: &str,
    machine_id: &str,
    expected_machine_version: &str,
) -> Result<()> {
    let url = format!(
        "https://api.machines.dev/v1/apps/{}/machines/{}",
        app_name, machine_id
    );

    let machine = client
        .get(url)
        .bearer_auth(api_token)
        .send()
        .await
        .context("fetch machine config")?
        .error_for_status()
        .context("machine api error status")?
        .json::<MachineResponse>()
        .await
        .context("parse machine response")?;

    if machine.instance_id != expected_machine_version {
        return Err(anyhow!(
            "machine version mismatch: instance_id={} expected={}",
            machine.instance_id,
            expected_machine_version
        ));
    }

    let config = machine
        .config
        .ok_or_else(|| anyhow!("machine config is missing"))?;

    assert_empty_or_missing(&config, "init.exec")?;
    assert_empty_or_missing(&config, "init.entrypoint")?;
    assert_empty_or_missing(&config, "init.cmd")?;
    assert_empty_or_missing(&config, "init.kernel_args")?;
    assert_env_only_provision_token(&config)?;
    assert_empty_or_missing(&config, "files")?;
    assert_empty_or_missing(&config, "containers")?;
    assert_empty_or_missing(&config, "processes")?;
    assert_empty_or_missing(&config, "volumes")?;
    assert_empty_or_missing(&config, "statics")?;
    assert_empty_or_missing(&config, "guest.kernel_args")?;

    let mounts = get_path(&config, "mounts");
    match mounts {
        None | Some(Value::Null) => {
            return Err(anyhow!(
                "config.mounts must contain exactly one /data mount"
            ));
        }
        Some(Value::Array(arr)) => {
            if arr.len() != 1 {
                return Err(anyhow!(
                    "config.mounts must contain exactly one entry, got {}",
                    arr.len()
                ));
            }
            let path = arr[0]
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("config.mounts[0].path is missing"))?;
            if path != "/data" {
                return Err(anyhow!("config.mounts[0].path must be /data, got {path}"));
            }
        }
        Some(_) => {
            return Err(anyhow!("config.mounts must be an array"));
        }
    }

    Ok(())
}

fn assert_env_only_provision_token(config: &Value) -> Result<()> {
    let value = get_path(config, "env");
    match value {
        None | Some(Value::Null) => Ok(()),
        Some(Value::Object(map)) => {
            for key in map.keys() {
                if key.starts_with("LD_") {
                    return Err(anyhow!("config.env contains disallowed LD_* key: {key}"));
                }
            }
            Ok(())
        }
        Some(other) => Err(anyhow!("config.env must be an object or null, got {other}")),
    }
}

fn assert_empty_or_missing(root: &Value, path: &str) -> Result<()> {
    let value = get_path(root, path);
    match value {
        None | Some(Value::Null) => Ok(()),
        Some(Value::Array(a)) if a.is_empty() => Ok(()),
        Some(Value::Object(o)) if o.is_empty() => Ok(()),
        Some(Value::String(s)) if s.is_empty() => Ok(()),
        Some(other) => Err(anyhow!("config.{path} must be empty/null, got {other}")),
    }
}

fn get_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = root;
    for part in path.split('.') {
        cur = cur.get(part)?;
    }
    Some(cur)
}
