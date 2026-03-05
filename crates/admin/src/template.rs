use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub struct TenantTemplate {
    pub version: u32,
    pub app: String,
    pub machine_count: usize,
    pub machine: MachineTemplate,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub struct MachineTemplate {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    pub config: toml::Value,
    #[serde(default)]
    pub lease_ttl: Option<u32>,
    #[serde(default)]
    pub skip_launch: Option<bool>,
    #[serde(default)]
    pub skip_service_registration: Option<bool>,
    #[serde(default)]
    pub lsvd: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct RenderedMachineSpec {
    pub name: Option<String>,
    pub region: Option<String>,
    pub config: Value,
    pub metadata: HashMap<String, String>,
    pub lease_ttl: Option<u32>,
    pub skip_launch: Option<bool>,
    pub skip_service_registration: Option<bool>,
    pub lsvd: Option<bool>,
}

pub fn load_template(path: &Path) -> Result<TenantTemplate> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read template file {}", path.display()))?;
    let template: TenantTemplate = toml::from_str(&raw).context("parse tenant template toml")?;

    if template.machine_count == 0 {
        return Err(anyhow!("template machine_count must be greater than zero"));
    }

    let config_json = serde_json::to_value(&template.machine.config)
        .context("convert template machine.config to json")?;
    if !config_json.is_object() {
        return Err(anyhow!("template machine.config must be a TOML table"));
    }

    Ok(template)
}

pub fn render_template(
    template: &TenantTemplate,
    tenant_id: &str,
    access_token: Option<&str>,
    extra_vars: &HashMap<String, String>,
) -> Result<Vec<RenderedMachineSpec>> {
    let mut rendered = Vec::with_capacity(template.machine_count);

    for idx in 0..template.machine_count {
        let mut vars = extra_vars.clone();
        vars.insert("tenant_id".to_string(), tenant_id.to_string());
        vars.insert("index".to_string(), (idx + 1).to_string());

        if let Some(token) = access_token {
            vars.insert("access_token".to_string(), token.to_string());
        }

        let mut config = serde_json::to_value(&template.machine.config)
            .context("convert template machine.config to json")?;
        render_value(&mut config, &vars)?;

        let mut metadata = template.metadata.clone();
        for value in metadata.values_mut() {
            *value = render_string(value, &vars)?;
        }

        rendered.push(RenderedMachineSpec {
            name: template
                .machine
                .name
                .as_ref()
                .map(|name| render_string(name, &vars))
                .transpose()?,
            region: template
                .machine
                .region
                .as_ref()
                .map(|region| render_string(region, &vars))
                .transpose()?,
            config,
            metadata,
            lease_ttl: template.machine.lease_ttl,
            skip_launch: template.machine.skip_launch,
            skip_service_registration: template.machine.skip_service_registration,
            lsvd: template.machine.lsvd,
        });
    }

    Ok(rendered)
}

fn render_value(value: &mut Value, vars: &HashMap<String, String>) -> Result<()> {
    match value {
        Value::String(s) => {
            *s = render_string(s, vars)?;
        }
        Value::Array(items) => {
            for item in items {
                render_value(item, vars)?;
            }
        }
        Value::Object(map) => {
            for nested in map.values_mut() {
                render_value(nested, vars)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn render_string(input: &str, vars: &HashMap<String, String>) -> Result<String> {
    let mut output = input.to_string();
    for (key, value) in vars {
        let token = format!("{{{{{key}}}}}");
        output = output.replace(&token, value);
    }

    if output.contains("{{") && output.contains("}}") {
        return Err(anyhow!("unresolved template variables in '{}'", input));
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_placeholders() {
        let template: TenantTemplate = toml::from_str(
            r#"
            version = 1
            app = "vault-tenants"
            machine_count = 1

            [machine]
            name = "tenant-{{tenant_id}}-{{index}}"
            region = "ord"

            [machine.config]
            image = "registry.fly.io/init:latest"

            [machine.config.env]
            ACCESS_TOKEN = "{{access_token}}"

            [metadata]
            role = "{{tenant_id}}"
            "#,
        )
        .unwrap();

        let rendered = render_template(
            &template,
            "alpha",
            Some("secret"),
            &HashMap::from([(String::from("extra"), String::from("x"))]),
        )
        .unwrap();

        assert_eq!(rendered.len(), 1);
        assert_eq!(rendered[0].name.as_deref(), Some("tenant-alpha-1"));
        assert_eq!(
            rendered[0].config["env"]["ACCESS_TOKEN"].as_str(),
            Some("secret")
        );
        assert_eq!(
            rendered[0].metadata.get("role").map(String::as_str),
            Some("alpha")
        );
    }
}
