use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use serde_json::Value;

use crate::machines::{
    checks_are_passing, classify_machine_action_error, config_image, mounted_volume_ids,
    with_metadata, CreateMachineRequest, CreateVolumeRequest, ImageRef, Machine, MachineAction,
    MachineActionDisposition, MachineUsageFact, MachinesClient, DEFAULT_VOLUME_SIZE_GIB,
};
use crate::template::{load_template, render_template};

pub const TENANT_ID_KEY: &str = "fly_vault.tenant_id";
pub const MANAGED_BY_KEY: &str = "fly_vault.managed_by";
pub const TEMPLATE_KEY: &str = "fly_vault.template";
pub const MANAGED_BY_VALUE: &str = "fly-vault-admin";

pub async fn create_tenant(
    client: &MachinesClient,
    tenant_id: &str,
    template_path: &Path,
    access_token: Option<&str>,
    extra_vars: &HashMap<String, String>,
    dry_run: bool,
    wait_timeout: Duration,
) -> Result<()> {
    let template = load_template(template_path)?;
    if template.version != 1 {
        return Err(anyhow!(
            "unsupported template version {} (expected 1)",
            template.version
        ));
    }
    if template.app != client.app() {
        return Err(anyhow!(
            "template app '{}' does not match configured app '{}'",
            template.app,
            client.app()
        ));
    }

    let template_label = template_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("template");

    let rendered = render_template(&template, tenant_id, access_token, extra_vars)?;

    let mut requests = Vec::with_capacity(rendered.len());
    let mut created_volume_ids = Vec::new();
    for machine in rendered {
        let mut metadata = machine.metadata;
        metadata.insert(TENANT_ID_KEY.to_string(), tenant_id.to_string());
        metadata.insert(MANAGED_BY_KEY.to_string(), MANAGED_BY_VALUE.to_string());
        metadata.insert(TEMPLATE_KEY.to_string(), template_label.to_string());

        let config =
            with_metadata(&machine.config, metadata).context("set metadata on machine config")?;
        let mut request = CreateMachineRequest {
            name: machine.name,
            region: machine.region,
            config,
            lease_ttl: machine.lease_ttl,
            skip_launch: machine.skip_launch,
            skip_service_registration: machine.skip_service_registration,
            lsvd: machine.lsvd,
        };

        let created = match ensure_mount_volumes(client, &mut request, dry_run).await {
            Ok(created) => created,
            Err(error) => {
                let cleanup_errors = cleanup_created_volumes(client, &created_volume_ids).await;
                return Err(with_cleanup_errors(
                    error,
                    cleanup_errors,
                    format!("prepare machine request for tenant '{}'", tenant_id),
                ));
            }
        };
        created_volume_ids.extend(created);
        requests.push(request);
    }

    if dry_run {
        println!(
            "{}",
            serde_json::to_string_pretty(&requests).context("serialize dry-run payload")?
        );
        return Ok(());
    }

    let mut created_ids = Vec::with_capacity(requests.len());

    for request in &requests {
        let machine = match client
            .create_machine(request)
            .await
            .with_context(|| format!("create machine for tenant '{}'", tenant_id))
        {
            Ok(machine) => machine,
            Err(error) => {
                let mut cleanup_errors = cleanup_created_machines(client, &created_ids).await;
                cleanup_errors.extend(cleanup_created_volumes(client, &created_volume_ids).await);
                return Err(with_cleanup_errors(
                    error,
                    cleanup_errors,
                    format!("create machine for tenant '{}'", tenant_id),
                ));
            }
        };
        println!("created machine {}", machine.id);
        created_ids.push(machine.id);
    }

    for machine_id in &created_ids {
        if let Err(error) = client
            .wait_for_state(machine_id, "started", wait_timeout, None)
            .await
            .with_context(|| format!("wait for machine {} to start", machine_id))
        {
            let mut cleanup_errors = cleanup_created_machines(client, &created_ids).await;
            cleanup_errors.extend(cleanup_created_volumes(client, &created_volume_ids).await);
            return Err(with_cleanup_errors(
                error,
                cleanup_errors,
                format!("wait for tenant '{}' machines to start", tenant_id),
            ));
        }
    }

    println!(
        "tenant '{}' created with {} machines",
        tenant_id,
        created_ids.len()
    );
    Ok(())
}

fn with_cleanup_errors(
    error: anyhow::Error,
    cleanup_errors: Vec<String>,
    context: String,
) -> anyhow::Error {
    let error = error.context(context);
    if cleanup_errors.is_empty() {
        error
    } else {
        anyhow!("{}\ncleanup errors:\n{}", error, cleanup_errors.join("\n"))
    }
}

async fn cleanup_created_machines(client: &MachinesClient, machine_ids: &[String]) -> Vec<String> {
    let mut errors = Vec::new();
    for machine_id in machine_ids {
        if let Err(err) = client.delete_machine(machine_id, true).await {
            match classify_machine_action_error(MachineAction::DeleteMachine, &err) {
                MachineActionDisposition::AlreadyApplied => {}
                MachineActionDisposition::Retryable => errors.push(format!(
                    "delete machine {} (retryable): {}",
                    machine_id, err
                )),
                MachineActionDisposition::Fatal => {
                    errors.push(format!("delete machine {}: {}", machine_id, err))
                }
            }
        }
    }
    errors
}

async fn cleanup_created_volumes(client: &MachinesClient, volume_ids: &[String]) -> Vec<String> {
    let mut errors = Vec::new();
    for volume_id in volume_ids {
        if let Err(err) = client.delete_volume(volume_id).await {
            match classify_machine_action_error(MachineAction::DeleteVolume, &err) {
                MachineActionDisposition::AlreadyApplied => {}
                MachineActionDisposition::Retryable => {
                    errors.push(format!("delete volume {} (retryable): {}", volume_id, err))
                }
                MachineActionDisposition::Fatal => {
                    errors.push(format!("delete volume {}: {}", volume_id, err))
                }
            }
        }
    }
    errors
}

async fn ensure_mount_volumes(
    client: &MachinesClient,
    request: &mut CreateMachineRequest,
    dry_run: bool,
) -> Result<Vec<String>> {
    #[derive(Debug)]
    struct PendingMount {
        index: usize,
        name: String,
    }

    let mut created_volume_ids = Vec::new();
    let region = request
        .region
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty());
    let config = request
        .config
        .as_object_mut()
        .ok_or_else(|| anyhow!("machine config must be an object"))?;

    let Some(mounts) = config.get_mut("mounts") else {
        return Ok(created_volume_ids);
    };
    let mounts = mounts
        .as_array_mut()
        .ok_or_else(|| anyhow!("machine config mounts must be an array"))?;

    let mut pending = Vec::new();
    for (index, mount) in mounts.iter().enumerate() {
        let mount_obj = mount
            .as_object()
            .ok_or_else(|| anyhow!("machine config mounts[{}] must be an object", index))?;

        let has_volume = mount_obj
            .get("volume")
            .and_then(Value::as_str)
            .map(|volume| !volume.trim().is_empty())
            .unwrap_or(false);
        if has_volume {
            continue;
        }

        let name = mount_obj
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                anyhow!(
                    "machine config mounts[{}] must include non-empty 'volume' or 'name'",
                    index
                )
            })?
            .to_string();
        pending.push(PendingMount { index, name });
    }

    for mount in pending {
        let region = region.ok_or_else(|| {
            anyhow!(
                "machine region is required when config.mounts[{}] uses name '{}' without volume",
                mount.index,
                mount.name
            )
        })?;

        if dry_run {
            let mount_obj = mounts[mount.index].as_object_mut().ok_or_else(|| {
                anyhow!("machine config mounts[{}] must be an object", mount.index)
            })?;
            mount_obj.insert(
                "volume".to_string(),
                Value::String(format!("<auto:{}@{}>", mount.name, region)),
            );
            continue;
        }

        let size_gb = mounts[mount.index]
            .as_object()
            .and_then(|mount_obj| mount_obj.get("size_gb"))
            .and_then(Value::as_u64)
            .map(|value| value as u32)
            .or(Some(DEFAULT_VOLUME_SIZE_GIB));

        let volume = match client
            .create_volume(&CreateVolumeRequest {
                name: mount.name.clone(),
                region: Some(region.to_string()),
                size_gb,
            })
            .await
            .with_context(|| format!("create volume '{}' in region '{}'", mount.name, region))
        {
            Ok(volume) => volume,
            Err(error) => {
                let cleanup_errors = cleanup_created_volumes(client, &created_volume_ids).await;
                return Err(with_cleanup_errors(
                    error,
                    cleanup_errors,
                    format!("create volume '{}' in region '{}'", mount.name, region),
                ));
            }
        };

        let mount_obj = mounts[mount.index]
            .as_object_mut()
            .ok_or_else(|| anyhow!("machine config mounts[{}] must be an object", mount.index))?;
        mount_obj.insert("volume".to_string(), Value::String(volume.id.clone()));
        created_volume_ids.push(volume.id);
    }

    Ok(created_volume_ids)
}

pub async fn list_tenants(
    client: &MachinesClient,
    tenant: Option<&str>,
    wide: bool,
    as_json: bool,
) -> Result<()> {
    let machines = list_managed_machines(client, tenant).await?;
    let grouped = group_machines_by_tenant(machines);

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&grouped).context("serialize tenant list json")?
        );
        return Ok(());
    }

    if wide {
        print_wide(&grouped);
    } else {
        print_summary(&grouped);
    }

    Ok(())
}

pub async fn delete_tenant(
    client: &MachinesClient,
    tenant_id: &str,
    yes: bool,
    wait_timeout: Duration,
) -> Result<()> {
    let machines = list_managed_machines(client, Some(tenant_id)).await?;

    if machines.is_empty() {
        println!("tenant '{}' has no managed machines", tenant_id);
        return Ok(());
    }

    let mut volume_ids: BTreeSet<String> = BTreeSet::new();
    for machine in &machines {
        for volume_id in mounted_volume_ids(machine) {
            volume_ids.insert(volume_id);
        }
    }

    println!("deletion plan for tenant '{}':", tenant_id);
    for machine in &machines {
        println!("- machine {} (state={})", machine.id, machine.state);
    }
    for volume_id in &volume_ids {
        println!("- volume {}", volume_id);
    }

    if !yes {
        return Err(anyhow!("refusing delete without --yes"));
    }

    let mut errors = Vec::new();

    for machine in &machines {
        if let Err(err) = client.cordon_machine(&machine.id, None).await {
            errors.push(format!("cordon {}: {}", machine.id, err));
        }

        if machine.state == "started" {
            if let Err(err) = client.stop_machine(&machine.id).await {
                match classify_machine_action_error(MachineAction::Stop, &err) {
                    MachineActionDisposition::AlreadyApplied => {}
                    MachineActionDisposition::Retryable => {
                        errors.push(format!("stop {} (retryable): {}", machine.id, err))
                    }
                    MachineActionDisposition::Fatal => {
                        errors.push(format!("stop {}: {}", machine.id, err))
                    }
                }
            } else if let Err(err) = client
                .wait_for_state(
                    &machine.id,
                    "stopped",
                    wait_timeout,
                    machine.instance_id.as_deref(),
                )
                .await
            {
                errors.push(format!("wait stopped {}: {}", machine.id, err));
            }
        }

        if let Err(err) = client.delete_machine(&machine.id, true).await {
            match classify_machine_action_error(MachineAction::DeleteMachine, &err) {
                MachineActionDisposition::AlreadyApplied => {}
                MachineActionDisposition::Retryable => errors.push(format!(
                    "delete machine {} (retryable): {}",
                    machine.id, err
                )),
                MachineActionDisposition::Fatal => {
                    errors.push(format!("delete machine {}: {}", machine.id, err))
                }
            }
        }
    }

    for volume_id in &volume_ids {
        if let Err(err) = client.delete_volume(volume_id).await {
            match classify_machine_action_error(MachineAction::DeleteVolume, &err) {
                MachineActionDisposition::AlreadyApplied => {}
                MachineActionDisposition::Retryable => {
                    errors.push(format!("delete volume {} (retryable): {}", volume_id, err))
                }
                MachineActionDisposition::Fatal => {
                    errors.push(format!("delete volume {}: {}", volume_id, err))
                }
            }
        }
    }

    let remaining = list_managed_machines(client, Some(tenant_id)).await?;
    if !remaining.is_empty() {
        errors.push(format!(
            "{} machine(s) still remain for tenant {}",
            remaining.len(),
            tenant_id
        ));
    }

    if !errors.is_empty() {
        return Err(anyhow!(
            "tenant delete completed with errors:\n{}",
            errors.join("\n")
        ));
    }

    println!("tenant '{}' deleted", tenant_id);
    Ok(())
}

pub async fn list_managed_machines(
    client: &MachinesClient,
    tenant_filter: Option<&str>,
) -> Result<Vec<Machine>> {
    let mut query = vec![(
        format!("metadata.{}", MANAGED_BY_KEY),
        MANAGED_BY_VALUE.to_string(),
    )];

    if let Some(tenant) = tenant_filter {
        query.push((format!("metadata.{}", TENANT_ID_KEY), tenant.to_string()));
    }

    let mut machines = client.list_machines(&query).await?;

    machines.retain(|machine| {
        let md = machine.metadata();
        md.get(MANAGED_BY_KEY)
            .map(|value| value == MANAGED_BY_VALUE)
            .unwrap_or(false)
            && md.contains_key(TENANT_ID_KEY)
            && machine.state != "destroyed"
    });

    if let Some(tenant_id) = tenant_filter {
        machines.retain(|machine| {
            machine
                .metadata()
                .get(TENANT_ID_KEY)
                .map(|value| value == tenant_id)
                .unwrap_or(false)
        });
    }

    Ok(machines)
}

#[derive(Debug, Serialize)]
struct TenantSummary {
    tenant_id: String,
    total: usize,
    started: usize,
    stopped: usize,
    other: usize,
    regions: Vec<String>,
    image: String,
    last_updated_at: Option<String>,
    machines: Vec<TenantMachine>,
}

#[derive(Debug, Serialize)]
struct TenantMachine {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    state: String,
    region: Option<String>,
    instance_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    private_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<String>,
    updated_at: Option<String>,
    image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    image_ref: Option<ImageRef>,
    volumes: Vec<String>,
    usage_fact: MachineUsageFact,
    config: Value,
    #[serde(skip_serializing_if = "Value::is_null")]
    checks: Value,
}

fn group_machines_by_tenant(machines: Vec<Machine>) -> Vec<TenantSummary> {
    let mut grouped: BTreeMap<String, Vec<Machine>> = BTreeMap::new();
    for machine in machines {
        if let Some(tenant_id) = machine.metadata().get(TENANT_ID_KEY).cloned() {
            grouped
                .entry(tenant_id.to_string())
                .or_default()
                .push(machine);
        }
    }

    grouped
        .into_iter()
        .map(|(tenant_id, machines)| summarize_tenant(tenant_id, machines))
        .collect()
}

fn summarize_tenant(tenant_id: String, machines: Vec<Machine>) -> TenantSummary {
    let total = machines.len();
    let started = machines
        .iter()
        .filter(|machine| machine.state == "started")
        .count();
    let stopped = machines
        .iter()
        .filter(|machine| machine.state == "stopped")
        .count();
    let other = total.saturating_sub(started + stopped);

    let mut regions = BTreeSet::new();
    let mut images = BTreeSet::new();
    let mut last_updated_at: Option<String> = None;
    let mut machine_rows = Vec::with_capacity(total);

    for machine in machines {
        let usage_fact = machine.usage_fact();
        if let Some(region) = machine.region.clone() {
            regions.insert(region);
        }

        if let Some(updated_at) = machine.updated_at.clone() {
            if last_updated_at
                .as_ref()
                .map(|current| &updated_at > current)
                .unwrap_or(true)
            {
                last_updated_at = Some(updated_at);
            }
        }

        let image = machine
            .image_ref
            .as_ref()
            .and_then(|image_ref| image_ref.digest.clone())
            .or_else(|| config_image(&machine.config));

        if let Some(image) = image.as_ref() {
            images.insert(image.clone());
        }

        let volumes = usage_fact
            .volumes
            .iter()
            .map(|volume| volume.volume_id.clone())
            .collect();
        machine_rows.push(TenantMachine {
            id: machine.id,
            name: machine.name,
            state: machine.state,
            region: machine.region,
            instance_id: machine.instance_id,
            private_ip: machine.private_ip,
            created_at: machine.created_at,
            updated_at: machine.updated_at,
            image,
            image_ref: machine.image_ref,
            volumes,
            usage_fact,
            config: machine.config,
            checks: machine.checks,
        });
    }

    machine_rows.sort_by(|left, right| left.id.cmp(&right.id));

    let image = if images.is_empty() {
        "unknown".to_string()
    } else if images.len() == 1 {
        images.into_iter().next().unwrap_or_default()
    } else {
        format!("drift({})", images.len())
    };

    TenantSummary {
        tenant_id,
        total,
        started,
        stopped,
        other,
        regions: regions.into_iter().collect(),
        image,
        last_updated_at,
        machines: machine_rows,
    }
}

fn print_summary(tenants: &[TenantSummary]) {
    if tenants.is_empty() {
        println!("no managed tenants found");
        return;
    }

    println!(
        "{:<24} {:<12} {:<16} {:<20} {:<26}",
        "TENANT", "MACHINES", "REGIONS", "IMAGE", "LAST UPDATED"
    );
    for tenant in tenants {
        let machines = format!("{}/{}/{}", tenant.total, tenant.started, tenant.stopped);
        let regions = if tenant.regions.is_empty() {
            "-".to_string()
        } else {
            tenant.regions.join(",")
        };
        println!(
            "{:<24} {:<12} {:<16} {:<20} {:<26}",
            tenant.tenant_id,
            machines,
            regions,
            truncate(&tenant.image, 20),
            tenant.last_updated_at.as_deref().unwrap_or("-")
        );
    }
    println!("machines: total/started/stopped");
}

fn print_wide(tenants: &[TenantSummary]) {
    if tenants.is_empty() {
        println!("no managed tenants found");
        return;
    }

    println!(
        "{:<24} {:<18} {:<10} {:<8} {:<22} {:<18}",
        "TENANT", "MACHINE", "STATE", "REGION", "IMAGE", "VOLUMES"
    );
    for tenant in tenants {
        for machine in &tenant.machines {
            let volumes = if machine.volumes.is_empty() {
                "-".to_string()
            } else {
                machine.volumes.join(",")
            };
            println!(
                "{:<24} {:<18} {:<10} {:<8} {:<22} {:<18}",
                tenant.tenant_id,
                machine.id,
                machine.state,
                machine.region.as_deref().unwrap_or("-"),
                truncate(machine.image.as_deref().unwrap_or("-"), 22),
                truncate(&volumes, 18)
            );
        }
    }
}

fn truncate(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_string();
    }

    if width <= 1 {
        return value.chars().take(width).collect();
    }

    let mut out = String::new();
    for c in value.chars().take(width - 1) {
        out.push(c);
    }
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::summarize_tenant;
    use crate::machines::{Machine, DEFAULT_VOLUME_SIZE_GIB};
    use serde_json::json;

    #[test]
    fn tenant_summary_machine_json_includes_usage_fact() {
        let summary = summarize_tenant(
            "tenant-1".to_string(),
            vec![Machine {
                id: "machine-1".to_string(),
                name: Some("worker".to_string()),
                state: "started".to_string(),
                region: Some("sjc".to_string()),
                instance_id: Some("instance-1".to_string()),
                private_ip: Some("fdaa::1".to_string()),
                created_at: Some("2026-04-08T00:00:00Z".to_string()),
                updated_at: Some("2026-04-08T01:00:00Z".to_string()),
                image_ref: None,
                config: json!({
                    "metadata": {
                        "fly_vault.tenant_id": "tenant-1",
                        "fly_vault.managed_by": "fly-vault-admin"
                    },
                    "mounts": [
                        { "volume": "vol-1", "name": "data", "path": "/data", "size_gb": 80 },
                        { "volume": "vol-2", "name": "cache", "path": "/cache" }
                    ]
                }),
                checks: json!({}),
            }],
        );

        assert_eq!(summary.machines.len(), 1);
        let machine = &summary.machines[0];
        assert_eq!(machine.volumes, vec!["vol-1".to_string(), "vol-2".to_string()]);
        assert_eq!(machine.usage_fact.machine_id, "machine-1");
        assert_eq!(machine.usage_fact.state, "started");
        assert_eq!(machine.usage_fact.region.as_deref(), Some("sjc"));
        assert_eq!(machine.usage_fact.volumes.len(), 2);
        assert_eq!(machine.usage_fact.volumes[0].volume_id, "vol-1");
        assert_eq!(machine.usage_fact.volumes[0].size_gib, 80);
        assert_eq!(machine.usage_fact.volumes[1].volume_id, "vol-2");
        assert_eq!(machine.usage_fact.volumes[1].size_gib, DEFAULT_VOLUME_SIZE_GIB);
    }
}

pub async fn wait_for_health(
    client: &MachinesClient,
    machine_id: &str,
    timeout: Duration,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let machine = client
            .get_machine(machine_id)
            .await
            .with_context(|| format!("fetch machine {}", machine_id))?;

        if machine.state != "started" {
            return Err(anyhow!(
                "machine {} left started state during health check: {}",
                machine_id,
                machine.state
            ));
        }

        match checks_are_passing(&machine.checks) {
            None | Some(true) => return Ok(()),
            Some(false) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(anyhow!(
                        "machine {} checks failed to pass before timeout",
                        machine_id
                    ));
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

pub async fn verify_soak_window(
    client: &MachinesClient,
    machine_id: &str,
    soak: Duration,
) -> Result<()> {
    if soak.is_zero() {
        return Ok(());
    }

    let deadline = tokio::time::Instant::now() + soak;
    while tokio::time::Instant::now() < deadline {
        let machine = client
            .get_machine(machine_id)
            .await
            .with_context(|| format!("fetch machine {} during soak", machine_id))?;

        if machine.state != "started" {
            return Err(anyhow!(
                "machine {} crashed during soak window (state={})",
                machine_id,
                machine.state
            ));
        }

        if matches!(checks_are_passing(&machine.checks), Some(false)) {
            return Err(anyhow!(
                "machine {} failed checks during soak window",
                machine_id
            ));
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    Ok(())
}
