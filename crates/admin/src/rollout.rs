use std::collections::{BTreeMap, HashSet, VecDeque};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::task::JoinSet;

use crate::machines::{
    config_image, with_image, with_metadata, Machine, MachinesClient, UpdateMachineRequest,
};
use crate::tenant::{
    list_managed_machines, verify_soak_window, wait_for_health, MANAGED_BY_KEY, MANAGED_BY_VALUE,
    TENANT_ID_KEY,
};

#[derive(Debug, Clone)]
pub struct UpdateImageOptions {
    pub image: String,
    pub tenants: Vec<String>,
    pub all_tenants: bool,
    pub concurrency: usize,
    pub canary: usize,
    pub soak: Duration,
    pub start_timeout: Duration,
    pub health_timeout: Duration,
    pub lease_ttl_secs: u32,
}

#[derive(Debug, Clone)]
struct MachineSnapshot {
    machine_id: String,
    tenant_id: String,
    name: Option<String>,
    region: Option<String>,
    metadata: std::collections::HashMap<String, String>,
    config: serde_json::Value,
    current_version: String,
    previous_image: String,
}

pub async fn update_image(client: &MachinesClient, options: UpdateImageOptions) -> Result<()> {
    validate_selectors(&options)?;
    if options.concurrency == 0 {
        return Err(anyhow!("--concurrency must be >= 1"));
    }

    let mut machines = list_managed_machines(client, None).await?;
    if !options.all_tenants {
        let target_tenants: HashSet<String> = options.tenants.iter().cloned().collect();
        machines.retain(|machine| {
            machine
                .metadata()
                .get(TENANT_ID_KEY)
                .map(|tenant| target_tenants.contains(tenant.as_str()))
                .unwrap_or(false)
        });
    }

    if machines.is_empty() {
        return Err(anyhow!("no target machines selected"));
    }

    let mut targets = Vec::with_capacity(machines.len());
    for machine in machines {
        targets.push(snapshot_from_machine(machine)?);
    }

    targets.sort_by(|left, right| {
        left.tenant_id
            .cmp(&right.tenant_id)
            .then_with(|| left.machine_id.cmp(&right.machine_id))
    });

    let canary_count = options.canary.min(targets.len());
    let canary_indices = select_canary_indices(&targets, canary_count);
    let canary_index_set: HashSet<usize> = canary_indices.iter().copied().collect();

    let mut canaries = Vec::with_capacity(canary_indices.len());
    let mut remaining = Vec::new();
    for (idx, snapshot) in targets.into_iter().enumerate() {
        if canary_index_set.contains(&idx) {
            canaries.push(snapshot);
        } else {
            remaining.push(snapshot);
        }
    }

    let mut updated = Vec::new();

    println!(
        "starting canary stage ({} of {} machines)",
        canaries.len(),
        canaries.len() + remaining.len()
    );

    for snapshot in &canaries {
        println!(
            "  canary {}/{}: {} (tenant {})",
            updated.len() + 1,
            canaries.len(),
            snapshot.machine_id,
            snapshot.tenant_id
        );

        if let Err(err) = update_one_machine(client, snapshot, &options.image, &options).await {
            rollback(client, &updated, &options).await;
            return Err(err.context("canary stage failed"));
        }
        updated.push(snapshot.clone());
    }

    println!("canary stage passed");

    if remaining.is_empty() {
        println!("image update completed for {} machine(s)", updated.len());
        return Ok(());
    }

    println!(
        "starting rolling update for {} remaining machine(s) (concurrency={})",
        remaining.len(),
        options.concurrency
    );

    let mut queue_by_tenant: BTreeMap<String, VecDeque<MachineSnapshot>> = BTreeMap::new();
    for snapshot in remaining {
        queue_by_tenant
            .entry(snapshot.tenant_id.clone())
            .or_default()
            .push_back(snapshot);
    }

    while queue_by_tenant.values().any(|queue| !queue.is_empty()) {
        let mut batch = Vec::new();
        for queue in queue_by_tenant.values_mut() {
            if batch.len() >= options.concurrency {
                break;
            }
            if let Some(snapshot) = queue.pop_front() {
                batch.push(snapshot);
            }
        }

        if batch.is_empty() {
            break;
        }

        let mut join_set = JoinSet::new();
        for snapshot in batch {
            let snapshot_for_task = snapshot.clone();
            let client_for_task = client.clone();
            let image = options.image.clone();
            let task_opts = options.clone();

            join_set.spawn(async move {
                update_one_machine(&client_for_task, &snapshot_for_task, &image, &task_opts)
                    .await
                    .map(|_| snapshot_for_task)
            });
        }

        let mut batch_errors = Vec::new();
        while let Some(joined) = join_set.join_next().await {
            match joined {
                Ok(Ok(snapshot)) => updated.push(snapshot),
                Ok(Err(err)) => batch_errors.push(err),
                Err(err) => batch_errors.push(anyhow!("rollout task join error: {}", err)),
            }
        }

        if !batch_errors.is_empty() {
            rollback(client, &updated, &options).await;
            return Err(anyhow!(
                "rolling stage failed:\n{}",
                batch_errors
                    .into_iter()
                    .map(|err| format!("- {}", err))
                    .collect::<Vec<_>>()
                    .join("\n")
            ));
        }
    }

    println!("image update completed for {} machine(s)", updated.len());
    Ok(())
}

fn validate_selectors(options: &UpdateImageOptions) -> Result<()> {
    if options.all_tenants && !options.tenants.is_empty() {
        return Err(anyhow!(
            "use either --all-tenants or --tenant <id>..., not both"
        ));
    }

    if !options.all_tenants && options.tenants.is_empty() {
        return Err(anyhow!(
            "select tenants with --tenant <id>... or use --all-tenants"
        ));
    }

    Ok(())
}

fn snapshot_from_machine(machine: Machine) -> Result<MachineSnapshot> {
    let metadata = machine.metadata();

    let tenant_id = metadata
        .get(TENANT_ID_KEY)
        .cloned()
        .ok_or_else(|| anyhow!("machine {} missing {} metadata", machine.id, TENANT_ID_KEY))?;

    let managed_by = metadata
        .get(MANAGED_BY_KEY)
        .map(String::as_str)
        .unwrap_or("");
    if managed_by != MANAGED_BY_VALUE {
        return Err(anyhow!(
            "machine {} not managed by fly-vault-admin",
            machine.id
        ));
    }

    let current_version = machine
        .instance_id
        .clone()
        .ok_or_else(|| anyhow!("machine {} missing instance_id", machine.id))?;

    let previous_image = config_image(&machine.config)
        .ok_or_else(|| anyhow!("machine {} config.image missing", machine.id))?;

    Ok(MachineSnapshot {
        machine_id: machine.id,
        tenant_id,
        name: machine.name,
        region: machine.region,
        metadata,
        config: machine.config,
        current_version,
        previous_image,
    })
}

fn select_canary_indices(targets: &[MachineSnapshot], count: usize) -> Vec<usize> {
    if count == 0 || targets.is_empty() {
        return Vec::new();
    }

    let mut picked = Vec::new();
    let mut seen_tenants = HashSet::new();

    for (idx, snapshot) in targets.iter().enumerate() {
        if seen_tenants.insert(snapshot.tenant_id.clone()) {
            picked.push(idx);
            if picked.len() == count {
                return picked;
            }
        }
    }

    for idx in 0..targets.len() {
        if picked.len() == count {
            break;
        }
        if !picked.contains(&idx) {
            picked.push(idx);
        }
    }

    picked
}

async fn update_one_machine(
    client: &MachinesClient,
    snapshot: &MachineSnapshot,
    image: &str,
    options: &UpdateImageOptions,
) -> Result<()> {
    let lease = client
        .create_lease(&snapshot.machine_id, options.lease_ttl_secs)
        .await
        .with_context(|| format!("lease machine {}", snapshot.machine_id))?;

    let mut operation_result = async {
        client
            .cordon_machine(&snapshot.machine_id, Some(&lease.nonce))
            .await
            .with_context(|| format!("cordon machine {}", snapshot.machine_id))?;

        let config = with_image(&snapshot.config, image)
            .with_context(|| format!("set image for machine {}", snapshot.machine_id))?;
        let config = with_metadata(&config, snapshot.metadata.clone())
            .with_context(|| format!("set metadata for machine {}", snapshot.machine_id))?;
        let request = UpdateMachineRequest {
            name: snapshot.name.clone(),
            region: snapshot.region.clone(),
            config,
            current_version: Some(snapshot.current_version.clone()),
        };

        client
            .update_machine(&snapshot.machine_id, &request, Some(&lease.nonce))
            .await
            .with_context(|| format!("update image for machine {}", snapshot.machine_id))?;

        client
            .wait_for_state(&snapshot.machine_id, "started", options.start_timeout, None)
            .await
            .with_context(|| format!("wait started for machine {}", snapshot.machine_id))?;

        wait_for_health(client, &snapshot.machine_id, options.health_timeout)
            .await
            .with_context(|| format!("health checks for machine {}", snapshot.machine_id))?;

        verify_soak_window(client, &snapshot.machine_id, options.soak)
            .await
            .with_context(|| format!("soak window for machine {}", snapshot.machine_id))?;

        client
            .uncordon_machine(&snapshot.machine_id, Some(&lease.nonce))
            .await
            .with_context(|| format!("uncordon machine {}", snapshot.machine_id))?;

        Result::<()>::Ok(())
    }
    .await;

    if operation_result.is_err() {
        let _ = client
            .uncordon_machine(&snapshot.machine_id, Some(&lease.nonce))
            .await;
    }

    let release_result = client
        .release_lease(&snapshot.machine_id, &lease.nonce)
        .await
        .with_context(|| format!("release lease for machine {}", snapshot.machine_id));

    if let Err(err) = release_result {
        if operation_result.is_ok() {
            operation_result = Err(err);
        } else {
            eprintln!("warning: {}", err);
        }
    }

    operation_result
}

async fn rollback(
    client: &MachinesClient,
    updated: &[MachineSnapshot],
    options: &UpdateImageOptions,
) {
    if updated.is_empty() {
        return;
    }

    eprintln!(
        "rollout failed, starting rollback for {} machine(s)",
        updated.len()
    );

    for snapshot in updated.iter().rev() {
        match rollback_one_machine(client, snapshot, options).await {
            Ok(()) => eprintln!("rolled back {}", snapshot.machine_id),
            Err(err) => eprintln!("rollback failed for {}: {}", snapshot.machine_id, err),
        }
    }
}

async fn rollback_one_machine(
    client: &MachinesClient,
    snapshot: &MachineSnapshot,
    options: &UpdateImageOptions,
) -> Result<()> {
    let current = client
        .get_machine(&snapshot.machine_id)
        .await
        .with_context(|| format!("fetch machine {} for rollback", snapshot.machine_id))?;

    let current_version = Some(current.instance_id.clone().ok_or_else(|| {
        anyhow!(
            "machine {} missing instance_id for rollback",
            snapshot.machine_id
        )
    })?);

    let lease = client
        .create_lease(&snapshot.machine_id, options.lease_ttl_secs)
        .await
        .with_context(|| format!("lease machine {} for rollback", snapshot.machine_id))?;

    let mut operation_result = async {
        client
            .cordon_machine(&snapshot.machine_id, Some(&lease.nonce))
            .await
            .with_context(|| format!("cordon machine {}", snapshot.machine_id))?;

        let config = with_image(&current.config, &snapshot.previous_image)
            .with_context(|| format!("set rollback image for machine {}", snapshot.machine_id))?;
        let config = with_metadata(&config, current.metadata())
            .with_context(|| format!("set metadata for machine {}", snapshot.machine_id))?;
        let request = UpdateMachineRequest {
            name: current.name,
            region: current.region,
            config,
            current_version,
        };

        client
            .update_machine(&snapshot.machine_id, &request, Some(&lease.nonce))
            .await
            .with_context(|| format!("rollback update for machine {}", snapshot.machine_id))?;

        client
            .wait_for_state(&snapshot.machine_id, "started", options.start_timeout, None)
            .await
            .with_context(|| format!("wait started for machine {}", snapshot.machine_id))?;

        wait_for_health(client, &snapshot.machine_id, options.health_timeout)
            .await
            .with_context(|| format!("health checks for machine {}", snapshot.machine_id))?;

        verify_soak_window(client, &snapshot.machine_id, options.soak)
            .await
            .with_context(|| format!("soak window for machine {}", snapshot.machine_id))?;

        client
            .uncordon_machine(&snapshot.machine_id, Some(&lease.nonce))
            .await
            .with_context(|| format!("uncordon machine {}", snapshot.machine_id))?;

        Result::<()>::Ok(())
    }
    .await;

    if operation_result.is_err() {
        let _ = client
            .uncordon_machine(&snapshot.machine_id, Some(&lease.nonce))
            .await;
    }

    let release_result = client
        .release_lease(&snapshot.machine_id, &lease.nonce)
        .await
        .with_context(|| format!("release lease for machine {}", snapshot.machine_id));

    if let Err(err) = release_result {
        if operation_result.is_ok() {
            operation_result = Err(err);
        } else {
            eprintln!("warning: {}", err);
        }
    }

    operation_result
}
