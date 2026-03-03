mod machines;
mod rollout;
mod template;
mod tenant;

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use machines::MachinesClient;
use rollout::{update_image, UpdateImageOptions};
use tenant::{create_tenant, delete_tenant, list_tenants};

#[derive(Debug, Parser)]
#[command(name = "fly-vault-admin")]
struct Cli {
    /// Fly Machines API token
    #[arg(long)]
    api_token: Option<String>,

    /// Fly app to manage (tenant machines app)
    #[arg(long)]
    app: Option<String>,

    /// Fly Machines API base URL
    #[arg(long)]
    api_base: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Tenant {
        #[command(subcommand)]
        command: TenantCommand,
    },
}

#[derive(Debug, Subcommand)]
enum TenantCommand {
    Create {
        tenant_id: String,
        #[arg(long)]
        template: PathBuf,
        #[arg(long)]
        provision_token: Option<String>,
        /// Additional template variables: --var key=value
        #[arg(long = "var")]
        vars: Vec<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, default_value_t = 180)]
        wait_timeout_secs: u64,
    },
    Delete {
        tenant_id: String,
        #[arg(long)]
        yes: bool,
        #[arg(long, default_value_t = 180)]
        wait_timeout_secs: u64,
    },
    List {
        #[arg(long)]
        tenant: Option<String>,
        #[arg(long)]
        wide: bool,
        #[arg(long)]
        json: bool,
    },
    UpdateImage {
        #[arg(long)]
        image: String,
        #[arg(long = "tenant")]
        tenants: Vec<String>,
        #[arg(long)]
        all_tenants: bool,
        #[arg(long, default_value_t = 4)]
        concurrency: usize,
        #[arg(long, default_value_t = 1)]
        canary: usize,
        #[arg(long, default_value_t = 20)]
        soak_secs: u64,
        #[arg(long, default_value_t = 180)]
        start_timeout_secs: u64,
        #[arg(long, default_value_t = 120)]
        health_timeout_secs: u64,
        #[arg(long, default_value_t = 120)]
        lease_ttl_secs: u32,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let api_token = cli
        .api_token
        .or_else(|| std::env::var("FLY_API_TOKEN").ok())
        .ok_or_else(|| anyhow!("missing api token (set --api-token or FLY_API_TOKEN)"))?;
    let app = cli
        .app
        .or_else(|| std::env::var("FLY_APP").ok())
        .unwrap_or_else(|| "vault-tenants".to_string());
    let api_base = cli
        .api_base
        .or_else(|| std::env::var("FLY_API_BASE").ok())
        .unwrap_or_else(|| "https://api.machines.dev".to_string());

    let client = MachinesClient::new(api_base, app, api_token);

    match cli.command {
        Command::Tenant { command } => match command {
            TenantCommand::Create {
                tenant_id,
                template,
                provision_token,
                vars,
                dry_run,
                wait_timeout_secs,
            } => {
                let vars = parse_vars(vars)?;
                create_tenant(
                    &client,
                    &tenant_id,
                    &template,
                    provision_token.as_deref(),
                    &vars,
                    dry_run,
                    Duration::from_secs(wait_timeout_secs),
                )
                .await?;
            }
            TenantCommand::Delete {
                tenant_id,
                yes,
                wait_timeout_secs,
            } => {
                delete_tenant(
                    &client,
                    &tenant_id,
                    yes,
                    Duration::from_secs(wait_timeout_secs),
                )
                .await?;
            }
            TenantCommand::List { tenant, wide, json } => {
                list_tenants(&client, tenant.as_deref(), wide, json).await?;
            }
            TenantCommand::UpdateImage {
                image,
                tenants,
                all_tenants,
                concurrency,
                canary,
                soak_secs,
                start_timeout_secs,
                health_timeout_secs,
                lease_ttl_secs,
            } => {
                update_image(
                    &client,
                    UpdateImageOptions {
                        image,
                        tenants,
                        all_tenants,
                        concurrency,
                        canary,
                        soak: Duration::from_secs(soak_secs),
                        start_timeout: Duration::from_secs(start_timeout_secs),
                        health_timeout: Duration::from_secs(health_timeout_secs),
                        lease_ttl_secs,
                    },
                )
                .await?;
            }
        },
    }

    Ok(())
}

fn parse_vars(input: Vec<String>) -> Result<HashMap<String, String>> {
    let mut vars = HashMap::new();
    for item in input {
        let (key, value) = item
            .split_once('=')
            .ok_or_else(|| anyhow!("invalid --var '{}', expected key=value", item))?;

        if key.trim().is_empty() {
            return Err(anyhow!("invalid --var '{}': empty key", item));
        }

        let old = vars.insert(key.trim().to_string(), value.to_string());
        if old.is_some() {
            return Err(anyhow!(
                "duplicate --var key '{}': provided multiple times",
                key
            ));
        }
    }

    Ok(vars)
}
