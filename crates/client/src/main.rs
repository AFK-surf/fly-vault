mod attest;
mod console;
mod forward;
mod proxy_udp;
mod quic;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "fly-vault")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Connect {
        vault: String,
        #[arg(long = "forward")]
        forward: Vec<String>,
        /// Re-provision the vault with a new rootfs while in ready state.
        #[arg(long)]
        reprovision: bool,
    },
    Build,
}

#[derive(Debug, Deserialize, Serialize)]
struct ConfigFile {
    #[serde(default)]
    vault: HashMap<String, VaultConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct VaultConfig {
    address: String,
    org: String,
    app: String,
    machine_id: Option<String>,
    #[serde(default)]
    forward: Vec<String>,
    rootfs: Option<String>,
    rootfs_url: Option<String>,
    access_token: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Connect {
            vault,
            forward,
            reprovision,
        } => {
            let (config_path, mut cfg_file) = load_config_file()?;
            let vault_cfg = cfg_file
                .vault
                .remove(&vault)
                .ok_or_else(|| anyhow!("vault {vault} not found in {}", config_path.display()))?;

            let forwards = if forward.is_empty() {
                vault_cfg.forward.clone()
            } else {
                forward
            };

            quic::connect_and_run(vault, vault_cfg, forwards, reprovision).await?;
        }
        Command::Build => {
            run_build_commands()?;
        }
    }

    Ok(())
}

fn run_build_commands() -> Result<()> {
    use std::process::Command;

    let status = Command::new("cargo")
        .arg("build")
        .arg("--release")
        .arg("--target")
        .arg("x86_64-unknown-linux-musl")
        .arg("-p")
        .arg("init")
        .status()
        .context("run cargo build for init")?;

    if !status.success() {
        return Err(anyhow!("cargo build failed"));
    }

    println!("init binary built at target/x86_64-unknown-linux-musl/release/init");
    Ok(())
}

fn load_config_file() -> Result<(PathBuf, ConfigFile)> {
    let path = config_path()?;
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("read config file {}", path.display()))?;
    let cfg: ConfigFile = toml::from_str(&raw).context("parse config toml")?;
    Ok((path, cfg))
}

fn config_path() -> Result<PathBuf> {
    let base = dirs::config_dir().ok_or_else(|| anyhow!("unable to determine config directory"))?;
    Ok(base.join("fly-vault").join("config.toml"))
}

#[cfg(test)]
mod tests {
    use super::VaultConfig;

    #[test]
    fn vault_config_deserializes_with_machine_id() {
        let raw = r#"
address = "proxy.fly.dev:8443"
org = "my-org"
app = "my-app"
machine_id = "abc123"
"#;
        let cfg: VaultConfig = toml::from_str(raw).expect("parse config with machine_id");
        assert_eq!(cfg.machine_id.as_deref(), Some("abc123"));
    }

    #[test]
    fn vault_config_deserializes_without_machine_id() {
        let raw = r#"
address = "my-app.fly.dev:8443"
org = "my-org"
app = "my-app"
"#;
        let cfg: VaultConfig = toml::from_str(raw).expect("parse config without machine_id");
        assert!(cfg.machine_id.is_none());
    }
}
