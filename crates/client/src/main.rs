mod attest;
mod config_verify;
mod console;
mod forward;
mod proxy_udp;
mod quic;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use crypto::{XtsKey, XTS_KEY_SIZE};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::info;

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
        /// Re-provision the vault with a new rootfs while in locked state
        #[arg(long)]
        reprovision: bool,
    },
    Keygen {
        vault: String,
    },
    Allow {
        vault: String,
        digest: String,
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
    fly_api_token: Option<String>,
    #[serde(default)]
    allowed_digests: Vec<String>,
    #[serde(default)]
    forward: Vec<String>,
    rootfs: Option<String>,
    rootfs_url: Option<String>,
    provision_token: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

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

            let key = load_or_create_key(&vault)?;
            let forwards = if forward.is_empty() {
                vault_cfg.forward.clone()
            } else {
                forward
            };

            quic::connect_and_run(vault, vault_cfg, key, forwards, reprovision).await?;
        }
        Command::Keygen { vault } => {
            let path = key_path(&vault)?;
            if path.exists() {
                return Err(anyhow!("key already exists at {}", path.display()));
            }
            let _ = generate_key_file(&path)?;
            info!(path = %path.display(), "key generated");
        }
        Command::Allow { vault, digest } => {
            let (config_path, mut cfg) = load_config_file()?;
            let vault_cfg = cfg
                .vault
                .get_mut(&vault)
                .ok_or_else(|| anyhow!("vault {vault} not found in {}", config_path.display()))?;
            if !vault_cfg.allowed_digests.contains(&digest) {
                vault_cfg.allowed_digests.push(digest);
            }
            let doc = toml::to_string_pretty(&cfg).context("serialize config toml")?;
            fs::write(&config_path, doc)
                .with_context(|| format!("write {}", config_path.display()))?;
            info!(path = %config_path.display(), "allowlist updated");
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

fn keys_dir() -> Result<PathBuf> {
    let base = dirs::config_dir().ok_or_else(|| anyhow!("unable to determine config directory"))?;
    Ok(base.join("fly-vault").join("keys"))
}

fn key_path(vault: &str) -> Result<PathBuf> {
    Ok(keys_dir()?.join(format!("{vault}.key")))
}

fn load_or_create_key(vault: &str) -> Result<XtsKey> {
    let path = key_path(vault)?;
    if path.exists() {
        return load_key_file(&path);
    }

    let key = generate_key_file(&path)?;
    Ok(key)
}

fn load_key_file(path: &Path) -> Result<XtsKey> {
    let bytes = fs::read(path).with_context(|| format!("read key {}", path.display()))?;
    if bytes.len() != XTS_KEY_SIZE {
        return Err(anyhow!(
            "invalid key size in {}: got {}, expected {}",
            path.display(),
            bytes.len(),
            XTS_KEY_SIZE
        ));
    }
    XtsKey::from_slice(&bytes)
}

fn generate_key_file(path: &Path) -> Result<XtsKey> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create key dir {}", parent.display()))?;
    }

    let mut bytes = [0u8; XTS_KEY_SIZE];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut bytes);

    fs::write(path, bytes).with_context(|| format!("write key {}", path.display()))?;
    set_0600(path)?;

    XtsKey::from_slice(&bytes)
}

#[cfg(unix)]
fn set_0600(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o600);
    fs::set_permissions(path, perms).with_context(|| format!("set 0600 on {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_0600(_path: &Path) -> Result<()> {
    Ok(())
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
