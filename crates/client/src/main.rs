mod attest;
mod cache;
mod console;
mod control;
mod forward;
mod proxy_udp;
mod quic;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::fs::File;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "fly-vault")]
struct Cli {
    #[arg(long, global = true, env = "FLY_VAULT_LOG_FILE")]
    log_file: Option<PathBuf>,
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
        /// Expose a local HTTP control API on a Unix socket at this path.
        #[arg(long = "control-socket")]
        control_socket: Option<PathBuf>,
    },
    Exec {
        vault: String,
        #[arg(long)]
        session: Option<String>,
        #[arg(long)]
        context: Option<String>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<OsString>,
    },
    ListExec {
        vault: String,
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum TransportConfig {
    Direct,
    Proxy { machine_id: String },
}

impl VaultConfig {
    fn transport(&self) -> TransportConfig {
        match &self.machine_id {
            Some(machine_id) => TransportConfig::Proxy {
                machine_id: machine_id.clone(),
            },
            None => TransportConfig::Direct,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cli = Cli::parse();
    init_logging(cli.log_file.as_ref())?;

    match cli.command {
        Command::Connect {
            vault,
            forward,
            reprovision,
            control_socket,
        } => {
            let (_, mut cfg_file) = load_config_file()?;
            let vault_cfg = resolve_vault_config(&mut cfg_file, &vault)?;

            let forwards = if forward.is_empty() {
                vault_cfg.forward.clone()
            } else {
                forward
            };

            quic::connect_and_run(vault_cfg, forwards, reprovision, control_socket).await?;
        }
        Command::Exec {
            vault,
            session,
            context,
            command,
        } => {
            let (_, mut cfg_file) = load_config_file()?;
            let vault_cfg = resolve_vault_config(&mut cfg_file, &vault)?;
            let command = command
                .into_iter()
                .map(|arg| {
                    arg.into_string()
                        .map_err(|arg| anyhow!("exec arguments must be valid UTF-8: {:?}", arg))
                })
                .collect::<Result<Vec<_>>>()?;
            if session.is_none() && command.is_empty() {
                return Err(anyhow!(
                    "exec requires a command unless --session is provided"
                ));
            }
            let exit_code = quic::connect_and_exec(vault_cfg, session, context, command).await?;
            if exit_code != 0 {
                std::process::exit((exit_code & 0xff) as i32);
            }
        }
        Command::ListExec { vault } => {
            let (_, mut cfg_file) = load_config_file()?;
            let vault_cfg = resolve_vault_config(&mut cfg_file, &vault)?;
            let sessions = quic::list_exec_sessions(vault_cfg).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&sessions).context("serialize exec sessions")?
            );
        }
        Command::Build => {
            run_build_commands()?;
        }
    }

    Ok(())
}

fn init_logging(log_file: Option<&PathBuf>) -> Result<()> {
    let Some(log_file) = log_file else {
        return Ok(());
    };

    if let Some(parent) = log_file
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("create log directory {}", parent.display()))?;
    }

    let file =
        File::create(log_file).with_context(|| format!("open log file {}", log_file.display()))?;
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .json()
        .with_ansi(false)
        .with_env_filter(filter)
        .with_writer(move || {
            file.try_clone()
                .expect("clone log file handle for tracing output")
        })
        .init();

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

fn resolve_vault_config(cfg_file: &mut ConfigFile, vault: &str) -> Result<VaultConfig> {
    cfg_file.vault.remove(vault).ok_or_else(|| {
        anyhow!(
            "vault {vault} not found in {}",
            config_path()
                .unwrap_or_else(|_| PathBuf::from("<unknown-config>"))
                .display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::{resolve_vault_config, Cli, Command, ConfigFile, TransportConfig, VaultConfig};
    use clap::Parser;
    use std::collections::HashMap;
    use std::path::PathBuf;

    #[test]
    fn vault_config_deserializes_with_machine_id() {
        let raw = r#"
address = "proxy.fly.dev:8443"
org = "my-org"
app = "my-app"
machine_id = "abc123"
"#;
        let cfg: VaultConfig = toml::from_str(raw).expect("parse config with machine_id");
        assert_eq!(
            cfg.transport(),
            TransportConfig::Proxy {
                machine_id: "abc123".to_string()
            }
        );
    }

    #[test]
    fn vault_config_deserializes_without_machine_id() {
        let raw = r#"
address = "my-app.fly.dev:8443"
org = "my-org"
app = "my-app"
"#;
        let cfg: VaultConfig = toml::from_str(raw).expect("parse config without machine_id");
        assert_eq!(cfg.transport(), TransportConfig::Direct);
    }

    #[test]
    fn resolve_vault_config_finds_named_entry() {
        let mut cfg = ConfigFile {
            vault: HashMap::from([(
                "my-dev".to_string(),
                VaultConfig {
                    address: "proxy.fly.dev:8443".to_string(),
                    org: "org".to_string(),
                    app: "app".to_string(),
                    machine_id: None,
                    forward: Vec::new(),
                    rootfs: None,
                    rootfs_url: None,
                    access_token: None,
                },
            )]),
        };

        let resolved = resolve_vault_config(&mut cfg, "my-dev").expect("resolve named vault");
        assert_eq!(resolved.app, "app");
    }

    #[test]
    fn resolve_vault_config_reports_missing_name() {
        let vault_cfg = VaultConfig {
            address: "proxy.fly.dev:8443".to_string(),
            org: "org".to_string(),
            app: "app".to_string(),
            machine_id: None,
            forward: Vec::new(),
            rootfs: None,
            rootfs_url: None,
            access_token: None,
        };
        let mut cfg = ConfigFile {
            vault: HashMap::from([
                ("one".to_string(), vault_cfg.clone()),
                ("two".to_string(), vault_cfg),
            ]),
        };

        let err = resolve_vault_config(&mut cfg, "missing").expect_err("expected missing vault");
        assert!(err.to_string().contains("vault missing not found"));
    }

    #[test]
    fn exec_command_parses_vault_and_trailing_command() {
        let cli = Cli::try_parse_from(["fly-vault", "exec", "my-dev", "--", "ls", "-lash", "/"])
            .expect("parse exec command");

        match cli.command {
            Command::Exec {
                vault,
                session,
                context,
                command,
            } => {
                assert_eq!(vault, "my-dev");
                assert_eq!(session, None);
                assert_eq!(context, None);
                let command = command
                    .into_iter()
                    .map(|arg| arg.into_string().unwrap())
                    .collect::<Vec<_>>();
                assert_eq!(command, vec!["ls", "-lash", "/"]);
            }
            other => panic!("expected exec command, got {other:?}"),
        }
    }

    #[test]
    fn exec_command_parses_optional_session() {
        let cli = Cli::try_parse_from(["fly-vault", "exec", "my-dev", "--session", "sess-1"])
            .expect("parse exec command with session");

        match cli.command {
            Command::Exec {
                vault,
                session,
                context,
                command,
            } => {
                assert_eq!(vault, "my-dev");
                assert_eq!(session.as_deref(), Some("sess-1"));
                assert_eq!(context, None);
                assert!(command.is_empty());
            }
            other => panic!("expected exec command, got {other:?}"),
        }
    }

    #[test]
    fn exec_command_parses_optional_context() {
        let cli = Cli::try_parse_from([
            "fly-vault",
            "exec",
            "my-dev",
            "--context",
            "investigate deploy failure",
            "--",
            "sh",
        ])
        .expect("parse exec command with context");

        match cli.command {
            Command::Exec {
                vault,
                session,
                context,
                command,
            } => {
                assert_eq!(vault, "my-dev");
                assert_eq!(session, None);
                assert_eq!(context.as_deref(), Some("investigate deploy failure"));
                let command = command
                    .into_iter()
                    .map(|arg| arg.into_string().unwrap())
                    .collect::<Vec<_>>();
                assert_eq!(command, vec!["sh"]);
            }
            other => panic!("expected exec command, got {other:?}"),
        }
    }

    #[test]
    fn global_log_file_parses_after_subcommand() {
        let cli = Cli::try_parse_from([
            "fly-vault",
            "exec",
            "--log-file",
            "/tmp/fly-vault.log",
            "my-dev",
            "--",
            "true",
        ])
        .expect("parse exec command with global log file");

        assert_eq!(cli.log_file, Some(PathBuf::from("/tmp/fly-vault.log")));
        match cli.command {
            Command::Exec { vault, command, .. } => {
                assert_eq!(vault, "my-dev");
                let command = command
                    .into_iter()
                    .map(|arg| arg.into_string().unwrap())
                    .collect::<Vec<_>>();
                assert_eq!(command, vec!["true"]);
            }
            other => panic!("expected exec command, got {other:?}"),
        }
    }
}
