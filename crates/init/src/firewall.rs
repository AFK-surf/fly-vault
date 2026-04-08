use anyhow::{Context, Result};
use std::io::Write;
use std::process::Command;
use tracing::info;

/// Set up nftables to drop all ingress traffic by default,
/// allowing only the QUIC listener port and established connections.
pub fn setup(listen_port: u16) -> Result<()> {
    let ruleset = format!(
        r#"
table inet filter {{
    chain input {{
        type filter hook input priority 0; policy accept;
        iif lo accept
        ct state established,related counter accept
        icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert }} counter accept
        udp dport {listen_port} counter accept
        tcp dport 22 counter accept
        counter drop
    }}
    chain forward {{
        type filter hook forward priority 0; policy drop;
    }}
    chain output {{
        type filter hook output priority 0; policy accept;
    }}
}}
"#
    );

    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("spawn nft")?;

    child
        .stdin
        .take()
        .context("open stdin pipe")
        .and_then(|mut stdin| {
            stdin
                .write_all(ruleset.as_bytes())
                .context("write ruleset")?;
            Ok(())
        })?;

    let output = child.wait_with_output().context("wait for nft")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("nft failed ({}): {stderr}", output.status);
    }

    info!(listen_port, "nftables: ingress drop policy applied");
    Ok(())
}
