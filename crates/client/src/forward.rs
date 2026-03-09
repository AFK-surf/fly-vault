use anyhow::{anyhow, Context, Result};
use protocol::STREAM_PORT_FORWARD;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub async fn run_local_forwarders(conn: quinn::Connection, specs: Vec<String>) -> Result<()> {
    if specs.is_empty() {
        tokio::signal::ctrl_c().await.context("wait for ctrl-c")?;
        return Ok(());
    }

    let mut tasks = Vec::new();
    for spec in specs {
        let (local_port, target) = parse_forward(&spec)?;
        let listener = TcpListener::bind(("127.0.0.1", local_port))
            .await
            .with_context(|| format!("bind local port {local_port}"))?;
        let conn = conn.clone();

        tasks.push(tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await?;
                let conn = conn.clone();
                let target = target.clone();
                tokio::spawn(async move {
                    if let Err(err) = bridge_one(conn, socket, target).await {
                        eprintln!("forward error: {err:#}");
                    }
                });
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        }));
    }

    tokio::signal::ctrl_c().await.context("wait for ctrl-c")?;
    for t in tasks {
        t.abort();
    }

    Ok(())
}

pub(crate) async fn bridge_one(
    conn: quinn::Connection,
    local: TcpStream,
    target: String,
) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await.context("open forward stream")?;
    send.write_u8(STREAM_PORT_FORWARD)
        .await
        .context("write stream tag")?;
    send.write_all(target.as_bytes())
        .await
        .context("write forward target")?;
    send.write_u8(0).await.context("write target terminator")?;

    let (mut local_read, mut local_write) = local.into_split();

    let to_remote = async {
        let mut buf = [0u8; 8192];
        loop {
            let n = local_read.read(&mut buf).await.context("read local tcp")?;
            if n == 0 {
                break;
            }
            send.write_all(&buf[..n]).await.context("write quic data")?;
        }
        send.finish().context("finish forward send")?;
        Ok::<(), anyhow::Error>(())
    };

    let from_remote = async {
        let mut buf = [0u8; 8192];
        loop {
            let n = recv.read(&mut buf).await.context("read quic data")?;
            let Some(n) = n else { break };
            if n == 0 {
                break;
            }
            local_write
                .write_all(&buf[..n])
                .await
                .context("write local tcp")?;
        }
        local_write
            .shutdown()
            .await
            .context("shutdown local write")?;
        Ok::<(), anyhow::Error>(())
    };

    tokio::select! {
        r = to_remote => r?,
        r = from_remote => r?,
    }

    Ok(())
}

pub(crate) fn parse_forward(spec: &str) -> Result<(u16, String)> {
    let parts: Vec<&str> = spec.split(':').collect();
    if parts.len() != 3 {
        return Err(anyhow!(
            "invalid --forward spec {spec}; expected <local_port>:<target_host>:<target_port>"
        ));
    }

    let local_port: u16 = parts[0]
        .parse()
        .with_context(|| format!("invalid local port in {spec}"))?;
    let target_port: u16 = parts[2]
        .parse()
        .with_context(|| format!("invalid target port in {spec}"))?;
    let target = format!("{}:{}", parts[1], target_port);

    Ok((local_port, target))
}
