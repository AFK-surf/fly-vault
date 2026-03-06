use anyhow::{anyhow, Context, Result};
use nix::unistd::Pid;
use protocol::{decode_resize, ConsoleFrame, CONSOLE_DATA, CONSOLE_EXIT, CONSOLE_RESIZE};
use std::future::Future;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::process::Stdio;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::Command;

pub async fn handle_port_forward_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<()> {
    let target = read_target_addr(&mut recv).await?;
    let mut tcp = TcpStream::connect(&target)
        .await
        .with_context(|| format!("connect target {target}"))?;

    let (mut tcp_read, mut tcp_write) = tcp.split();

    let recv_to_tcp = async {
        let mut buf = [0u8; 8192];
        loop {
            let Some(n) = recv.read(&mut buf).await.context("read quic recv")? else {
                break;
            };
            if n == 0 {
                break;
            }
            tcp_write
                .write_all(&buf[..n])
                .await
                .context("write target tcp")?;
        }
        tcp_write
            .shutdown()
            .await
            .context("shutdown target write")?;
        Ok::<(), anyhow::Error>(())
    };

    let tcp_to_send = async {
        let mut buf = [0u8; 8192];
        loop {
            let n = tcp_read.read(&mut buf).await.context("read target tcp")?;
            if n == 0 {
                break;
            }
            send.write_all(&buf[..n]).await.context("write quic send")?;
        }
        send.finish().context("finish quic send")?;
        Ok::<(), anyhow::Error>(())
    };

    tokio::select! {
        r = recv_to_tcp => r?,
        r = tcp_to_send => r?,
    }

    Ok(())
}

pub async fn handle_console_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    root_dir: &Path,
    inner_pid: Pid,
) -> Result<()> {
    let shell = if root_dir.join("bin/bash").exists() {
        "/bin/bash"
    } else {
        "/bin/sh"
    };

    let (master_fd, slave_fd) = open_pty().context("allocate pty pair")?;

    // Spawn shell with the slave side as its controlling terminal.
    // When an inner init is running in PID+mount namespaces, use nsenter to
    // join those namespaces so the console sees the same /proc and mounts.
    let slave_raw = slave_fd.as_raw_fd();
    let mut cmd = Command::new("nsenter");
    cmd.args([
        "-m",
        "-p",
        "-t",
        &inner_pid.as_raw().to_string(),
        &format!("--wd={}", root_dir.display()),
        shell,
        "-l",
    ]);
    unsafe {
        cmd.stdin(Stdio::from_raw_fd(dup_fd(slave_raw)?));
        cmd.stdout(Stdio::from_raw_fd(dup_fd(slave_raw)?));
        cmd.stderr(Stdio::from_raw_fd(dup_fd(slave_raw)?));
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawn nsenter console via pid {}", inner_pid.as_raw()))?;

    // Close slave in parent — the child has its own copies.
    drop(slave_fd);

    // Prepare async I/O on the master side. Keep the master in a narrow scope so
    // any client/PTTY teardown drops it before we wait on the shell again.
    set_nonblocking(&master_fd)?;
    let termination = {
        let master = AsyncFd::new(master_fd).context("wrap pty master in AsyncFd")?;

        let from_pty = async {
            let mut buf = [0u8; 8192];
            loop {
                let n = pty_read(&master, &mut buf).await?;
                if n == 0 {
                    break;
                }
                ConsoleFrame::new(CONSOLE_DATA, buf[..n].to_vec())
                    .write_to(&mut send)
                    .await?;
            }
            Ok::<(), anyhow::Error>(())
        };

        let to_pty = async {
            loop {
                let frame = match ConsoleFrame::read_from(&mut recv).await {
                    Ok(frame) => frame,
                    Err(err) if is_unexpected_eof(&err) => break,
                    Err(err) => return Err(err),
                };
                match frame.ty {
                    CONSOLE_DATA => {
                        pty_write_all(&master, &frame.payload).await?;
                    }
                    CONSOLE_RESIZE => {
                        let (rows, cols) = decode_resize(&frame.payload)?;
                        set_pty_winsize(master.get_ref().as_raw_fd(), rows, cols);
                    }
                    _ => break,
                }
            }
            Ok::<(), anyhow::Error>(())
        };

        wait_for_child_or_console_io(&mut child, from_pty, to_pty).await?
    };

    let status = match termination {
        ConsoleTermination::Shell(status) => status,
        ConsoleTermination::Pty(result) => {
            let status = child.wait().await.context("wait on shell after pty EOF")?;
            result?;
            status
        }
        ConsoleTermination::Client(result) => {
            let status = child
                .wait()
                .await
                .context("wait on shell after client disconnect")?;
            result?;
            status
        }
    };
    let code = status.code().unwrap_or(255) as u32;
    ConsoleFrame::new(CONSOLE_EXIT, code.to_be_bytes().to_vec())
        .write_to(&mut send)
        .await?;
    send.finish().context("finish console stream")?;

    Ok(())
}

// ---------------------------------------------------------------------------
// PTY helpers
// ---------------------------------------------------------------------------

fn open_pty() -> Result<(OwnedFd, OwnedFd)> {
    let mut master: libc::c_int = 0;
    let mut slave: libc::c_int = 0;
    if unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error()).context("openpty");
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) })
}

fn dup_fd(fd: libc::c_int) -> Result<libc::c_int> {
    let new = unsafe { libc::dup(fd) };
    if new < 0 {
        return Err(std::io::Error::last_os_error()).context("dup");
    }
    Ok(new)
}

fn set_nonblocking(fd: &OwnedFd) -> Result<()> {
    let raw = fd.as_raw_fd();
    unsafe {
        let flags = libc::fcntl(raw, libc::F_GETFL);
        if flags < 0 {
            return Err(std::io::Error::last_os_error()).context("fcntl F_GETFL");
        }
        if libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(std::io::Error::last_os_error()).context("fcntl F_SETFL O_NONBLOCK");
        }
    }
    Ok(())
}

async fn pty_read(master: &AsyncFd<OwnedFd>, buf: &mut [u8]) -> Result<usize> {
    loop {
        let mut guard = master.readable().await.context("wait pty readable")?;
        match guard.try_io(|inner| {
            let n = unsafe {
                libc::read(
                    inner.get_ref().as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EIO) {
                    Ok(0)
                } else {
                    Err(err)
                }
            } else {
                Ok(n as usize)
            }
        }) {
            Ok(result) => return result.context("read pty master"),
            Err(_would_block) => continue,
        }
    }
}

async fn pty_write_all(master: &AsyncFd<OwnedFd>, data: &[u8]) -> Result<()> {
    let mut written = 0;
    while written < data.len() {
        let mut guard = master.writable().await.context("wait pty writable")?;
        match guard.try_io(|inner| {
            let n = unsafe {
                libc::write(
                    inner.get_ref().as_raw_fd(),
                    data[written..].as_ptr() as *const libc::c_void,
                    data.len() - written,
                )
            };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }) {
            Ok(Ok(n)) => written += n,
            Ok(Err(e)) => return Err(e).context("write pty master"),
            Err(_would_block) => continue,
        }
    }
    Ok(())
}

enum ConsoleTermination {
    Shell(std::process::ExitStatus),
    Pty(Result<()>),
    Client(Result<()>),
}

async fn wait_for_child_or_console_io<FPty, FClient>(
    child: &mut tokio::process::Child,
    from_pty: FPty,
    to_pty: FClient,
) -> Result<ConsoleTermination>
where
    FPty: Future<Output = Result<()>>,
    FClient: Future<Output = Result<()>>,
{
    tokio::pin!(from_pty);
    tokio::pin!(to_pty);

    tokio::select! {
        status = child.wait() => Ok(ConsoleTermination::Shell(status.context("wait on shell")?)),
        result = &mut from_pty => Ok(ConsoleTermination::Pty(result)),
        result = &mut to_pty => Ok(ConsoleTermination::Client(result)),
    }
}

fn is_unexpected_eof(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::UnexpectedEof)
    })
}

fn set_pty_winsize(fd: libc::c_int, rows: u16, cols: u16) {
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe {
        libc::ioctl(fd, libc::TIOCSWINSZ, &ws);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::process::Command;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn pty_read_treats_hangup_as_eof() -> Result<()> {
        let (master_fd, slave_fd) = open_pty()?;
        drop(slave_fd);

        set_nonblocking(&master_fd)?;
        let master = AsyncFd::new(master_fd).context("wrap pty master")?;
        let mut buf = [0u8; 16];

        let n = timeout(Duration::from_secs(1), pty_read(&master, &mut buf))
            .await
            .context("timed out waiting for pty EOF")??;
        assert_eq!(n, 0);
        Ok(())
    }

    #[tokio::test]
    async fn child_exit_wins_even_if_console_io_never_completes() -> Result<()> {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "(sleep 5) & exit 7"])
            .spawn()
            .context("spawn shell")?;

        let termination = timeout(
            Duration::from_secs(1),
            wait_for_child_or_console_io(
                &mut child,
                std::future::pending::<Result<()>>(),
                std::future::pending::<Result<()>>(),
            ),
        )
        .await
        .context("timed out waiting for child exit")??;

        match termination {
            ConsoleTermination::Shell(status) => assert_eq!(status.code(), Some(7)),
            ConsoleTermination::Pty(_) | ConsoleTermination::Client(_) => {
                panic!("expected shell exit to win")
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Port-forward helpers
// ---------------------------------------------------------------------------

async fn read_target_addr(recv: &mut quinn::RecvStream) -> Result<String> {
    let mut bytes = Vec::with_capacity(128);
    let mut one = [0u8; 1];
    loop {
        let n = recv
            .read(&mut one)
            .await
            .context("read target header byte")?;
        let Some(n) = n else {
            return Err(anyhow!("unexpected EOF while reading target header"));
        };
        if n == 0 {
            continue;
        }
        if one[0] == 0 {
            break;
        }
        bytes.push(one[0]);
        if bytes.len() > 1024 {
            return Err(anyhow!("target address header too long"));
        }
    }

    String::from_utf8(bytes).context("target address not utf-8")
}
