use anyhow::{Context, Result};
use protocol::{
    decode_exit, encode_exec_argv, encode_resize, ConsoleFrame, CONSOLE_DATA, CONSOLE_EXEC,
    CONSOLE_EXIT, CONSOLE_RESIZE, CONSOLE_SHELL, STREAM_CONSOLE,
};
use std::io::{IsTerminal, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use tokio::io::unix::AsyncFd;
use tokio::io::AsyncWriteExt;

pub async fn run_console(conn: quinn::Connection) -> Result<()> {
    let exit_code = run_session(conn, ConsoleFrame::new(CONSOLE_SHELL, vec![])).await?;
    eprintln!("\r\nremote shell exited with {exit_code}");
    Ok(())
}

pub async fn run_exec(conn: quinn::Connection, argv: Vec<String>) -> Result<u32> {
    run_session(
        conn,
        ConsoleFrame::new(
            CONSOLE_EXEC,
            encode_exec_argv(&wrap_exec_with_term(argv, current_term_for_exec())),
        ),
    )
    .await
}

async fn run_session(conn: quinn::Connection, startup: ConsoleFrame) -> Result<u32> {
    let (mut send, mut recv) = conn.open_bi().await.context("open console stream")?;
    send.write_u8(STREAM_CONSOLE)
        .await
        .context("write console stream tag")?;
    startup.write_to(&mut send).await?;

    let is_tty = std::io::stdin().is_terminal();
    let _raw_guard = if is_tty {
        let guard = RawModeGuard::enable().context("enable raw mode")?;
        if let Some((rows, cols)) = terminal_size() {
            ConsoleFrame::new(CONSOLE_RESIZE, encode_resize(rows, cols).to_vec())
                .write_to(&mut send)
                .await?;
        }
        Some(guard)
    } else {
        None
    };

    let (frame_tx, mut frame_rx) = tokio::sync::mpsc::channel::<ConsoleFrame>(64);

    let stdin_task = spawn_stdin_task(is_tty, frame_tx.clone());

    let resize_task = tokio::spawn({
        let tx = frame_tx;
        async move {
            if !is_tty {
                return Ok::<(), anyhow::Error>(());
            }
            let Ok(mut sig) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
            else {
                return Ok(());
            };
            loop {
                sig.recv().await;
                if let Some((rows, cols)) = terminal_size() {
                    let _ = tx
                        .send(ConsoleFrame::new(
                            CONSOLE_RESIZE,
                            encode_resize(rows, cols).to_vec(),
                        ))
                        .await;
                }
            }
        }
    });

    let send_task = tokio::spawn(async move {
        while let Some(frame) = frame_rx.recv().await {
            frame.write_to(&mut send).await?;
        }
        send.finish().context("finish console send")?;
        Ok::<(), anyhow::Error>(())
    });

    let exit_result: Result<u32> = async {
        let mut stdout = tokio::io::stdout();
        loop {
            let frame = ConsoleFrame::read_from(&mut recv).await?;
            match frame.ty {
                CONSOLE_DATA => {
                    stdout
                        .write_all(&frame.payload)
                        .await
                        .context("write stdout")?;
                    stdout.flush().await.context("flush stdout")?;
                }
                CONSOLE_EXIT => {
                    return decode_exit(&frame.payload);
                }
                _ => {}
            }
        }
    }
    .await;

    stdin_task.abort();
    resize_task.abort();

    match stdin_task.await {
        Ok(result) => result?,
        Err(err) if err.is_cancelled() => {}
        Err(err) => return Err(err).context("join stdin task"),
    }
    match resize_task.await {
        Ok(result) => result?,
        Err(err) if err.is_cancelled() => {}
        Err(err) => return Err(err).context("join resize task"),
    }
    send_task.await.context("join send task")??;

    let exit_code = exit_result?;
    Ok(exit_code)
}

fn current_term_for_exec() -> Option<String> {
    if !(std::io::stdin().is_terminal() || std::io::stdout().is_terminal()) {
        return None;
    }

    Some("xterm".to_string())
}

fn wrap_exec_with_term(argv: Vec<String>, term: Option<String>) -> Vec<String> {
    let Some(term) = term else {
        return argv;
    };

    let mut wrapped = Vec::with_capacity(argv.len() + 5);
    wrapped.push("/bin/sh".to_string());
    wrapped.push("-lc".to_string());
    wrapped.push("export TERM=\"$1\"; shift; exec \"$@\"".to_string());
    wrapped.push("sh".to_string());
    wrapped.push(term);
    wrapped.extend(argv);
    wrapped
}

fn spawn_stdin_task(
    is_tty: bool,
    tx: tokio::sync::mpsc::Sender<ConsoleFrame>,
) -> tokio::task::JoinHandle<Result<()>> {
    if is_tty {
        tokio::spawn(async move {
            let stdin = open_nonblocking_stdin().context("open nonblocking stdin")?;
            let mut buf = [0u8; 4096];
            loop {
                let n = read_stdin(&stdin, &mut buf).await?;
                if n == 0 {
                    break;
                }
                let _ = tx
                    .send(ConsoleFrame::new(CONSOLE_DATA, buf[..n].to_vec()))
                    .await;
            }
            Ok::<(), anyhow::Error>(())
        })
    } else {
        tokio::task::spawn_blocking(move || {
            let stdin = std::io::stdin();
            let mut stdin = stdin.lock();
            let mut buf = [0u8; 4096];
            loop {
                let n = stdin.read(&mut buf).context("read local stdin")?;
                if n == 0 {
                    break;
                }
                if tx
                    .blocking_send(ConsoleFrame::new(CONSOLE_DATA, buf[..n].to_vec()))
                    .is_err()
                {
                    break;
                }
            }
            Ok::<(), anyhow::Error>(())
        })
    }
}

/// RAII guard that restores the original terminal settings on drop.
struct RawModeGuard {
    original: libc::termios,
    fd: i32,
}

impl RawModeGuard {
    fn enable() -> Result<Self> {
        let fd = std::io::stdin().as_raw_fd();
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return Err(std::io::Error::last_os_error()).context("tcgetattr");
        }

        let mut raw = original;
        // Input: no break interrupt, no CR→NL, no parity, no strip, no flow ctl
        raw.c_iflag &= !(libc::BRKINT | libc::ICRNL | libc::INPCK | libc::ISTRIP | libc::IXON);
        // Output: disable post-processing
        raw.c_oflag &= !libc::OPOST;
        // Control: 8-bit chars
        raw.c_cflag |= libc::CS8;
        // Local: no echo, no canonical, no extended, no signal chars
        raw.c_lflag &= !(libc::ECHO | libc::ICANON | libc::IEXTEN | libc::ISIG);
        // Return each byte as it arrives
        raw.c_cc[libc::VMIN] = 1;
        raw.c_cc[libc::VTIME] = 0;

        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
            return Err(std::io::Error::last_os_error()).context("tcsetattr raw");
        }

        Ok(Self { original, fd })
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
        }
    }
}

fn terminal_size() -> Option<(u16, u16)> {
    let fd = std::io::stdout().as_raw_fd();
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } == 0 && ws.ws_row > 0 && ws.ws_col > 0
    {
        Some((ws.ws_row, ws.ws_col))
    } else {
        None
    }
}

fn open_nonblocking_stdin() -> Result<AsyncFd<OwnedFd>> {
    let fd = std::io::stdin().as_raw_fd();
    let dup = unsafe { libc::dup(fd) };
    if dup < 0 {
        return Err(std::io::Error::last_os_error()).context("dup stdin");
    }

    let owned = unsafe { OwnedFd::from_raw_fd(dup) };
    set_nonblocking(&owned)?;
    AsyncFd::new(owned).context("wrap stdin in AsyncFd")
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

async fn read_stdin(stdin: &AsyncFd<OwnedFd>, buf: &mut [u8]) -> Result<usize> {
    loop {
        if let Some(result) = try_read_fd(stdin.get_ref().as_raw_fd(), buf)? {
            return Ok(result);
        }

        let mut guard = stdin.readable().await.context("wait for stdin readable")?;
        match guard.try_io(|inner| {
            try_read_fd(inner.get_ref().as_raw_fd(), buf)?
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::WouldBlock))
        }) {
            Ok(result) => return result.context("read local stdin"),
            Err(_would_block) => continue,
        }
    }
}

fn try_read_fd(fd: i32, buf: &mut [u8]) -> std::io::Result<Option<usize>> {
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n >= 0 {
        return Ok(Some(n as usize));
    }

    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::EAGAIN) => Ok(None),
        _ => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use super::wrap_exec_with_term;

    #[test]
    fn wrap_exec_with_term_preserves_plain_exec_without_term() {
        let argv = vec![
            "tmux".to_string(),
            "attach".to_string(),
            "-t".to_string(),
            "svc".to_string(),
        ];
        assert_eq!(wrap_exec_with_term(argv.clone(), None), argv);
    }

    #[test]
    fn wrap_exec_with_term_injects_shell_wrapper() {
        let wrapped = wrap_exec_with_term(
            vec![
                "tmux".to_string(),
                "attach".to_string(),
                "-t".to_string(),
                "svc".to_string(),
            ],
            Some("tmux-256color".to_string()),
        );

        assert_eq!(
            wrapped,
            vec![
                "/bin/sh".to_string(),
                "-lc".to_string(),
                "export TERM=\"$1\"; shift; exec \"$@\"".to_string(),
                "sh".to_string(),
                "tmux-256color".to_string(),
                "tmux".to_string(),
                "attach".to_string(),
                "-t".to_string(),
                "svc".to_string(),
            ]
        );
    }
}
