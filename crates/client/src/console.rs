use anyhow::{Context, Result};
use protocol::{
    decode_exit, encode_resize, ConsoleFrame, ExecSessionRequest, SharedConsoleRequest,
    CONSOLE_DATA, CONSOLE_EXEC, CONSOLE_EXIT, CONSOLE_RESIZE, CONSOLE_SHELL, STREAM_CONSOLE,
};
use std::io::{IsTerminal, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use tokio::io::unix::AsyncFd;
use tokio::io::AsyncWriteExt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleSessionOutcome {
    Exited(u32),
    Disconnected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsoleSessionProgress {
    pub outcome: ConsoleSessionOutcome,
    pub rendered_bytes: u64,
}

pub async fn run_console(
    conn: quinn::Connection,
    rendered_bytes: u64,
) -> Result<ConsoleSessionProgress> {
    let progress = run_session(
        conn,
        ConsoleFrame::new(
            CONSOLE_SHELL,
            SharedConsoleRequest { rendered_bytes }.to_bytes(),
        ),
        rendered_bytes,
    )
    .await?;
    if let ConsoleSessionOutcome::Exited(exit_code) = progress.outcome {
        eprintln!("\r\nremote shell exited with {exit_code}");
    }
    Ok(progress)
}

pub async fn run_exec(
    conn: quinn::Connection,
    request: ExecSessionRequest,
) -> Result<ConsoleSessionProgress> {
    run_session(
        conn,
        ConsoleFrame::new(CONSOLE_EXEC, request.to_bytes()),
        request.rendered_bytes,
    )
    .await
}

/// Run an exec session non-interactively, streaming output through `output_tx`.
/// Returns the exit code when the remote process exits.
/// No terminal handling (no raw mode, no resize, no stdin).
pub async fn run_exec_streaming(
    conn: quinn::Connection,
    request: ExecSessionRequest,
    output_tx: tokio::sync::mpsc::Sender<bytes::Bytes>,
) -> Result<u32> {
    let (mut send, mut recv) = conn.open_bi().await.context("open exec stream")?;
    send.write_u8(STREAM_CONSOLE)
        .await
        .context("write console stream tag")?;
    ConsoleFrame::new(CONSOLE_EXEC, request.to_bytes())
        .write_to(&mut send)
        .await
        .context("write exec startup frame")?;

    // Keep `send` alive — finishing or dropping it signals EOF/RESET to the
    // remote, which would tear down the session before output arrives.
    let exit_code = loop {
        let frame = ConsoleFrame::read_from(&mut recv)
            .await
            .context("read exec frame")?;
        match frame.ty {
            CONSOLE_DATA => {
                if output_tx
                    .send(bytes::Bytes::from(frame.payload))
                    .await
                    .is_err()
                {
                    // HTTP client disconnected
                    break decode_exit(&wait_for_exit(&mut recv).await?)?;
                }
            }
            CONSOLE_EXIT => {
                break decode_exit(&frame.payload)?;
            }
            _ => {}
        }
    };

    let _ = send.finish();
    Ok(exit_code)
}

/// Drain frames until a CONSOLE_EXIT arrives, returning its payload.
async fn wait_for_exit(recv: &mut quinn::RecvStream) -> Result<Vec<u8>> {
    loop {
        let frame = ConsoleFrame::read_from(recv)
            .await
            .context("read exec frame while waiting for exit")?;
        if frame.ty == CONSOLE_EXIT {
            return Ok(frame.payload);
        }
    }
}

pub fn build_exec_request(
    session_id: String,
    argv: Option<Vec<String>>,
    context: Option<String>,
) -> ExecSessionRequest {
    ExecSessionRequest {
        session_id,
        argv: argv.map(|argv| wrap_exec_with_term(argv, current_term_for_exec())),
        context,
        rendered_bytes: 0,
    }
}

async fn run_session(
    conn: quinn::Connection,
    startup: ConsoleFrame,
    mut rendered_bytes: u64,
) -> Result<ConsoleSessionProgress> {
    let (mut send, mut recv) = match conn.open_bi().await {
        Ok(streams) => streams,
        Err(err) => {
            let err = anyhow::Error::new(err).context("open console stream");
            if is_reconnectable_transport(&err) {
                return Ok(ConsoleSessionProgress {
                    outcome: ConsoleSessionOutcome::Disconnected,
                    rendered_bytes,
                });
            }
            return Err(err);
        }
    };
    if let Err(err) = send.write_u8(STREAM_CONSOLE).await {
        let err = anyhow::Error::new(err).context("write console stream tag");
        if is_reconnectable_transport(&err) {
            return Ok(ConsoleSessionProgress {
                outcome: ConsoleSessionOutcome::Disconnected,
                rendered_bytes,
            });
        }
        return Err(err);
    }
    if let Err(err) = startup.write_to(&mut send).await {
        if is_reconnectable_transport(&err) {
            return Ok(ConsoleSessionProgress {
                outcome: ConsoleSessionOutcome::Disconnected,
                rendered_bytes,
            });
        }
        return Err(err);
    }

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

    let session_result: Result<ConsoleSessionOutcome> = async {
        let mut stdout = std::io::stdout();
        loop {
            let frame = match ConsoleFrame::read_from(&mut recv).await {
                Ok(frame) => frame,
                Err(err) if is_reconnectable_transport(&err) => {
                    return Ok(ConsoleSessionOutcome::Disconnected);
                }
                Err(err) => return Err(err),
            };
            match frame.ty {
                CONSOLE_DATA => {
                    write_console_output(&mut stdout, &frame.payload).await?;
                    rendered_bytes = rendered_bytes.saturating_add(frame.payload.len() as u64);
                }
                CONSOLE_EXIT => {
                    return Ok(ConsoleSessionOutcome::Exited(decode_exit(&frame.payload)?));
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
    let send_result = match send_task.await {
        Ok(result) => result,
        Err(err) => return Err(err).context("join send task"),
    };

    let outcome = match session_result {
        Ok(ConsoleSessionOutcome::Exited(exit_code)) => {
            send_result?;
            ConsoleSessionOutcome::Exited(exit_code)
        }
        Ok(ConsoleSessionOutcome::Disconnected) => {
            if let Err(err) = send_result {
                if !is_reconnectable_transport(&err) {
                    return Err(err);
                }
            }
            ConsoleSessionOutcome::Disconnected
        }
        Err(err) => {
            if is_reconnectable_transport(&err) {
                if let Err(send_err) = send_result {
                    if !is_reconnectable_transport(&send_err) {
                        return Err(send_err);
                    }
                }
                ConsoleSessionOutcome::Disconnected
            } else {
                if let Err(send_err) = send_result {
                    if !is_reconnectable_transport(&send_err) {
                        return Err(send_err);
                    }
                }
                return Err(err);
            }
        }
    };

    Ok(ConsoleSessionProgress {
        outcome,
        rendered_bytes,
    })
}

async fn write_console_output(stdout: &mut std::io::Stdout, payload: &[u8]) -> Result<()> {
    let mut written = 0;
    while written < payload.len() {
        let slice = &payload[written..];
        let ret = tokio::task::block_in_place(|| unsafe {
            libc::write(stdout.as_raw_fd(), slice.as_ptr().cast(), slice.len())
        });
        if ret < 0 {
            return Err(
                anyhow::Error::from(std::io::Error::last_os_error()).context("write stdout")
            );
        }
        if ret == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::WriteZero))
                .context("write stdout");
        }
        written += ret as usize;
    }

    Ok(())
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

pub fn is_reconnectable_transport(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<quinn::ConnectionError>()
            .is_some_and(is_reconnectable_connection_error)
            || cause
                .downcast_ref::<quinn::ReadError>()
                .is_some_and(is_reconnectable_read_error)
            || cause
                .downcast_ref::<quinn::WriteError>()
                .is_some_and(is_reconnectable_write_error)
            || cause.downcast_ref::<std::io::Error>().is_some_and(|io| {
                matches!(
                    io.kind(),
                    std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::NotConnected
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::UnexpectedEof
                )
            })
    })
}

fn is_reconnectable_connection_error(err: &quinn::ConnectionError) -> bool {
    matches!(
        err,
        quinn::ConnectionError::ApplicationClosed(_)
            | quinn::ConnectionError::ConnectionClosed(_)
            | quinn::ConnectionError::Reset
            | quinn::ConnectionError::TimedOut
            | quinn::ConnectionError::TransportError(_)
    )
}

fn is_reconnectable_read_error(err: &quinn::ReadError) -> bool {
    matches!(err, quinn::ReadError::Reset(_))
        || matches!(
            err,
            quinn::ReadError::ConnectionLost(conn_err)
                if is_reconnectable_connection_error(conn_err)
        )
}

fn is_reconnectable_write_error(err: &quinn::WriteError) -> bool {
    matches!(err, quinn::WriteError::Stopped(_))
        || matches!(
            err,
            quinn::WriteError::ConnectionLost(conn_err)
                if is_reconnectable_connection_error(conn_err)
        )
}

#[cfg(test)]
mod tests {
    use super::{is_reconnectable_transport, wrap_exec_with_term};
    use anyhow::anyhow;

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

    #[test]
    fn reconnectable_transport_matches_connection_reset_io_errors() {
        let err = anyhow!(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
        assert!(is_reconnectable_transport(&err));
    }
}
