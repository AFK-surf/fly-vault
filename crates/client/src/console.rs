use anyhow::{Context, Result};
use protocol::{
    decode_exit, encode_resize, ConsoleFrame, CONSOLE_DATA, CONSOLE_EXIT, CONSOLE_RESIZE,
    STREAM_CONSOLE,
};
use std::io::IsTerminal;
use std::os::fd::AsRawFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn run_console(conn: quinn::Connection) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await.context("open console stream")?;
    send.write_u8(STREAM_CONSOLE)
        .await
        .context("write console stream tag")?;

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

    // Channel lets both stdin and resize signal write frames without aliasing
    // the send stream.
    let (frame_tx, mut frame_rx) = tokio::sync::mpsc::channel::<ConsoleFrame>(64);

    let stdin_task = {
        let tx = frame_tx.clone();
        async move {
            let mut stdin = tokio::io::stdin();
            let mut buf = [0u8; 4096];
            loop {
                let n = stdin.read(&mut buf).await.context("read local stdin")?;
                if n == 0 {
                    break;
                }
                let _ = tx
                    .send(ConsoleFrame::new(CONSOLE_DATA, buf[..n].to_vec()))
                    .await;
            }
            Ok::<(), anyhow::Error>(())
        }
    };

    let resize_task = {
        let tx = frame_tx;
        async move {
            if !is_tty {
                return std::future::pending::<()>().await;
            }
            let Ok(mut sig) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
            else {
                return std::future::pending::<()>().await;
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
    };

    let send_task = async {
        while let Some(frame) = frame_rx.recv().await {
            frame.write_to(&mut send).await?;
        }
        Ok::<(), anyhow::Error>(())
    };

    let recv_task = async {
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
                    let code = decode_exit(&frame.payload)?;
                    eprintln!("\r\nremote shell exited with {code}");
                    break;
                }
                _ => {}
            }
        }
        Ok::<(), anyhow::Error>(())
    };

    tokio::select! {
        r = stdin_task => r?,
        _ = resize_task => {}
        r = send_task => r?,
        r = recv_task => r?,
    }

    send.finish().context("finish console send")?;
    Ok(())
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
