use anyhow::{anyhow, Context, Result};
use nix::unistd::Pid;
use protocol::{
    decode_resize, ConsoleFrame, ExecSessionInfo, ExecSessionList, ExecSessionRequest,
    SharedConsoleRequest, CONSOLE_DATA, CONSOLE_EXEC, CONSOLE_EXIT, CONSOLE_RESIZE, CONSOLE_SHELL,
};
use std::collections::{HashMap, VecDeque};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::sync::{mpsc, watch, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::warn;

const DETACHED_OUTPUT_BUFFER_LIMIT_BYTES: usize = 1024 * 1024;

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

#[derive(Debug, Default)]
pub struct SharedConsoleManager {
    session: Mutex<Option<Arc<SharedConsoleSession>>>,
}

impl SharedConsoleManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn attach(
        &self,
        root_dir: &Path,
        inner_pid: Pid,
        test_mode: bool,
        rendered_bytes: u64,
    ) -> Result<SharedConsoleAttachment> {
        loop {
            let session = {
                let mut guard = self.session.lock().await;
                match guard.as_ref() {
                    Some(existing) if !existing.is_finished() => Arc::clone(existing),
                    _ => {
                        let session =
                            Arc::new(SharedConsoleSession::spawn(root_dir, inner_pid, test_mode)?);
                        *guard = Some(Arc::clone(&session));
                        session
                    }
                }
            };

            let attachment = session.attach(rendered_bytes);
            if !session.is_finished() {
                return Ok(attachment);
            }

            let mut guard = self.session.lock().await;
            if guard
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &session))
            {
                *guard = None;
            }
        }
    }
}

#[derive(Debug)]
pub struct ExecSessionManager {
    sessions: Mutex<HashMap<String, Arc<ExecSession>>>,
}

const COMPLETED_SESSION_TTL: Duration = Duration::from_secs(60);

impl ExecSessionManager {
    pub fn new_arced() -> Arc<Self> {
        let manager = Arc::new(Self {
            sessions: Mutex::new(HashMap::new()),
        });
        tokio::spawn(Self::reap_completed_sessions(Arc::clone(&manager)));
        manager
    }

    async fn reap_completed_sessions(self: Arc<Self>) {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let mut guard = self.sessions.lock().await;
            guard.retain(|_, session| {
                let exited_at = session.runtime.exited_at.lock().unwrap();
                match *exited_at {
                    Some(t) => t.elapsed() < COMPLETED_SESSION_TTL,
                    None => true,
                }
            });
        }
    }

    pub async fn attach_or_create(
        self: &Arc<Self>,
        root_dir: &Path,
        inner_pid: Pid,
        test_mode: bool,
        request: ExecSessionRequest,
    ) -> Result<ExecSessionAttachment> {
        let session = {
            let mut guard = self.sessions.lock().await;
            if let Some(existing) = guard.get(&request.session_id) {
                Arc::clone(existing)
            } else {
                let argv = request
                    .argv
                    .clone()
                    .ok_or_else(|| anyhow!("exec session {} not found", request.session_id))?;
                if argv.is_empty() {
                    return Err(anyhow!(
                        "exec request must include at least one argv element"
                    ));
                }
                let session = Arc::new(ExecSession::spawn(
                    root_dir,
                    inner_pid,
                    test_mode,
                    request.session_id.clone(),
                    argv,
                    request.context.clone(),
                    Arc::downgrade(self),
                )?);
                guard.insert(request.session_id.clone(), Arc::clone(&session));
                session
            }
        };

        session.attach(request.rendered_bytes).await
    }

    pub async fn list(&self) -> Vec<ExecSessionInfo> {
        let sessions = {
            let guard = self.sessions.lock().await;
            let mut sessions = guard.values().cloned().collect::<Vec<_>>();
            sessions.sort_by(|a, b| a.session_id.cmp(&b.session_id));
            sessions
        };

        let mut out = Vec::with_capacity(sessions.len());
        for session in sessions {
            out.push(session.snapshot().await);
        }
        out
    }

    async fn remove_if_same(&self, session_id: &str, session: &Arc<ExecSession>) {
        let mut guard = self.sessions.lock().await;
        if guard
            .get(session_id)
            .is_some_and(|current| Arc::ptr_eq(current, session))
        {
            guard.remove(session_id);
        }
    }
}

#[derive(Debug)]
struct SharedConsoleSession {
    runtime: PersistentConsoleRuntime,
}

impl SharedConsoleSession {
    fn spawn(root_dir: &Path, inner_pid: Pid, test_mode: bool) -> Result<Self> {
        Ok(Self {
            runtime: spawn_persistent_console(
                ConsoleLaunch::Shell,
                root_dir,
                inner_pid,
                test_mode,
                "shared console shell",
            )?,
        })
    }

    fn attach(&self, rendered_bytes: u64) -> SharedConsoleAttachment {
        SharedConsoleAttachment {
            input_tx: self.runtime.input_tx.clone(),
            output: Arc::clone(&self.runtime.output),
            output_subscription: self.runtime.output.subscribe_from(rendered_bytes),
            exit_code: Arc::clone(&self.runtime.exit_code),
        }
    }

    fn is_finished(&self) -> bool {
        read_exit_code(self.runtime.exit_code.as_ref()).is_some()
    }
}

#[derive(Debug)]
struct ExecSession {
    session_id: String,
    argv: Vec<String>,
    context: Option<String>,
    runtime: PersistentConsoleRuntime,
    attachment: Mutex<ExecAttachmentState>,
    owner: std::sync::Weak<ExecSessionManager>,
}

impl ExecSession {
    fn spawn(
        root_dir: &Path,
        inner_pid: Pid,
        test_mode: bool,
        session_id: String,
        argv: Vec<String>,
        context: Option<String>,
        owner: std::sync::Weak<ExecSessionManager>,
    ) -> Result<Self> {
        Ok(Self {
            session_id: session_id.clone(),
            argv: argv.clone(),
            context,
            runtime: spawn_persistent_console(
                ConsoleLaunch::Exec(argv),
                root_dir,
                inner_pid,
                test_mode,
                "persistent exec session",
            )?,
            attachment: Mutex::new(ExecAttachmentState::default()),
            owner,
        })
    }

    async fn attach(self: &Arc<Self>, rendered_bytes: u64) -> Result<ExecSessionAttachment> {
        let mut state = self.attachment.lock().await;
        if let Some((_, token)) = state.current.take() {
            token.cancel();
        }
        state.next_generation += 1;
        let generation = state.next_generation;
        let takeover = CancellationToken::new();
        state.current = Some((generation, takeover.clone()));

        Ok(ExecSessionAttachment {
            session: Arc::clone(self),
            input_tx: self.runtime.input_tx.clone(),
            output: Arc::clone(&self.runtime.output),
            output_subscription: self.runtime.output.subscribe_from(rendered_bytes),
            exit_code: Arc::clone(&self.runtime.exit_code),
            takeover,
            generation,
        })
    }

    async fn detach(self: &Arc<Self>, generation: u64) {
        let mut state = self.attachment.lock().await;
        if state
            .current
            .as_ref()
            .is_some_and(|(current, _)| *current == generation)
        {
            state.current = None;
        }
        let should_remove = read_exit_code(self.runtime.exit_code.as_ref()).is_some();
        drop(state);

        if should_remove {
            if let Some(owner) = self.owner.upgrade() {
                owner.remove_if_same(&self.session_id, self).await;
            }
        }
    }

    async fn snapshot(&self) -> ExecSessionInfo {
        let attached = {
            let state = self.attachment.lock().await;
            state.current.is_some() && read_exit_code(self.runtime.exit_code.as_ref()).is_none()
        };
        ExecSessionInfo {
            session_id: self.session_id.clone(),
            argv: self.argv.clone(),
            context: self.context.clone(),
            attached,
            exit_code: read_exit_code(self.runtime.exit_code.as_ref()),
        }
    }
}

#[derive(Debug, Default)]
struct ExecAttachmentState {
    next_generation: u64,
    current: Option<(u64, CancellationToken)>,
}

#[derive(Debug)]
struct BufferedConsoleOutput {
    limit_bytes: usize,
    state: StdMutex<BufferedConsoleState>,
    notify_tx: watch::Sender<u64>,
}

impl BufferedConsoleOutput {
    fn new(limit_bytes: usize) -> Self {
        let (notify_tx, _) = watch::channel(0u64);
        Self {
            limit_bytes,
            state: StdMutex::new(BufferedConsoleState::default()),
            notify_tx,
        }
    }

    fn subscribe_from(&self, rendered_bytes: u64) -> BufferedConsoleSubscription {
        let notify_rx = self.notify_tx.subscribe();
        let state = self.state.lock().unwrap();
        let next_offset = state.next_offset;
        let replay_from = rendered_bytes.clamp(state.retained_start, next_offset);
        let skip = (replay_from - state.retained_start) as usize;
        let replay: Vec<u8> = state.buffer.iter().skip(skip).copied().collect();
        BufferedConsoleSubscription {
            replay,
            next_offset,
            notify_rx,
        }
    }

    fn replay_from(&self, offset: u64) -> (Vec<u8>, u64) {
        let state = self.state.lock().unwrap();
        state.replay_from(offset)
    }

    fn push_data(&self, payload: &[u8]) {
        let next_offset = {
            let mut state = self.state.lock().unwrap();
            state.push(payload, self.limit_bytes);
            state.next_offset
        };
        self.notify_tx.send_modify(|v| *v = next_offset);
    }

    fn push_exit(&self, _code: u32) {
        // Exit is detected via the exit_code mutex; just bump the watch
        // so any waiters wake up and can check.
        self.notify_tx.send_modify(|v| *v = v.saturating_add(1));
    }
}

#[derive(Debug, Default)]
struct BufferedConsoleState {
    retained_start: u64,
    next_offset: u64,
    buffer: VecDeque<u8>,
}

impl BufferedConsoleState {
    fn push(&mut self, payload: &[u8], limit_bytes: usize) -> u64 {
        let start_offset = self.next_offset;
        self.next_offset = self.next_offset.saturating_add(payload.len() as u64);

        if limit_bytes == 0 {
            self.buffer.clear();
            self.retained_start = self.next_offset;
            return start_offset;
        }

        if payload.len() >= limit_bytes {
            self.buffer.clear();
            self.buffer
                .extend(payload[payload.len() - limit_bytes..].iter().copied());
            self.retained_start = self.next_offset - self.buffer.len() as u64;
            return start_offset;
        }

        self.buffer.extend(payload.iter().copied());
        let overflow = self.buffer.len().saturating_sub(limit_bytes);
        if overflow > 0 {
            self.buffer.drain(..overflow);
            self.retained_start = self.retained_start.saturating_add(overflow as u64);
        }

        start_offset
    }

    fn replay_from(&self, rendered_bytes: u64) -> (Vec<u8>, u64) {
        let replay_from = rendered_bytes.clamp(self.retained_start, self.next_offset);
        let skip = (replay_from - self.retained_start) as usize;
        (
            self.buffer.iter().skip(skip).copied().collect(),
            self.next_offset,
        )
    }
}

#[derive(Debug)]
struct BufferedConsoleSubscription {
    replay: Vec<u8>,
    next_offset: u64,
    notify_rx: watch::Receiver<u64>,
}

#[derive(Debug)]
struct PersistentConsoleRuntime {
    input_tx: mpsc::Sender<ConsoleInput>,
    output: Arc<BufferedConsoleOutput>,
    exit_code: Arc<StdMutex<Option<u32>>>,
    exited_at: Arc<StdMutex<Option<Instant>>>,
}

#[derive(Debug)]
pub struct SharedConsoleAttachment {
    input_tx: mpsc::Sender<ConsoleInput>,
    output: Arc<BufferedConsoleOutput>,
    output_subscription: BufferedConsoleSubscription,
    exit_code: Arc<StdMutex<Option<u32>>>,
}

#[derive(Debug)]
pub struct ExecSessionAttachment {
    session: Arc<ExecSession>,
    input_tx: mpsc::Sender<ConsoleInput>,
    output: Arc<BufferedConsoleOutput>,
    output_subscription: BufferedConsoleSubscription,
    exit_code: Arc<StdMutex<Option<u32>>>,
    takeover: CancellationToken,
    generation: u64,
}

#[derive(Debug)]
enum ConsoleInput {
    Data(Vec<u8>),
    Resize { rows: u16, cols: u16 },
}

pub async fn handle_console_stream(
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    shared_console: Arc<SharedConsoleManager>,
    exec_sessions: Arc<ExecSessionManager>,
    root_dir: &Path,
    inner_pid: Pid,
    test_mode: bool,
) -> Result<()> {
    let startup = ConsoleFrame::read_from(&mut recv).await?;

    match startup.ty {
        CONSOLE_SHELL => {
            let request = SharedConsoleRequest::from_bytes(&startup.payload)?;
            handle_shared_console_stream(
                send,
                recv,
                shared_console,
                root_dir,
                inner_pid,
                test_mode,
                request.rendered_bytes,
            )
            .await
        }
        CONSOLE_EXEC => {
            let request = ExecSessionRequest::from_bytes(&startup.payload)?;
            handle_exec_session_stream(
                send,
                recv,
                exec_sessions,
                root_dir,
                inner_pid,
                test_mode,
                request,
            )
            .await
        }
        other => Err(anyhow!("unexpected initial console frame type: {other}")),
    }
}

pub async fn handle_exec_list_stream(
    mut send: quinn::SendStream,
    exec_sessions: Arc<ExecSessionManager>,
) -> Result<()> {
    let list = ExecSessionList {
        sessions: exec_sessions.list().await,
    };
    list.write_to(&mut send).await?;
    send.finish().context("finish exec-list stream")?;
    Ok(())
}

async fn handle_shared_console_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    shared_console: Arc<SharedConsoleManager>,
    root_dir: &Path,
    inner_pid: Pid,
    test_mode: bool,
    rendered_bytes: u64,
) -> Result<()> {
    let SharedConsoleAttachment {
        input_tx,
        output,
        output_subscription,
        exit_code,
    } = shared_console
        .attach(root_dir, inner_pid, test_mode, rendered_bytes)
        .await?;

    let session_to_client = async {
        stream_console_output(
            &mut send,
            output.as_ref(),
            output_subscription,
            exit_code.as_ref(),
            None,
            "finish shared console stream",
        )
        .await
    };

    let client_to_session = async { relay_client_input(&mut recv, &input_tx, None).await };

    tokio::select! {
        result = session_to_client => result?,
        result = client_to_session => result?,
    }

    Ok(())
}

async fn handle_exec_session_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    exec_sessions: Arc<ExecSessionManager>,
    root_dir: &Path,
    inner_pid: Pid,
    test_mode: bool,
    request: ExecSessionRequest,
) -> Result<()> {
    let ExecSessionAttachment {
        session,
        input_tx,
        output,
        output_subscription,
        exit_code,
        takeover,
        generation,
    } = exec_sessions
        .attach_or_create(root_dir, inner_pid, test_mode, request)
        .await?;

    let session_to_client = async {
        stream_console_output(
            &mut send,
            output.as_ref(),
            output_subscription,
            exit_code.as_ref(),
            Some(&takeover),
            "finish exec session stream",
        )
        .await
    };

    let client_to_session =
        async { relay_client_input(&mut recv, &input_tx, Some(&takeover)).await };

    let result = tokio::select! {
        result = session_to_client => result,
        result = client_to_session => result,
    };

    session.detach(generation).await;
    result?;
    Ok(())
}

fn spawn_persistent_console(
    launch: ConsoleLaunch,
    root_dir: &Path,
    inner_pid: Pid,
    test_mode: bool,
    wait_label: &'static str,
) -> Result<PersistentConsoleRuntime> {
    let (master_fd, slave_fd) = open_pty().context("allocate pty pair")?;

    let mut cmd = build_console_command(&launch, root_dir, inner_pid, test_mode);
    configure_console_stdio(&mut cmd, &slave_fd)?;
    let child = cmd
        .spawn()
        .with_context(|| launch.spawn_context(inner_pid, test_mode))?;

    drop(slave_fd);

    set_nonblocking(&master_fd)?;
    let master = Arc::new(AsyncFd::new(master_fd).context("wrap pty master in AsyncFd")?);

    let (input_tx, input_rx) = mpsc::channel(64);
    let output = Arc::new(BufferedConsoleOutput::new(
        DETACHED_OUTPUT_BUFFER_LIMIT_BYTES,
    ));
    let exit_code = Arc::new(StdMutex::new(None));
    let exited_at = Arc::new(StdMutex::new(None));
    let shutdown = CancellationToken::new();

    tokio::spawn(run_persistent_console_input(
        Arc::clone(&master),
        input_rx,
        shutdown.clone(),
        Arc::clone(&exit_code),
    ));
    tokio::spawn(run_persistent_console_output(
        master,
        Arc::clone(&output),
        shutdown.clone(),
        Arc::clone(&exit_code),
    ));
    tokio::spawn(wait_for_persistent_console_exit(
        child,
        Arc::clone(&output),
        shutdown,
        Arc::clone(&exit_code),
        Arc::clone(&exited_at),
        wait_label,
    ));

    Ok(PersistentConsoleRuntime {
        input_tx,
        output,
        exit_code,
        exited_at,
    })
}

async fn run_persistent_console_input(
    master: Arc<AsyncFd<OwnedFd>>,
    mut input_rx: mpsc::Receiver<ConsoleInput>,
    shutdown: CancellationToken,
    exit_code: Arc<StdMutex<Option<u32>>>,
) {
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            maybe_input = input_rx.recv() => {
                let Some(input) = maybe_input else {
                    break;
                };

                let result = match input {
                    ConsoleInput::Data(data) => pty_write_all(master.as_ref(), &data).await,
                    ConsoleInput::Resize { rows, cols } => {
                        set_pty_winsize(master.get_ref().as_raw_fd(), rows, cols);
                        Ok(())
                    }
                };

                if let Err(err) = result {
                    if read_exit_code(exit_code.as_ref()).is_none() {
                        warn!(error = ?err, "persistent console input failed");
                    }
                    shutdown.cancel();
                    break;
                }
            }
        }
    }
}

async fn run_persistent_console_output(
    master: Arc<AsyncFd<OwnedFd>>,
    output: Arc<BufferedConsoleOutput>,
    shutdown: CancellationToken,
    exit_code: Arc<StdMutex<Option<u32>>>,
) {
    let mut buf = [0u8; 8192];
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            result = pty_read(master.as_ref(), &mut buf) => {
                match result {
                    Ok(0) => break,
                    Ok(n) => {
                        output.push_data(&buf[..n]);
                    }
                    Err(err) => {
                        if read_exit_code(exit_code.as_ref()).is_none() {
                            warn!(error = ?err, "persistent console output failed");
                        }
                        break;
                    }
                }
            }
        }
    }
}

async fn wait_for_persistent_console_exit(
    mut child: tokio::process::Child,
    output: Arc<BufferedConsoleOutput>,
    shutdown: CancellationToken,
    exit_code: Arc<StdMutex<Option<u32>>>,
    exited_at: Arc<StdMutex<Option<Instant>>>,
    wait_label: &'static str,
) {
    let code = match child.wait().await {
        Ok(status) => status.code().unwrap_or(255) as u32,
        Err(err) => {
            warn!(error = ?err, wait_label, "wait on persistent console failed");
            255
        }
    };

    {
        let mut guard = exit_code.lock().unwrap();
        *guard = Some(code);
    }
    {
        let mut guard = exited_at.lock().unwrap();
        *guard = Some(Instant::now());
    }

    output.push_exit(code);
    shutdown.cancel();
}

async fn relay_client_input(
    recv: &mut quinn::RecvStream,
    input_tx: &mpsc::Sender<ConsoleInput>,
    takeover: Option<&CancellationToken>,
) -> Result<()> {
    loop {
        if let Some(takeover) = takeover {
            tokio::select! {
                _ = takeover.cancelled() => break,
                frame = ConsoleFrame::read_from(recv) => {
                    match frame {
                        Ok(frame) => forward_client_frame(frame, input_tx).await?,
                        Err(err) if is_unexpected_eof(&err) => break,
                        Err(err) => return Err(err),
                    }
                }
            }
        } else {
            let frame = match ConsoleFrame::read_from(recv).await {
                Ok(frame) => frame,
                Err(err) if is_unexpected_eof(&err) => break,
                Err(err) => return Err(err),
            };
            forward_client_frame(frame, input_tx).await?;
        }
    }

    Ok(())
}

async fn stream_console_output(
    send: &mut quinn::SendStream,
    output: &BufferedConsoleOutput,
    mut subscription: BufferedConsoleSubscription,
    exit_code: &StdMutex<Option<u32>>,
    takeover: Option<&CancellationToken>,
    finish_context: &'static str,
) -> Result<()> {
    send_console_bytes(send, &subscription.replay).await?;
    let mut next_offset = subscription.next_offset;

    if let Some(code) = read_exit_code(exit_code) {
        write_exit_frame(send, code).await?;
        send.finish().context(finish_context)?;
        return Ok(());
    }

    loop {
        let changed = if let Some(takeover) = takeover {
            tokio::select! {
                _ = takeover.cancelled() => break,
                result = subscription.notify_rx.changed() => result,
            }
        } else {
            subscription.notify_rx.changed().await
        };

        if changed.is_err() {
            // Sender dropped — drain remaining data.
            let (replay, _) = output.replay_from(next_offset);
            send_console_bytes(send, &replay).await?;
            if let Some(code) = read_exit_code(exit_code) {
                write_exit_frame(send, code).await?;
                send.finish().context(finish_context)?;
            }
            break;
        }

        let (data, new_offset) = output.replay_from(next_offset);
        send_console_bytes(send, &data).await?;
        next_offset = new_offset;

        if let Some(code) = read_exit_code(exit_code) {
            write_exit_frame(send, code).await?;
            send.finish().context(finish_context)?;
            break;
        }
    }

    Ok(())
}

async fn send_console_bytes(send: &mut quinn::SendStream, payload: &[u8]) -> Result<()> {
    if payload.is_empty() {
        return Ok(());
    }

    ConsoleFrame::new(CONSOLE_DATA, payload.to_vec())
        .write_to(send)
        .await
}

async fn forward_client_frame(
    frame: ConsoleFrame,
    input_tx: &mpsc::Sender<ConsoleInput>,
) -> Result<()> {
    let input = match frame.ty {
        CONSOLE_DATA => ConsoleInput::Data(frame.payload),
        CONSOLE_RESIZE => {
            let (rows, cols) = decode_resize(&frame.payload)?;
            ConsoleInput::Resize { rows, cols }
        }
        _ => return Ok(()),
    };

    let _ = input_tx.send(input).await;
    Ok(())
}

async fn write_exit_frame(send: &mut quinn::SendStream, code: u32) -> Result<()> {
    ConsoleFrame::new(CONSOLE_EXIT, code.to_be_bytes().to_vec())
        .write_to(send)
        .await
}

fn read_exit_code(exit_code: &StdMutex<Option<u32>>) -> Option<u32> {
    *exit_code.lock().unwrap()
}

enum ConsoleLaunch {
    Shell,
    Exec(Vec<String>),
}

impl ConsoleLaunch {
    fn shell_path(root_dir: &Path) -> &'static str {
        if root_dir.join("bin/bash").exists() {
            "/bin/bash"
        } else {
            "/bin/sh"
        }
    }

    fn spawn_context(&self, inner_pid: Pid, test_mode: bool) -> String {
        if test_mode {
            return match self {
                Self::Shell => "spawn shared console shell in test mode".to_string(),
                Self::Exec(argv) => format!("spawn test-mode exec {:?}", argv),
            };
        }

        match self {
            Self::Shell => format!("spawn nsenter console via pid {}", inner_pid.as_raw()),
            Self::Exec(argv) => format!(
                "spawn nsenter exec {:?} via pid {}",
                argv,
                inner_pid.as_raw()
            ),
        }
    }
}

fn build_console_command(
    launch: &ConsoleLaunch,
    root_dir: &Path,
    inner_pid: Pid,
    test_mode: bool,
) -> Command {
    if test_mode {
        let cmd = match launch {
            ConsoleLaunch::Shell => {
                let mut cmd = Command::new(ConsoleLaunch::shell_path(root_dir));
                cmd.current_dir(root_dir)
                    .env("HOME", root_dir.join("root"))
                    .env("PWD", root_dir);
                cmd
            }
            ConsoleLaunch::Exec(argv) => {
                let mut cmd = Command::new(&argv[0]);
                cmd.args(&argv[1..]).current_dir(root_dir);
                cmd
            }
        };
        return cmd;
    }

    let mut cmd = Command::new("nsenter");
    cmd.args([
        "-m",
        "-p",
        "-t",
        &inner_pid.as_raw().to_string(),
        &format!("--wd={}", root_dir.display()),
        "--",
    ]);

    match launch {
        ConsoleLaunch::Shell => {
            cmd.args([ConsoleLaunch::shell_path(root_dir), "-l"]);
        }
        ConsoleLaunch::Exec(argv) => {
            cmd.args(argv);
        }
    }

    cmd
}

fn configure_console_stdio(cmd: &mut Command, slave_fd: &OwnedFd) -> Result<()> {
    let slave_raw = slave_fd.as_raw_fd();
    unsafe {
        cmd.stdin(Stdio::from_raw_fd(dup_fd(slave_raw)?));
        cmd.stdout(Stdio::from_raw_fd(dup_fd(slave_raw)?));
        cmd.stderr(Stdio::from_raw_fd(dup_fd(slave_raw)?));
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            #[cfg(any(
                target_os = "macos",
                target_os = "ios",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd",
                target_os = "dragonfly"
            ))]
            let tiocsctty: libc::c_ulong = libc::TIOCSCTTY.into();
            #[cfg(not(any(
                target_os = "macos",
                target_os = "ios",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd",
                target_os = "dragonfly"
            )))]
            let tiocsctty = libc::TIOCSCTTY;

            if libc::ioctl(0, tiocsctty, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
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
        if let Some(result) = try_read_fd(master.get_ref().as_raw_fd(), buf)? {
            return Ok(result);
        }

        let mut guard = master.readable().await.context("wait pty readable")?;
        match guard.try_io(|inner| {
            try_read_fd(inner.get_ref().as_raw_fd(), buf)?
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::WouldBlock))
        }) {
            Ok(result) => return result.context("read pty master"),
            Err(_would_block) => continue,
        }
    }
}

fn try_read_fd(fd: libc::c_int, buf: &mut [u8]) -> std::io::Result<Option<usize>> {
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    classify_pty_read(n)
}

fn classify_pty_read(read_result: isize) -> std::io::Result<Option<usize>> {
    if read_result >= 0 {
        return Ok(Some(read_result as usize));
    }

    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::EAGAIN) => Ok(None),
        Some(libc::EIO) => Ok(Some(0)),
        _ => Err(err),
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

#[cfg(test)]
mod tests {
    use super::*;
    use nix::errno::Errno;
    use std::path::Path;

    #[test]
    fn classify_pty_read_treats_eio_as_eof() {
        Errno::set(Errno::EIO);
        let result = classify_pty_read(-1).expect("eio should be mapped to eof");
        assert_eq!(result, Some(0));
    }

    #[test]
    fn build_console_command_preserves_exec_argv() {
        let cmd = build_console_command(
            &ConsoleLaunch::Exec(vec!["ls".to_string(), "-lash".to_string(), "/".to_string()]),
            Path::new("/tmp/rootfs"),
            Pid::from_raw(42),
            false,
        );

        let args = cmd
            .as_std()
            .get_args()
            .map(|arg| arg.to_str().unwrap().to_string())
            .collect::<Vec<_>>();

        assert_eq!(
            args,
            vec![
                "-m",
                "-p",
                "-t",
                "42",
                "--wd=/tmp/rootfs",
                "--",
                "ls",
                "-lash",
                "/",
            ]
        );
    }

    #[test]
    fn build_console_command_avoids_nsenter_in_test_mode() {
        let cmd = build_console_command(
            &ConsoleLaunch::Shell,
            Path::new("/tmp/rootfs"),
            Pid::from_raw(42),
            true,
        );

        assert_eq!(cmd.as_std().get_program(), "/bin/sh");
        assert_eq!(
            cmd.as_std().get_current_dir(),
            Some(Path::new("/tmp/rootfs"))
        );

        let args = cmd
            .as_std()
            .get_args()
            .map(|arg| arg.to_str().unwrap().to_string())
            .collect::<Vec<_>>();
        assert!(args.is_empty());
    }

    #[test]
    fn shared_console_manager_starts_without_session() {
        let manager = SharedConsoleManager::new();
        let guard = manager.session.try_lock().expect("lock manager");
        assert!(guard.is_none());
    }

    #[tokio::test]
    async fn exec_session_attach_replaces_previous_attachment() -> Result<()> {
        let session = Arc::new(ExecSession {
            session_id: "sess".to_string(),
            argv: vec!["sh".to_string()],
            context: Some("test context".to_string()),
            runtime: PersistentConsoleRuntime {
                input_tx: mpsc::channel(1).0,
                output: Arc::new(BufferedConsoleOutput::new(1024)),
                exit_code: Arc::new(StdMutex::new(None)),
                exited_at: Arc::new(StdMutex::new(None)),
            },
            attachment: Mutex::new(ExecAttachmentState::default()),
            owner: std::sync::Weak::new(),
        });

        let first = session.attach(0).await?;
        let second = session.attach(0).await?;

        assert!(first.takeover.is_cancelled());
        assert!(!second.takeover.is_cancelled());
        Ok(())
    }
}
