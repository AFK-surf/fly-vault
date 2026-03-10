use crate::{forward, quic};
use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Frame;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use protocol::{ExecSessionList, ExecSessionRequest, STREAM_EXEC_LIST};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::Mutex;
use tokio_stream::StreamExt;
use tracing::{info, warn};

type BoxBody = http_body_util::combinators::BoxBody<Bytes, anyhow::Error>;

struct ControlState {
    connections: quic::ReconnectableConnection,
    forwards: Mutex<HashMap<u16, ForwardEntry>>,
}

struct ForwardEntry {
    target: String,
    task: tokio::task::JoinHandle<()>,
}

pub async fn serve(
    connections: quic::ReconnectableConnection,
    path: impl AsRef<Path>,
) -> Result<()> {
    let path = path.as_ref();

    // Remove stale socket file if present.
    let _ = std::fs::remove_file(path);
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create control socket directory {}", parent.display()))?;
    }

    let listener = UnixListener::bind(path)
        .with_context(|| format!("bind control socket {}", path.display()))?;
    info!(path = %path.display(), "control socket listening");

    let state = Arc::new(ControlState {
        connections,
        forwards: Mutex::new(HashMap::new()),
    });

    loop {
        let (stream, _) = listener.accept().await.context("accept control socket")?;
        let state = Arc::clone(&state);
        let io = hyper_util::rt::TokioIo::new(stream);
        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let state = Arc::clone(&state);
                route(state, req)
            });
            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                warn!(error = %err, "control socket connection error");
            }
        });
    }
}

async fn route(
    state: Arc<ControlState>,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody>> {
    match (req.method(), req.uri().path()) {
        (&Method::POST, "/exec") => handle_exec(&state, req).await,
        (&Method::GET, "/list-exec") => handle_list_exec(&state).await,
        (&Method::POST, "/forwards") => handle_create_forward(&state, req).await,
        (&Method::GET, "/forwards") => handle_list_forwards(&state).await,
        (&Method::DELETE, "/forwards") => handle_delete_forward(&state, req).await,
        _ => json_error(StatusCode::NOT_FOUND, "not found"),
    }
}

// --- exec endpoints ---

#[derive(Deserialize)]
struct ExecRequest {
    command: Vec<String>,
    session_id: Option<String>,
    context: Option<String>,
}

async fn handle_exec(
    state: &ControlState,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody>> {
    let body = req
        .into_body()
        .collect()
        .await
        .context("read request body")?
        .to_bytes();
    let exec_req: ExecRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(err) => return json_error(StatusCode::BAD_REQUEST, &format!("invalid json: {err}")),
    };

    if exec_req.command.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "command must not be empty");
    }

    let session_id = exec_req
        .session_id
        .unwrap_or_else(quic::generate_exec_session_id);

    let request = ExecSessionRequest {
        session_id: session_id.clone(),
        argv: Some(exec_req.command),
        context: exec_req.context,
        rendered_bytes: 0,
    };

    let (output_tx, output_rx) = tokio::sync::mpsc::channel::<Bytes>(64);

    // Spawn the QUIC exec session that feeds output into the channel.
    let connections = state.connections.clone();
    let spawn_session_id = session_id.clone();
    tokio::spawn(async move {
        let sid = spawn_session_id;
        match quic::run_exec_streaming_with_reconnect(&connections, request, output_tx).await {
            Ok(exit_code) => {
                info!(session_id = sid, exit_code, "exec session completed");
            }
            Err(err) => {
                warn!(session_id = sid, error = %err, "exec session error");
            }
        }
    });

    // Convert the mpsc receiver into a streaming body.
    let body_stream = tokio_stream::wrappers::ReceiverStream::new(output_rx);
    let stream_body = StreamBody::new(body_stream.map(|chunk| Ok(Frame::data(chunk))));

    let response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/octet-stream")
        .header("x-session-id", &session_id)
        .body(stream_body.boxed())
        .context("build exec response")?;

    Ok(response)
}

async fn handle_list_exec(state: &ControlState) -> Result<Response<BoxBody>> {
    let list = loop {
        let lease = match state.connections.connect().await {
            Ok(lease) => lease,
            Err(err) => {
                return json_error(
                    StatusCode::BAD_GATEWAY,
                    &format!("connect to machine: {err}"),
                )
            }
        };
        let conn = lease.conn();
        let result: Result<ExecSessionList> = async {
            let (mut send, mut recv) = conn.open_bi().await.context("open exec-list stream")?;
            send.write_u8(STREAM_EXEC_LIST)
                .await
                .context("write exec-list tag")?;
            send.finish().context("finish exec-list request")?;
            ExecSessionList::read_from(&mut recv)
                .await
                .context("read exec-list response")
        }
        .await;

        match result {
            Ok(list) => break list,
            Err(err) if crate::console::is_reconnectable_transport(&err) => {
                state.connections.invalidate(lease.generation()).await;
                continue;
            }
            Err(err) => {
                return json_error(StatusCode::BAD_GATEWAY, &format!("{err}"));
            }
        }
    };

    json_response(StatusCode::OK, &list.sessions)
}

// --- forward endpoints ---

#[derive(Deserialize)]
struct CreateForwardRequest {
    spec: String,
}

#[derive(Serialize)]
struct ForwardInfo {
    local_port: u16,
    target: String,
}

async fn handle_create_forward(
    state: &ControlState,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody>> {
    let body = req
        .into_body()
        .collect()
        .await
        .context("read request body")?
        .to_bytes();
    let create_req: CreateForwardRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(err) => return json_error(StatusCode::BAD_REQUEST, &format!("invalid json: {err}")),
    };

    let (local_port, target) = match forward::parse_forward(&create_req.spec) {
        Ok(parsed) => parsed,
        Err(err) => return json_error(StatusCode::BAD_REQUEST, &format!("{err}")),
    };

    let mut forwards = state.forwards.lock().await;
    if forwards.contains_key(&local_port) {
        return json_error(
            StatusCode::CONFLICT,
            &format!("forward on port {local_port} already exists"),
        );
    }

    let listener = match TcpListener::bind(("127.0.0.1", local_port)).await {
        Ok(l) => l,
        Err(err) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                &format!("bind local port {local_port}: {err}"),
            )
        }
    };

    let connections = state.connections.clone();
    let task_target = target.clone();
    let task = tokio::spawn(async move {
        loop {
            let (socket, _) = match listener.accept().await {
                Ok(s) => s,
                Err(err) => {
                    warn!(local_port, error = %err, "forward accept error");
                    break;
                }
            };
            let connections = connections.clone();
            let target = task_target.clone();
            tokio::spawn(async move {
                if let Err(err) =
                    forward::bridge_one_with_reconnect(connections, socket, target).await
                {
                    warn!(local_port, error = %err, "forward bridge error");
                }
            });
        }
    });

    forwards.insert(
        local_port,
        ForwardEntry {
            target: target.clone(),
            task,
        },
    );

    info!(local_port, target, "forward created");
    json_response(StatusCode::OK, &ForwardInfo { local_port, target })
}

async fn handle_list_forwards(state: &ControlState) -> Result<Response<BoxBody>> {
    let forwards = state.forwards.lock().await;
    let mut list: Vec<ForwardInfo> = forwards
        .iter()
        .map(|(&local_port, entry)| ForwardInfo {
            local_port,
            target: entry.target.clone(),
        })
        .collect();
    list.sort_by_key(|f| f.local_port);
    json_response(StatusCode::OK, &list)
}

#[derive(Deserialize)]
struct DeleteForwardRequest {
    local_port: u16,
}

async fn handle_delete_forward(
    state: &ControlState,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody>> {
    let body = req
        .into_body()
        .collect()
        .await
        .context("read request body")?
        .to_bytes();
    let delete_req: DeleteForwardRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(err) => return json_error(StatusCode::BAD_REQUEST, &format!("invalid json: {err}")),
    };

    let mut forwards = state.forwards.lock().await;
    let entry = match forwards.remove(&delete_req.local_port) {
        Some(entry) => entry,
        None => {
            return json_error(
                StatusCode::NOT_FOUND,
                &format!("no forward on port {}", delete_req.local_port),
            )
        }
    };

    entry.task.abort();
    info!(
        local_port = delete_req.local_port,
        target = entry.target,
        "forward deleted"
    );

    json_response(
        StatusCode::OK,
        &ForwardInfo {
            local_port: delete_req.local_port,
            target: entry.target,
        },
    )
}

// --- helpers ---

fn json_response<T: Serialize>(status: StatusCode, value: &T) -> Result<Response<BoxBody>> {
    let body = serde_json::to_vec(value).context("serialize response")?;
    Ok(Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(
            Full::new(Bytes::from(body))
                .map_err(anyhow::Error::from)
                .boxed(),
        )
        .unwrap())
}

fn json_error(status: StatusCode, message: &str) -> Result<Response<BoxBody>> {
    let body = serde_json::json!({ "error": message }).to_string();
    Ok(Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(
            Full::new(Bytes::from(body))
                .map_err(anyhow::Error::from)
                .boxed(),
        )
        .unwrap())
}
