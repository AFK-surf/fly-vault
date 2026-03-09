use anyhow::{anyhow, Context, Result};
use bytes::{Buf, BufMut, BytesMut};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL_VERSION: u16 = 1;
pub const CHANNEL_BINDING_LABEL: &str = "fly-vault-channel-binding";

pub const STREAM_CONTROL: u8 = 0x01;
pub const STREAM_PORT_FORWARD: u8 = 0x02;
pub const STREAM_CONSOLE: u8 = 0x03;
pub const STREAM_EXEC_LIST: u8 = 0x04;

pub const CONTROL_REQUEST_ATTESTATION: u8 = 0x01;
pub const CONTROL_ATTESTATION: u8 = 0x02;
pub const CONTROL_SETUP_REQUEST: u8 = 0x03;
pub const CONTROL_SETUP_COMPLETE: u8 = 0x04;
pub const CONTROL_ERROR: u8 = 0x05;

pub const CONSOLE_DATA: u8 = 0x00;
pub const CONSOLE_RESIZE: u8 = 0x01;
pub const CONSOLE_EXIT: u8 = 0x02;
pub const CONSOLE_SHELL: u8 = 0x03;
pub const CONSOLE_EXEC: u8 = 0x04;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum VmState {
    Cold = 0x00,
    Ready = 0x01,
}

impl VmState {
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0x00 => Ok(Self::Cold),
            0x01 => Ok(Self::Ready),
            _ => Err(anyhow!("invalid vm state: {value}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum RuntimeStatus {
    NotStarted = 0x00,
    SystemInit = 0x01,
    FallbackInit = 0x02,
}

impl RuntimeStatus {
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0x00 => Ok(Self::NotStarted),
            0x01 => Ok(Self::SystemInit),
            0x02 => Ok(Self::FallbackInit),
            _ => Err(anyhow!("invalid runtime status: {value}")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ControlFrame {
    pub ty: u8,
    pub payload: Vec<u8>,
}

impl ControlFrame {
    pub fn new(ty: u8, payload: Vec<u8>) -> Self {
        Self { ty, payload }
    }

    pub async fn read_from<R>(reader: &mut R) -> Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let ty = reader.read_u8().await.context("read control type")?;
        let len = reader
            .read_u32()
            .await
            .context("read control payload length")?;
        let mut payload = vec![0u8; len as usize];
        reader
            .read_exact(&mut payload)
            .await
            .context("read control payload")?;
        Ok(Self { ty, payload })
    }

    pub async fn write_to<W>(&self, writer: &mut W) -> Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        writer
            .write_u8(self.ty)
            .await
            .context("write control type")?;
        writer
            .write_u32(self.payload.len() as u32)
            .await
            .context("write control payload length")?;
        writer
            .write_all(&self.payload)
            .await
            .context("write control payload")?;
        writer.flush().await.context("flush control frame")?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct AttestationPayload {
    pub protocol_version: u16,
    pub state: VmState,
    pub runtime_status: RuntimeStatus,
    pub jwt: String,
}

impl AttestationPayload {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(2 + 1 + 1 + 4 + self.jwt.len());
        out.put_u16(self.protocol_version);
        out.put_u8(self.state as u8);
        out.put_u8(self.runtime_status as u8);
        out.put_u32(self.jwt.len() as u32);
        out.extend_from_slice(self.jwt.as_bytes());
        out.to_vec()
    }

    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self> {
        if bytes.remaining() < 8 {
            return Err(anyhow!("attestation payload too short"));
        }
        let protocol_version = bytes.get_u16();
        let state = VmState::from_u8(bytes.get_u8())?;
        let runtime_status = RuntimeStatus::from_u8(bytes.get_u8())?;
        let jwt_len = bytes.get_u32() as usize;
        if bytes.remaining() != jwt_len {
            return Err(anyhow!(
                "attestation payload length mismatch: expected {jwt_len}, got {}",
                bytes.remaining()
            ));
        }
        let jwt = String::from_utf8(bytes.to_vec()).context("attestation jwt not utf-8")?;
        Ok(Self {
            protocol_version,
            state,
            runtime_status,
            jwt,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootfsSource {
    None,
    Inline(Vec<u8>),
    Url(String),
}

impl RootfsSource {
    fn encode(&self, out: &mut BytesMut) {
        match self {
            Self::None => out.put_u8(0x00),
            Self::Inline(data) => {
                out.put_u8(0x01);
                out.put_u32(data.len() as u32);
                out.extend_from_slice(data);
            }
            Self::Url(url) => {
                out.put_u8(0x02);
                out.put_u32(url.len() as u32);
                out.extend_from_slice(url.as_bytes());
            }
        }
    }

    fn decode(bytes: &mut &[u8]) -> Result<Self> {
        if !bytes.has_remaining() {
            return Err(anyhow!("rootfs source payload too short"));
        }
        match bytes.get_u8() {
            0x00 => Ok(Self::None),
            0x01 => {
                let payload = take_len_prefixed(bytes, "inline rootfs")?;
                Ok(Self::Inline(payload.to_vec()))
            }
            0x02 => {
                let payload = take_len_prefixed(bytes, "rootfs url")?;
                let url = String::from_utf8(payload.to_vec()).context("rootfs url not utf-8")?;
                Ok(Self::Url(url))
            }
            kind => Err(anyhow!("invalid rootfs source kind: {kind}")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SetupRequest {
    pub access_token: String,
    pub rootfs: RootfsSource,
}

impl SetupRequest {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(4 + self.access_token.len() + 8);
        out.put_u32(self.access_token.len() as u32);
        out.extend_from_slice(self.access_token.as_bytes());
        self.rootfs.encode(&mut out);
        out.to_vec()
    }

    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self> {
        let token = take_len_prefixed(&mut bytes, "access token")?;
        let access_token =
            String::from_utf8(token.to_vec()).context("setup access token not utf-8")?;
        let rootfs = RootfsSource::decode(&mut bytes)?;
        if bytes.has_remaining() {
            return Err(anyhow!("setup request payload has trailing bytes"));
        }
        Ok(Self {
            access_token,
            rootfs,
        })
    }
}

#[derive(Debug, Clone)]
pub enum ControlMessage {
    RequestAttestation,
    Attestation(AttestationPayload),
    SetupRequest(SetupRequest),
    SetupComplete,
    Error(String),
}

impl ControlMessage {
    pub async fn read_from<R>(reader: &mut R) -> Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let frame = ControlFrame::read_from(reader).await?;
        Self::from_frame(frame)
    }

    pub async fn write_to<W>(&self, writer: &mut W) -> Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        self.to_frame().write_to(writer).await
    }

    pub fn from_frame(frame: ControlFrame) -> Result<Self> {
        match frame.ty {
            CONTROL_REQUEST_ATTESTATION => {
                if !frame.payload.is_empty() {
                    return Err(anyhow!("request attestation frame must be empty"));
                }
                Ok(Self::RequestAttestation)
            }
            CONTROL_ATTESTATION => Ok(Self::Attestation(AttestationPayload::from_bytes(
                &frame.payload,
            )?)),
            CONTROL_SETUP_REQUEST => Ok(Self::SetupRequest(SetupRequest::from_bytes(
                &frame.payload,
            )?)),
            CONTROL_SETUP_COMPLETE => {
                if !frame.payload.is_empty() {
                    return Err(anyhow!("setup complete frame must be empty"));
                }
                Ok(Self::SetupComplete)
            }
            CONTROL_ERROR => Ok(Self::Error(
                String::from_utf8(frame.payload).context("control error not utf-8")?,
            )),
            other => Err(anyhow!("unknown control type: {other}")),
        }
    }

    pub fn to_frame(&self) -> ControlFrame {
        match self {
            Self::RequestAttestation => ControlFrame::new(CONTROL_REQUEST_ATTESTATION, vec![]),
            Self::Attestation(payload) => {
                ControlFrame::new(CONTROL_ATTESTATION, payload.to_bytes())
            }
            Self::SetupRequest(payload) => {
                ControlFrame::new(CONTROL_SETUP_REQUEST, payload.to_bytes())
            }
            Self::SetupComplete => ControlFrame::new(CONTROL_SETUP_COMPLETE, vec![]),
            Self::Error(message) => ControlFrame::new(CONTROL_ERROR, message.as_bytes().to_vec()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConsoleFrame {
    pub ty: u8,
    pub payload: Vec<u8>,
}

impl ConsoleFrame {
    pub fn new(ty: u8, payload: Vec<u8>) -> Self {
        Self { ty, payload }
    }

    pub async fn read_from<R>(reader: &mut R) -> Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let ty = reader.read_u8().await.context("read console type")?;
        let len = reader
            .read_u32()
            .await
            .context("read console payload length")?;
        let mut payload = vec![0u8; len as usize];
        reader
            .read_exact(&mut payload)
            .await
            .context("read console payload")?;
        Ok(Self { ty, payload })
    }

    pub async fn write_to<W>(&self, writer: &mut W) -> Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        writer
            .write_u8(self.ty)
            .await
            .context("write console type")?;
        writer
            .write_u32(self.payload.len() as u32)
            .await
            .context("write console payload length")?;
        writer
            .write_all(&self.payload)
            .await
            .context("write console payload")?;
        writer.flush().await.context("flush console frame")?;
        Ok(())
    }
}

pub fn encode_resize(rows: u16, cols: u16) -> [u8; 4] {
    let mut out = [0u8; 4];
    out[..2].copy_from_slice(&rows.to_be_bytes());
    out[2..].copy_from_slice(&cols.to_be_bytes());
    out
}

pub fn decode_resize(data: &[u8]) -> Result<(u16, u16)> {
    if data.len() != 4 {
        return Err(anyhow!("invalid resize payload length: {}", data.len()));
    }
    let rows = u16::from_be_bytes([data[0], data[1]]);
    let cols = u16::from_be_bytes([data[2], data[3]]);
    Ok((rows, cols))
}

pub fn encode_exit(exit_code: u32) -> [u8; 4] {
    exit_code.to_be_bytes()
}

pub fn decode_exit(data: &[u8]) -> Result<u32> {
    if data.len() != 4 {
        return Err(anyhow!("invalid exit payload length: {}", data.len()));
    }
    Ok(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
}

pub fn encode_exec_argv(argv: &[String]) -> Vec<u8> {
    let mut out = BytesMut::new();
    out.put_u32(argv.len() as u32);
    for arg in argv {
        out.put_u32(arg.len() as u32);
        out.extend_from_slice(arg.as_bytes());
    }
    out.to_vec()
}

pub fn decode_exec_argv(mut data: &[u8]) -> Result<Vec<String>> {
    if data.remaining() < 4 {
        return Err(anyhow!("exec argv payload too short"));
    }

    let argc = data.get_u32() as usize;
    let mut argv = Vec::with_capacity(argc);
    for _ in 0..argc {
        if data.remaining() < 4 {
            return Err(anyhow!("exec argv length prefix truncated"));
        }
        let len = data.get_u32() as usize;
        if data.remaining() < len {
            return Err(anyhow!("exec argv element truncated"));
        }
        let arg = String::from_utf8(data[..len].to_vec()).context("exec argv not utf-8")?;
        data.advance(len);
        argv.push(arg);
    }

    if data.has_remaining() {
        return Err(anyhow!("exec argv payload has trailing bytes"));
    }

    Ok(argv)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedConsoleRequest {
    pub rendered_bytes: u64,
}

impl SharedConsoleRequest {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.rendered_bytes.to_be_bytes().to_vec()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        match data.len() {
            0 => Ok(Self { rendered_bytes: 0 }),
            8 => Ok(Self {
                rendered_bytes: u64::from_be_bytes(data.try_into().unwrap()),
            }),
            len => Err(anyhow!("invalid shared console payload length: {len}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecSessionRequest {
    pub session_id: String,
    pub argv: Option<Vec<String>>,
    pub context: Option<String>,
    pub rendered_bytes: u64,
}

impl ExecSessionRequest {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = BytesMut::new();
        out.put_u32(self.session_id.len() as u32);
        out.extend_from_slice(self.session_id.as_bytes());
        match &self.argv {
            Some(argv) => {
                out.put_u8(1);
                let argv = encode_exec_argv(argv);
                out.put_u32(argv.len() as u32);
                out.extend_from_slice(&argv);
            }
            None => out.put_u8(0),
        }
        match &self.context {
            Some(context) => {
                out.put_u8(1);
                out.put_u32(context.len() as u32);
                out.extend_from_slice(context.as_bytes());
            }
            None => out.put_u8(0),
        }
        out.put_u64(self.rendered_bytes);
        out.to_vec()
    }

    pub fn from_bytes(mut data: &[u8]) -> Result<Self> {
        let session_id = take_len_prefixed(&mut data, "exec session id")?;
        let session_id =
            String::from_utf8(session_id.to_vec()).context("exec session id not utf-8")?;
        if session_id.is_empty() {
            return Err(anyhow!("exec session id must not be empty"));
        }
        if !data.has_remaining() {
            return Err(anyhow!("exec session payload missing argv flag"));
        }
        let has_argv = data.get_u8();
        let argv = match has_argv {
            0 => None,
            1 => {
                let argv = take_len_prefixed(&mut data, "exec session argv")?;
                Some(decode_exec_argv(argv)?)
            }
            other => return Err(anyhow!("invalid exec session argv flag: {other}")),
        };
        if !data.has_remaining() {
            return Ok(Self {
                session_id,
                argv,
                context: None,
                rendered_bytes: 0,
            });
        }
        let has_context = data.get_u8();
        let context = match has_context {
            0 => None,
            1 => {
                let payload = take_len_prefixed(&mut data, "exec session context")?;
                Some(
                    String::from_utf8(payload.to_vec())
                        .context("exec session context not utf-8")?,
                )
            }
            other => return Err(anyhow!("invalid exec session context flag: {other}")),
        };
        let rendered_bytes = match data.remaining() {
            0 => 0,
            8 => data.get_u64(),
            other => {
                return Err(anyhow!(
                    "exec session payload has invalid rendered byte length: {other}"
                ));
            }
        };
        Ok(Self {
            session_id,
            argv,
            context,
            rendered_bytes,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecSessionInfo {
    pub session_id: String,
    pub argv: Vec<String>,
    pub context: Option<String>,
    pub attached: bool,
    pub exit_code: Option<u32>,
}

impl ExecSessionInfo {
    fn encode(&self, out: &mut BytesMut) {
        out.put_u32(self.session_id.len() as u32);
        out.extend_from_slice(self.session_id.as_bytes());
        out.put_u8(u8::from(self.attached));
        match self.exit_code {
            Some(code) => {
                out.put_u8(1);
                out.put_u32(code);
            }
            None => out.put_u8(0),
        }
        let argv = encode_exec_argv(&self.argv);
        out.put_u32(argv.len() as u32);
        out.extend_from_slice(&argv);
        match &self.context {
            Some(context) => {
                out.put_u8(1);
                out.put_u32(context.len() as u32);
                out.extend_from_slice(context.as_bytes());
            }
            None => out.put_u8(0),
        }
    }

    fn decode(data: &mut &[u8]) -> Result<Self> {
        let session_id = take_len_prefixed(data, "exec session info id")?;
        let session_id =
            String::from_utf8(session_id.to_vec()).context("exec session info id not utf-8")?;
        if session_id.is_empty() {
            return Err(anyhow!("exec session info id must not be empty"));
        }
        if data.remaining() < 2 {
            return Err(anyhow!("exec session info payload too short"));
        }
        let attached = match data.get_u8() {
            0 => false,
            1 => true,
            other => return Err(anyhow!("invalid exec session attached flag: {other}")),
        };
        let exit_code = match data.get_u8() {
            0 => None,
            1 => {
                if data.remaining() < 4 {
                    return Err(anyhow!("exec session exit code truncated"));
                }
                Some(data.get_u32())
            }
            other => return Err(anyhow!("invalid exec session exit flag: {other}")),
        };
        let argv = take_len_prefixed(data, "exec session argv")?;
        let argv = decode_exec_argv(argv)?;
        if !data.has_remaining() {
            return Ok(Self {
                session_id,
                argv,
                context: None,
                attached,
                exit_code,
            });
        }
        let context = match data.get_u8() {
            0 => None,
            1 => {
                let payload = take_len_prefixed(data, "exec session context")?;
                Some(
                    String::from_utf8(payload.to_vec())
                        .context("exec session context not utf-8")?,
                )
            }
            other => return Err(anyhow!("invalid exec session context flag: {other}")),
        };
        Ok(Self {
            session_id,
            argv,
            context,
            attached,
            exit_code,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecSessionList {
    pub sessions: Vec<ExecSessionInfo>,
}

impl ExecSessionList {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = BytesMut::new();
        out.put_u32(self.sessions.len() as u32);
        for session in &self.sessions {
            session.encode(&mut out);
        }
        out.to_vec()
    }

    pub fn from_bytes(mut data: &[u8]) -> Result<Self> {
        if data.remaining() < 4 {
            return Err(anyhow!("exec session list payload too short"));
        }
        let count = data.get_u32() as usize;
        let mut sessions = Vec::with_capacity(count);
        for _ in 0..count {
            sessions.push(ExecSessionInfo::decode(&mut data)?);
        }
        if data.has_remaining() {
            return Err(anyhow!("exec session list payload has trailing bytes"));
        }
        Ok(Self { sessions })
    }

    pub async fn read_from<R>(reader: &mut R) -> Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let len = reader
            .read_u32()
            .await
            .context("read exec session list length")?;
        let mut payload = vec![0u8; len as usize];
        reader
            .read_exact(&mut payload)
            .await
            .context("read exec session list payload")?;
        Self::from_bytes(&payload)
    }

    pub async fn write_to<W>(&self, writer: &mut W) -> Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let payload = self.to_bytes();
        writer
            .write_u32(payload.len() as u32)
            .await
            .context("write exec session list length")?;
        writer
            .write_all(&payload)
            .await
            .context("write exec session list payload")?;
        writer.flush().await.context("flush exec session list")?;
        Ok(())
    }
}

pub fn encode_proxy_machine_header(machine_id: &str) -> Result<Vec<u8>> {
    if machine_id.is_empty() {
        return Err(anyhow!("machine_id must not be empty"));
    }

    let machine_id = machine_id.as_bytes();
    let mut out = Vec::with_capacity(8 + machine_id.len());
    out.extend_from_slice(&(machine_id.len() as u64).to_le_bytes());
    out.extend_from_slice(machine_id);
    Ok(out)
}

pub struct ProxyPacket<'a> {
    pub machine_id: &'a str,
    pub payload: &'a [u8],
}

pub fn decode_proxy_packet(packet: &[u8]) -> Result<ProxyPacket<'_>> {
    if packet.len() < 8 {
        return Err(anyhow!("packet too short for proxy header"));
    }

    let id_len = u64::from_le_bytes(packet[..8].try_into().unwrap()) as usize;
    if id_len == 0 {
        return Err(anyhow!("proxy machine id must not be empty"));
    }
    if packet.len() < 8 + id_len {
        return Err(anyhow!("packet too short for proxy machine id"));
    }

    let machine_id =
        std::str::from_utf8(&packet[8..8 + id_len]).context("proxy machine id not utf-8")?;
    let payload = &packet[8 + id_len..];
    if payload.is_empty() {
        return Err(anyhow!("proxy packet payload must not be empty"));
    }

    Ok(ProxyPacket {
        machine_id,
        payload,
    })
}

fn take_len_prefixed<'a>(bytes: &mut &'a [u8], label: &str) -> Result<&'a [u8]> {
    if bytes.remaining() < 4 {
        return Err(anyhow!("{label} length prefix truncated"));
    }
    let len = bytes.get_u32() as usize;
    if bytes.remaining() < len {
        return Err(anyhow!("{label} payload truncated"));
    }
    let payload = &bytes[..len];
    bytes.advance(len);
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::{
        decode_exec_argv, decode_proxy_packet, encode_exec_argv, encode_proxy_machine_header,
        AttestationPayload, ExecSessionInfo, ExecSessionList, ExecSessionRequest, RootfsSource,
        RuntimeStatus, SetupRequest, SharedConsoleRequest, VmState, PROTOCOL_VERSION,
    };

    #[test]
    fn exec_argv_round_trips() {
        let argv = vec!["ls".to_string(), "-lash".to_string(), "/".to_string()];
        let encoded = encode_exec_argv(&argv);
        assert_eq!(decode_exec_argv(&encoded).unwrap(), argv);
    }

    #[test]
    fn exec_argv_rejects_truncated_payload() {
        let err = decode_exec_argv(&[0, 0, 0, 1, 0, 0, 0]).unwrap_err();
        assert!(err.to_string().contains("length prefix truncated"));
    }

    #[test]
    fn attestation_payload_round_trips() {
        let payload = AttestationPayload {
            protocol_version: PROTOCOL_VERSION,
            state: VmState::Ready,
            runtime_status: RuntimeStatus::SystemInit,
            jwt: "jwt".to_string(),
        };

        let decoded = AttestationPayload::from_bytes(&payload.to_bytes()).unwrap();
        assert_eq!(decoded.protocol_version, PROTOCOL_VERSION);
        assert_eq!(decoded.state, VmState::Ready);
        assert_eq!(decoded.runtime_status, RuntimeStatus::SystemInit);
        assert_eq!(decoded.jwt, "jwt");
    }

    #[test]
    fn setup_request_round_trips() {
        let request = SetupRequest {
            access_token: "secret".to_string(),
            rootfs: RootfsSource::Url("https://example.com/rootfs.tar.gz".to_string()),
        };

        let decoded = SetupRequest::from_bytes(&request.to_bytes()).unwrap();
        assert_eq!(decoded.access_token, "secret");
        assert_eq!(
            decoded.rootfs,
            RootfsSource::Url("https://example.com/rootfs.tar.gz".to_string())
        );
    }

    #[test]
    fn proxy_header_round_trips() {
        let mut packet = encode_proxy_machine_header("machine-123").unwrap();
        packet.extend_from_slice(b"payload");
        let decoded = decode_proxy_packet(&packet).unwrap();
        assert_eq!(decoded.machine_id, "machine-123");
        assert_eq!(decoded.payload, b"payload");
    }

    #[test]
    fn exec_session_request_round_trips() {
        let request = ExecSessionRequest {
            session_id: "sess-123".to_string(),
            argv: Some(vec!["ls".to_string(), "-l".to_string()]),
            context: Some("investigate deploy failure".to_string()),
            rendered_bytes: 4096,
        };
        assert_eq!(
            ExecSessionRequest::from_bytes(&request.to_bytes()).unwrap(),
            request
        );
    }

    #[test]
    fn shared_console_request_round_trips() {
        let request = SharedConsoleRequest {
            rendered_bytes: 8192,
        };
        assert_eq!(
            SharedConsoleRequest::from_bytes(&request.to_bytes()).unwrap(),
            request
        );
        assert_eq!(
            SharedConsoleRequest::from_bytes(&[]).unwrap(),
            SharedConsoleRequest { rendered_bytes: 0 }
        );
    }

    #[test]
    fn exec_session_list_round_trips() {
        let list = ExecSessionList {
            sessions: vec![
                ExecSessionInfo {
                    session_id: "sess-running".to_string(),
                    argv: vec!["bash".to_string()],
                    context: Some("live debugging".to_string()),
                    attached: true,
                    exit_code: None,
                },
                ExecSessionInfo {
                    session_id: "sess-exited".to_string(),
                    argv: vec!["echo".to_string(), "hi".to_string()],
                    context: None,
                    attached: false,
                    exit_code: Some(7),
                },
            ],
        };
        assert_eq!(ExecSessionList::from_bytes(&list.to_bytes()).unwrap(), list);
    }
}
