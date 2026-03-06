use anyhow::{anyhow, Context, Result};
use bytes::{Buf, BufMut, BytesMut};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const STREAM_CONTROL: u8 = 0x01;
pub const STREAM_PORT_FORWARD: u8 = 0x02;
pub const STREAM_CONSOLE: u8 = 0x03;

pub const CONTROL_REQUEST_ATTESTATION: u8 = 0x01;
pub const CONTROL_ATTESTATION: u8 = 0x02;
pub const CONTROL_PROVISION_ROOTFS: u8 = 0x04;
pub const CONTROL_SETUP_COMPLETE: u8 = 0x05;
pub const CONTROL_ERROR: u8 = 0x06;
pub const CONTROL_ACCESS_TOKEN: u8 = 0x07;
pub const CONTROL_PROVISION_ROOTFS_URL: u8 = 0x08;

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
            0x01 | 0x02 => Ok(Self::Ready),
            _ => Err(anyhow!("invalid vm state: {value}")),
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
    pub state: VmState,
    pub jwt: String,
}

impl AttestationPayload {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(1 + 4 + self.jwt.len());
        out.put_u8(self.state as u8);
        out.put_u32(self.jwt.len() as u32);
        out.extend_from_slice(self.jwt.as_bytes());
        out.to_vec()
    }

    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self> {
        if bytes.remaining() < 5 {
            return Err(anyhow!("attestation payload too short"));
        }
        let state = VmState::from_u8(bytes.get_u8())?;
        let jwt_len = bytes.get_u32() as usize;
        if bytes.remaining() != jwt_len {
            return Err(anyhow!(
                "attestation payload length mismatch: expected {jwt_len}, got {}",
                bytes.remaining()
            ));
        }
        let jwt = String::from_utf8(bytes.to_vec()).context("attestation jwt not utf-8")?;
        Ok(Self { state, jwt })
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

#[cfg(test)]
mod tests {
    use super::{decode_exec_argv, encode_exec_argv};

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
}
