use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use std::io;
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

#[derive(Debug)]
pub struct ProxyUdpSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    machine_header: Vec<u8>,
}

impl ProxyUdpSocket {
    pub fn new(inner: Arc<dyn AsyncUdpSocket>, machine_id: String) -> io::Result<Self> {
        if machine_id.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "machine_id must not be empty",
            ));
        }

        let machine_header = encode_machine_header(machine_id.as_bytes());
        Ok(Self {
            inner,
            machine_header,
        })
    }

    fn prepend_machine_header(&self, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.machine_header.len() + payload.len());
        out.extend_from_slice(&self.machine_header);
        out.extend_from_slice(payload);
        out
    }
}

impl AsyncUdpSocket for ProxyUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // quinn only supplies segmented transmits when a packet contains multiple datagrams,
        // which this proxy mode does not support because each datagram needs its own header.
        if transmit.segment_size.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "segmented transmits are unsupported in proxy mode",
            ));
        }

        let packet = self.prepend_machine_header(transmit.contents);
        let wrapped = Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &packet,
            segment_size: None,
            src_ip: transmit.src_ip,
        };
        self.inner.try_send(&wrapped)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

pub fn encode_machine_header(machine_id: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + machine_id.len());
    out.extend_from_slice(&(machine_id.len() as u64).to_le_bytes());
    out.extend_from_slice(machine_id);
    out
}

#[cfg(test)]
#[derive(Debug)]
struct RecordingUdpSocket {
    sent: std::sync::Mutex<Vec<Vec<u8>>>,
}

#[cfg(test)]
impl RecordingUdpSocket {
    fn take_sent(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut *self.sent.lock().unwrap())
    }

    fn new() -> Self {
        Self {
            sent: std::sync::Mutex::new(Vec::new()),
        }
    }
}

#[cfg(test)]
impl AsyncUdpSocket for RecordingUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        struct ReadyPoller;
        impl std::fmt::Debug for ReadyPoller {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("ReadyPoller").finish()
            }
        }
        impl UdpPoller for ReadyPoller {
            fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let _ = self;
        Box::pin(ReadyPoller)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.sent.lock().unwrap().push(transmit.contents.to_vec());
        Ok(())
    }

    fn poll_recv(
        &self,
        _cx: &mut Context,
        _bufs: &mut [IoSliceMut<'_>],
        _meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::new(io::ErrorKind::WouldBlock, "no data")))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        "[::]:0".parse::<SocketAddr>().map_err(io::Error::other)
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn::udp::EcnCodepoint;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn encode_machine_header_uses_little_endian_len() {
        let machine_id = b"machine-123";
        let header = encode_machine_header(machine_id);

        assert_eq!(
            &header[..8],
            (machine_id.len() as u64).to_le_bytes().as_slice()
        );
        assert_eq!(&header[8..], machine_id);
    }

    #[test]
    fn proxy_udp_socket_prepends_header() {
        let inner = Arc::new(RecordingUdpSocket::new());
        let socket = ProxyUdpSocket::new(inner.clone(), "machine-xyz".to_string()).unwrap();

        let payload = b"quic-packet";
        let transmit = Transmit {
            destination: SocketAddr::from(([127, 0, 0, 1], 8443)),
            ecn: Some(EcnCodepoint::Ect0),
            contents: payload,
            segment_size: None,
            src_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        };

        socket.try_send(&transmit).unwrap();

        let sent = inner.take_sent();
        assert_eq!(sent.len(), 1);

        let expected_header = encode_machine_header(b"machine-xyz");
        assert_eq!(
            &sent[0][..expected_header.len()],
            expected_header.as_slice()
        );
        assert_eq!(&sent[0][expected_header.len()..], payload);
    }

    #[test]
    fn proxy_udp_socket_rejects_empty_machine_id() {
        let inner = Arc::new(RecordingUdpSocket::new());
        let err = ProxyUdpSocket::new(inner, String::new()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn proxy_udp_socket_rejects_segmented_transmit() {
        let inner = Arc::new(RecordingUdpSocket::new());
        let socket = ProxyUdpSocket::new(inner, "machine-abc".to_string()).unwrap();

        let payload = b"abc";
        let transmit = Transmit {
            destination: SocketAddr::from(([127, 0, 0, 1], 8443)),
            ecn: None,
            contents: payload,
            segment_size: Some(1200),
            src_ip: None,
        };

        let err = socket.try_send(&transmit).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
