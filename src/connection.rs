use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
#[cfg(feature = "ftps")]
use tokio_rustls::client::TlsStream;
use pin_project::pin_project;

#[pin_project(project = ConnectionProj)]
pub enum Connection {
    Tcp(#[pin] TcpStream),
    #[cfg(feature = "ftps")]
    Ssl(#[pin] TlsStream<TcpStream>),
}

impl Connection {
    /// Unwrap the stream into TcpStream. This method is only used in secure connection.
    pub fn into_tcp_stream(self) -> TcpStream {
        match self {
            Connection::Tcp(stream) => stream,
            #[cfg(feature = "ftps")]
            Connection::Ssl(stream) => stream.into_inner().0,
        }
    }

    /// Test if the stream is secured
    pub fn is_ssl(&self) -> bool {
        match self {
            #[cfg(feature = "ftps")]
            Connection::Ssl(_) => true,
            _ => false,
        }
    }

    /// Returns a reference to the underlying TcpStream.
    pub fn get_ref(&self) -> &TcpStream {
        match self {
            Connection::Tcp(ref stream) => stream,
            #[cfg(feature = "ftps")]
            Connection::Ssl(ref stream) => stream.get_ref().0,
        }
    }
}

impl AsyncRead for Connection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.project() {
            ConnectionProj::Tcp(stream) => stream.poll_read(cx, buf),
            #[cfg(feature = "ftps")]
            ConnectionProj::Ssl(stream) => stream.poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Connection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.project() {
            ConnectionProj::Tcp(stream) => stream.poll_write(cx, buf),
            #[cfg(feature = "ftps")]
            ConnectionProj::Ssl(stream) => stream.poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            ConnectionProj::Tcp(stream) => stream.poll_flush(cx),
            #[cfg(feature = "ftps")]
            ConnectionProj::Ssl(stream) => stream.poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            ConnectionProj::Tcp(stream) => stream.poll_shutdown(cx),
            #[cfg(feature = "ftps")]
            ConnectionProj::Ssl(stream) => stream.poll_shutdown(cx),
        }
    }
}
