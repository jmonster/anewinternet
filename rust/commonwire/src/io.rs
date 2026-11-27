//! The glue hyper needs on tokio: I/O in both directions, an executor, a timer, and a whole-body type.
use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};

/// Wraps a tokio stream as hyper I/O, or hyper I/O (an upgraded connection) as a tokio stream.
pub struct Io<T>(pub T);

impl<T: tokio::io::AsyncRead + Unpin> hyper::rt::Read for Io<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let n = unsafe {
            let mut tbuf = tokio::io::ReadBuf::uninit(buf.as_mut());
            match tokio::io::AsyncRead::poll_read(Pin::new(&mut self.get_mut().0), cx, &mut tbuf) {
                Poll::Ready(Ok(())) => tbuf.filled().len(),
                other => return other,
            }
        };
        unsafe { buf.advance(n) };
        Poll::Ready(Ok(()))
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> hyper::rt::Write for Io<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(Pin::new(&mut self.get_mut().0), cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().0), cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().0), cx)
    }
    fn is_write_vectored(&self) -> bool {
        tokio::io::AsyncWrite::is_write_vectored(&self.0)
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write_vectored(Pin::new(&mut self.get_mut().0), cx, bufs)
    }
}

/// An upgraded hyper connection as a tokio stream.
pub struct Upgraded(pub hyper::upgrade::Upgraded);

impl tokio::io::AsyncRead for Upgraded {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        tbuf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let filled = tbuf.filled().len();
        let added = unsafe {
            let mut buf = hyper::rt::ReadBuf::uninit(tbuf.unfilled_mut());
            match hyper::rt::Read::poll_read(Pin::new(&mut self.get_mut().0), cx, buf.unfilled()) {
                Poll::Ready(Ok(())) => buf.filled().len(),
                other => return other,
            }
        };
        unsafe {
            tbuf.assume_init(added);
            tbuf.set_filled(filled + added);
        }
        Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for Upgraded {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        hyper::rt::Write::poll_write(Pin::new(&mut self.get_mut().0), cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        hyper::rt::Write::poll_flush(Pin::new(&mut self.get_mut().0), cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        hyper::rt::Write::poll_shutdown(Pin::new(&mut self.get_mut().0), cx)
    }
}

#[derive(Clone, Copy)]
pub struct Exec;

impl<F> hyper::rt::Executor<F> for Exec
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, fut: F) {
        tokio::spawn(fut);
    }
}

#[derive(Clone, Copy)]
pub struct Timer;

struct Sleep(Pin<Box<tokio::time::Sleep>>);

impl Future for Sleep {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        self.0.as_mut().poll(cx)
    }
}

impl hyper::rt::Sleep for Sleep {}

impl hyper::rt::Timer for Timer {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn hyper::rt::Sleep>> {
        Box::pin(Sleep(Box::pin(tokio::time::sleep(duration))))
    }
    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn hyper::rt::Sleep>> {
        Box::pin(Sleep(Box::pin(tokio::time::sleep_until(deadline.into()))))
    }
}

/// A body sent in one piece.
pub struct Full(Option<Bytes>);

impl Full {
    pub fn new(bytes: Vec<u8>) -> Self {
        Full(Some(Bytes::from(bytes)))
    }
}

impl Body for Full {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        Poll::Ready(self.get_mut().0.take().filter(|b| !b.is_empty()).map(|b| Ok(Frame::data(b))))
    }
    fn is_end_stream(&self) -> bool {
        self.0.as_ref().is_none_or(|b| b.is_empty())
    }
    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.0.as_ref().map_or(0, |b| b.len() as u64))
    }
}

/// Reads a whole body, refusing more than `limit` bytes.
pub async fn collect<B: Body<Data = Bytes> + Unpin>(mut body: B, limit: usize) -> Result<Vec<u8>, ()> {
    let mut out = Vec::new();
    while let Some(frame) = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
        let frame = frame.map_err(|_| ())?;
        if let Ok(data) = frame.into_data() {
            if out.len() + data.len() > limit {
                return Err(());
            }
            out.extend_from_slice(&data);
        }
    }
    Ok(out)
}
