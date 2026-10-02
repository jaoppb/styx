//! Length-prefixed TCP message framing written without an intermediate framed copy.

use std::io::{ErrorKind, IoSlice};

use thiserror::Error;
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Errors writing a length-prefixed DNS message to a stream.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FrameWriteError {
    /// The body does not fit the two-octet length prefix.
    #[error("tcp frame body of {length} octets exceeds 65535")]
    BodyTooLong {
        /// The offending body length in octets.
        length: usize,
    },

    /// The underlying writer failed, accepted no bytes, or over-reported progress.
    #[error("tcp frame write failed: {0}")]
    Io(ErrorKind),
}

/// Writes `body` to `writer` preceded by its two-octet big-endian length.
///
/// The prefix and the body are sent as two vectored slices, so no framed copy of the
/// message is built.
///
/// # Errors
///
/// Returns [`FrameWriteError::BodyTooLong`] if `body` exceeds 65535 octets, and
/// [`FrameWriteError::Io`] if the writer errors, accepts zero bytes (`WriteZero`), or
/// reports more bytes written than were offered (`InvalidData`).
pub async fn write_framed<W: AsyncWrite + Unpin>(
    writer: &mut W,
    body: &[u8],
) -> Result<(), FrameWriteError> {
    let length = u16::try_from(body.len())
        .map_err(|_| FrameWriteError::BodyTooLong { length: body.len() })?;
    let prefix = length.to_be_bytes();
    let mut slices = [IoSlice::new(&prefix), IoSlice::new(body)];
    let mut remaining: &mut [IoSlice<'_>] = &mut slices;

    while !remaining.is_empty() {
        let offered = remaining
            .iter()
            .fold(0usize, |total, slice| total.saturating_add(slice.len()));
        let written = writer
            .write_vectored(&*remaining)
            .await
            .map_err(|error| FrameWriteError::Io(error.kind()))?;
        if written == 0 {
            return Err(FrameWriteError::Io(ErrorKind::WriteZero));
        }
        if written > offered {
            return Err(FrameWriteError::Io(ErrorKind::InvalidData));
        }
        IoSlice::advance_slices(&mut remaining, written);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use super::*;

    /// Records written bytes, accepting at most `per_call` octets per poll.
    struct Recorder {
        data: Vec<u8>,
        per_call: usize,
    }

    impl AsyncWrite for Recorder {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let take = buf.len().min(self.per_call);
            let chunk = buf.get(..take).unwrap_or_default();
            self.data.extend_from_slice(chunk);
            Poll::Ready(Ok(take))
        }

        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            let mut budget = self.per_call;
            let mut taken = 0usize;
            for slice in bufs {
                let take = slice.len().min(budget);
                let chunk = slice.get(..take).unwrap_or_default();
                self.data.extend_from_slice(chunk);
                taken = taken.saturating_add(take);
                budget = budget.saturating_sub(take);
            }
            Poll::Ready(Ok(taken))
        }

        fn is_write_vectored(&self) -> bool {
            true
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Reports a scripted result for every vectored write.
    enum Scripted {
        Zero,
        Failure,
        OverReport,
    }

    impl AsyncWrite for Scripted {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(0))
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            let offered = bufs
                .iter()
                .fold(0usize, |total, slice| total.saturating_add(slice.len()));
            Poll::Ready(match *self {
                Self::Zero => Ok(0),
                Self::Failure => Err(io::Error::from(ErrorKind::BrokenPipe)),
                Self::OverReport => Ok(offered.saturating_add(1)),
            })
        }

        fn is_write_vectored(&self) -> bool {
            true
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn recorder(per_call: usize) -> Recorder {
        Recorder {
            data: Vec::new(),
            per_call,
        }
    }

    #[tokio::test]
    async fn writes_prefix_then_body_in_order() {
        let mut writer = recorder(usize::MAX);
        write_framed(&mut writer, b"hello").await.expect("write");
        assert_eq!(writer.data, [0, 5, b'h', b'e', b'l', b'l', b'o']);
    }

    #[tokio::test]
    async fn survives_one_byte_partial_writes() {
        let mut writer = recorder(1);
        write_framed(&mut writer, b"partial").await.expect("write");
        assert_eq!(writer.data, [&[0u8, 7][..], b"partial"].concat());
    }

    #[tokio::test]
    async fn empty_body_writes_only_the_prefix() {
        let mut writer = recorder(usize::MAX);
        write_framed(&mut writer, b"").await.expect("write");
        assert_eq!(writer.data, [0, 0]);
    }

    #[tokio::test]
    async fn accepts_a_body_of_exactly_65535_octets() {
        let body = vec![7u8; 65535];
        let mut writer = recorder(usize::MAX);
        write_framed(&mut writer, &body).await.expect("write");
        assert_eq!(writer.data.get(..2), Some(&[0xFF, 0xFF][..]));
        assert_eq!(writer.data.len(), 65537);
    }

    #[tokio::test]
    async fn rejects_a_body_of_65536_octets() {
        let body = vec![7u8; 65536];
        let mut writer = recorder(usize::MAX);
        let error = write_framed(&mut writer, &body).await.unwrap_err();
        assert_eq!(error, FrameWriteError::BodyTooLong { length: 65536 });
        assert!(writer.data.is_empty());
    }

    #[tokio::test]
    async fn zero_length_write_is_write_zero_error() {
        let error = write_framed(&mut Scripted::Zero, b"x").await.unwrap_err();
        assert_eq!(error, FrameWriteError::Io(ErrorKind::WriteZero));
    }

    #[tokio::test]
    async fn writer_error_is_propagated_as_io() {
        let error = write_framed(&mut Scripted::Failure, b"x")
            .await
            .unwrap_err();
        assert_eq!(error, FrameWriteError::Io(ErrorKind::BrokenPipe));
    }

    #[tokio::test]
    async fn over_reported_progress_is_invalid_data() {
        let error = write_framed(&mut Scripted::OverReport, b"x")
            .await
            .unwrap_err();
        assert_eq!(error, FrameWriteError::Io(ErrorKind::InvalidData));
    }
}
