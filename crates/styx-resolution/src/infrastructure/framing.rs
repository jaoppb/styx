//! The two-octet big-endian length prefix that precedes each DNS message on a stream.
//!
//! One implementation for every stream transport: plaintext TCP and DNS over TLS read
//! through [`read_frame`] and write through [`send_frame`], so the framing
//! that sits under `indexing_slicing` and `arithmetic_side_effects` scrutiny exists once.

use std::time::Duration;

use styx_net::{write_framed, FrameWriteError};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::domain::error::ListenerError;

/// Why a response frame did not reach the stream.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SendFrameError {
    /// The frame could not be written.
    #[error(transparent)]
    Write(#[from] FrameWriteError),
    /// The frame was written but could not be flushed.
    #[error("flushing the frame failed: {0}")]
    Flush(std::io::Error),
    /// The write and flush did not finish within the write timeout.
    #[error("the frame was not sent within the write timeout")]
    TimedOut,
}

/// Writes one length-prefixed frame and flushes it, both within `write_timeout`.
///
/// The flush is what puts a DNS-over-TLS answer on the wire: tokio-rustls reports a
/// write as done once rustls holds the plaintext, even while the encrypted records still
/// wait for the socket, and only a later write, a flush or a shutdown sends them.
/// Bounding the flush too keeps `write_timeout` a bound on a slow reader.
pub(crate) async fn send_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    body: &[u8],
    write_timeout: Duration,
) -> Result<(), SendFrameError> {
    let sent = async {
        write_framed(writer, body).await?;
        writer.flush().await.map_err(SendFrameError::Flush)
    };
    tokio::time::timeout(write_timeout, sent)
        .await
        .map_err(|_| SendFrameError::TimedOut)?
}

/// Reads one length-prefixed frame; `Ok(None)` when the peer closed cleanly before a prefix.
///
/// The prefix read has no timeout of its own — the caller races it against the idle
/// timer — but the payload must follow within `payload_timeout`. The largest frame the
/// prefix can declare is 65535 octets, so the payload allocation is bounded by the
/// protocol itself.
///
/// # Errors
/// Returns [`ListenerError::Framing`] for a zero-length frame or a payload that does not
/// arrive in time, and [`ListenerError::Io`] when the stream fails or ends mid-frame.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    payload_timeout: Duration,
) -> Result<Option<Vec<u8>>, ListenerError> {
    let mut prefix = [0u8; 2];
    match reader.read_exact(&mut prefix).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(ListenerError::Io(err)),
    }

    let len = usize::from(u16::from_be_bytes(prefix));
    if len == 0 {
        return Err(ListenerError::Framing("zero-length frame received".into()));
    }

    let mut payload = vec![0u8; len];
    let read_payload = tokio::time::timeout(payload_timeout, reader.read_exact(&mut payload));
    match read_payload.await {
        Ok(Ok(_)) => Ok(Some(payload)),
        Ok(Err(err)) => Err(ListenerError::Io(err)),
        Err(_) => Err(ListenerError::Framing(
            "timeout reading frame payload".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TIMEOUT: Duration = Duration::from_secs(1);

    #[tokio::test]
    async fn reads_a_frame_split_across_reads() {
        let (mut client, mut server) = tokio::io::duplex(1);
        let writer = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            client.write_all(&[0, 3, 1, 2, 3]).await.unwrap();
        });
        let frame = read_frame(&mut server, TIMEOUT).await.unwrap();
        writer.await.unwrap();
        assert_eq!(frame, Some(vec![1, 2, 3]));
    }

    #[tokio::test]
    async fn a_sent_frame_reaches_a_peer_behind_a_buffering_writer() {
        let (near, mut far) = tokio::io::duplex(64);
        // Like tokio-rustls, a BufWriter reports the write done while the bytes wait in
        // its buffer; without the flush the peer would see nothing.
        let mut buffered = tokio::io::BufWriter::new(near);
        send_frame(&mut buffered, &[1, 2, 3], TIMEOUT)
            .await
            .unwrap();

        let frame = tokio::time::timeout(TIMEOUT, read_frame(&mut far, TIMEOUT))
            .await
            .expect("the frame was flushed")
            .unwrap();
        assert_eq!(frame, Some(vec![1, 2, 3]));
    }

    #[tokio::test]
    async fn a_peer_that_never_reads_times_the_send_out() {
        let (near, _far) = tokio::io::duplex(8);
        let mut buffered = tokio::io::BufWriter::new(near);
        let err = send_frame(&mut buffered, &[7; 64], Duration::from_millis(50))
            .await
            .unwrap_err();
        assert!(matches!(err, SendFrameError::TimedOut), "{err}");
    }

    #[tokio::test]
    async fn clean_close_before_a_prefix_is_none() {
        let mut empty: &[u8] = &[];
        assert_eq!(read_frame(&mut empty, TIMEOUT).await.unwrap(), None);
    }

    #[tokio::test]
    async fn zero_length_frame_is_a_framing_error() {
        let mut zero: &[u8] = &[0, 0];
        let err = read_frame(&mut zero, TIMEOUT).await.unwrap_err();
        assert!(matches!(err, ListenerError::Framing(_)));
    }

    #[tokio::test]
    async fn short_prefix_is_a_clean_close_and_short_body_an_error() {
        let mut half_prefix: &[u8] = &[0];
        assert_eq!(read_frame(&mut half_prefix, TIMEOUT).await.unwrap(), None);

        let mut short_body: &[u8] = &[0, 5, 1, 2];
        let err = read_frame(&mut short_body, TIMEOUT).await.unwrap_err();
        assert!(matches!(err, ListenerError::Io(_)));
    }
}
