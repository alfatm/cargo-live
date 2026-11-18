use std::fmt;
use std::io;

use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroize;

/// Largest accepted frame payload.
pub const MAX_FRAME: usize = 64 * 1024 * 1024;

#[derive(Debug)]
pub enum FrameError {
    Io(io::Error),
    TooLarge(usize),
    Decode(postcard::Error),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::Io(e) => write!(f, "connection error: {e}"),
            FrameError::TooLarge(n) => {
                write!(f, "frame of {n} bytes exceeds the {MAX_FRAME} byte limit")
            }
            FrameError::Decode(e) => write!(f, "malformed protocol message: {e}"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<io::Error> for FrameError {
    fn from(e: io::Error) -> Self {
        FrameError::Io(e)
    }
}

/// Encodes a message as a complete frame (length prefix included).
pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>, FrameError> {
    let mut out = postcard::to_extend(msg, vec![0; 4]).map_err(FrameError::Decode)?;
    let len = out.len() - 4;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    out[..4].copy_from_slice(&(len as u32).to_be_bytes());
    Ok(out)
}

/// Decodes a frame payload (without the length prefix).
pub fn decode<T: DeserializeOwned>(payload: &[u8]) -> Result<T, FrameError> {
    postcard::from_bytes(payload).map_err(FrameError::Decode)
}

pub async fn write_frame<W, T>(writer: &mut W, msg: &T) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let mut frame = encode(msg)?;
    let result = writer.write_all(&frame).await;
    // Frames may carry credentials; do not leave copies in freed memory.
    frame.zeroize();
    result?;
    writer.flush().await?;
    Ok(())
}

/// Reads one frame. Returns `None` on a clean end of stream before a frame.
pub async fn read_frame<R, T>(reader: &mut R) -> Result<Option<T>, FrameError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut header = [0u8; 4];
    let mut filled = 0;
    while filled < 4 {
        let n = reader.read(&mut header[filled..]).await?;
        if n == 0 {
            if filled == 0 {
                return Ok(None);
            }
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }
        filled += n;
    }
    let len = u32::from_be_bytes(header) as usize;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    let mut payload = vec![0; len];
    reader.read_exact(&mut payload).await?;
    let result = decode(&payload).map(Some);
    payload.zeroize();
    result
}

/// Buffered frame reader whose [`FrameReader::next`] is cancel safe, so it
/// can be used as a branch of `tokio::select!` in a loop: a cancelled call
/// loses no data. Consumed frames are zeroed in the buffer.
pub struct FrameReader<R> {
    inner: R,
    buf: Vec<u8>,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buf: Vec::new(),
        }
    }

    /// Reads the next frame. Returns `None` on a clean end of stream
    /// between frames.
    pub async fn next<T: DeserializeOwned>(&mut self) -> Result<Option<T>, FrameError> {
        loop {
            if self.buf.len() >= 4 {
                let len = u32::from_be_bytes(self.buf[..4].try_into().expect("4 bytes")) as usize;
                if len > MAX_FRAME {
                    return Err(FrameError::TooLarge(len));
                }
                if self.buf.len() >= 4 + len {
                    let result = decode(&self.buf[4..4 + len]).map(Some);
                    let total = self.buf.len();
                    self.buf[..4 + len].zeroize();
                    self.buf.drain(..4 + len);
                    // The tail moved down; clear its stale copy.
                    let new_len = self.buf.len();
                    let spare = self.buf.spare_capacity_mut();
                    for byte in &mut spare[..total - new_len] {
                        byte.write(0);
                    }
                    return result;
                }
                self.buf.reserve(4 + len - self.buf.len());
            } else {
                self.buf.reserve(64 * 1024);
            }
            // `read_buf` is cancel safe: if cancelled, nothing was read.
            let n = self.inner.read_buf(&mut self.buf).await?;
            if n == 0 {
                if self.buf.is_empty() {
                    return Ok(None);
                }
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
            }
        }
    }
}

impl<R> Drop for FrameReader<R> {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentMsg, BuildCommand, BuildRequest, ClientMsg, Entry, EntryKind};

    #[tokio::test]
    async fn round_trips_frames() {
        let messages = vec![
            ClientMsg::Hello {
                protocol_version: 1,
                client_version: "0.1.0".into(),
            },
            ClientMsg::Manifest {
                entries: vec![
                    Entry {
                        path: "src".into(),
                        kind: EntryKind::Dir,
                    },
                    Entry {
                        path: "src/main.rs".into(),
                        kind: EntryKind::File {
                            size: 10,
                            mtime_ns: -5,
                            executable: true,
                        },
                    },
                    Entry {
                        path: "link".into(),
                        kind: EntryKind::Symlink {
                            target: "src".into(),
                        },
                    },
                ],
            },
            ClientMsg::FileChunk(vec![1, 2, 3]),
            ClientMsg::Build(BuildRequest {
                command: BuildCommand::Run,
                toolchain: Some("nightly".into()),
                args: vec!["--release".into()],
                relative_cwd: "a/b".into(),
                json_output: false,
            }),
        ];
        let mut buf = Vec::new();
        for msg in &messages {
            write_frame(&mut buf, msg).await.unwrap();
        }
        let mut reader = buf.as_slice();
        for msg in &messages {
            let got: ClientMsg = read_frame(&mut reader).await.unwrap().unwrap();
            assert_eq!(&got, msg);
        }
        assert!(read_frame::<_, ClientMsg>(&mut reader)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn rejects_oversized_and_truncated_frames() {
        let mut header = ((MAX_FRAME + 1) as u32).to_be_bytes().to_vec();
        header.extend_from_slice(&[0; 8]);
        let err = read_frame::<_, AgentMsg>(&mut header.as_slice())
            .await
            .unwrap_err();
        assert!(matches!(err, FrameError::TooLarge(_)));

        let frame = encode(&AgentMsg::Exit { code: 3 }).unwrap();
        let truncated = &frame[..frame.len() - 1];
        assert!(read_frame::<_, AgentMsg>(&mut &truncated[..])
            .await
            .is_err());
        assert!(read_frame::<_, AgentMsg>(&mut &frame[..2]).await.is_err());
    }

    #[tokio::test]
    async fn frame_reader_handles_split_and_batched_frames() {
        let mut buf = Vec::new();
        for code in 0..5 {
            write_frame(&mut buf, &AgentMsg::Exit { code })
                .await
                .unwrap();
        }
        write_frame(&mut buf, &AgentMsg::BinaryChunk(vec![7; 200_000]))
            .await
            .unwrap();
        // Deliver in odd-sized pieces.
        let (mut tx, rx) = tokio::io::duplex(37);
        let feeder = tokio::spawn(async move {
            for piece in buf.chunks(13) {
                tx.write_all(piece).await.unwrap();
            }
        });
        let mut reader = FrameReader::new(rx);
        for code in 0..5 {
            let msg: AgentMsg = reader.next().await.unwrap().unwrap();
            assert_eq!(msg, AgentMsg::Exit { code });
        }
        let msg: AgentMsg = reader.next().await.unwrap().unwrap();
        assert_eq!(msg, AgentMsg::BinaryChunk(vec![7; 200_000]));
        feeder.await.unwrap();
        assert!(reader.next::<AgentMsg>().await.unwrap().is_none());
    }

    #[test]
    fn stable_variant_indices() {
        // Hello, Welcome and Error must keep index 0, 0 and 1.
        let hello = encode(&ClientMsg::Hello {
            protocol_version: 9,
            client_version: String::new(),
        })
        .unwrap();
        assert_eq!(hello[4], 0);
        let error = encode(&AgentMsg::Error {
            message: String::new(),
        })
        .unwrap();
        assert_eq!(error[4], 1);
    }
}
