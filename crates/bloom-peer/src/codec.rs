use anyhow::{Context, Result, bail};
use iroh::endpoint::{RecvStream, SendStream};
use serde::{Serialize, de::DeserializeOwned};

pub(crate) async fn send_json<T: Serialize>(
    send: &mut SendStream,
    value: &T,
    max_bytes: usize,
) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > max_bytes {
        bail!("message exceeds {max_bytes} byte limit");
    }
    let len = u32::try_from(bytes.len()).context("message too large")?;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    send.finish()?;
    Ok(())
}

pub(crate) async fn recv_json<T: DeserializeOwned>(
    recv: &mut RecvStream,
    max_bytes: usize,
) -> Result<T> {
    let mut prefix = [0_u8; 4];
    recv.read_exact(&mut prefix).await?;
    let len = u32::from_be_bytes(prefix) as usize;
    if len > max_bytes {
        bail!("message length {len} exceeds {max_bytes} byte limit");
    }
    let mut bytes = vec![0_u8; len];
    recv.read_exact(&mut bytes).await?;
    // Consume the peer's FIN. This keeps the QUIC connection alive until the
    // complete framed message has been acknowledged by the receiver.
    let trailing = recv.read_to_end(0).await?;
    if !trailing.is_empty() {
        bail!("unexpected bytes after framed message");
    }
    Ok(serde_json::from_slice(&bytes)?)
}
