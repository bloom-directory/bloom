use bloom_checkout_api::{BrowseResponse, Request, Status};
use serde_json::Value;
use std::{path::PathBuf, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

/// The client cannot request screenshots, selectors, card fields, or private URLs.
#[derive(Clone)]
pub struct CheckoutClient {
    socket: PathBuf,
    checkout_uid: u32,
}
impl CheckoutClient {
    pub fn new(socket: PathBuf, checkout_uid: u32) -> Self {
        Self {
            socket,
            checkout_uid,
        }
    }
    pub async fn call(&self, request: &Request) -> Result<Value, String> {
        tokio::time::timeout(Duration::from_secs(45), self.exchange(request))
            .await
            .map_err(|_| "Checkout response timed out; inspect status before retrying".to_owned())?
    }
    async fn exchange(&self, request: &Request) -> Result<Value, String> {
        let stream = tokio::net::UnixStream::connect(&self.socket)
            .await
            .map_err(|_| "Checkout service unavailable")?;
        if stream
            .peer_cred()
            .map_err(|_| "Checkout identity unavailable")?
            .uid()
            != self.checkout_uid
        {
            return Err("Checkout identity rejected".into());
        }
        let (reader, mut writer) = stream.into_split();
        let mut bytes = serde_json::to_vec(request).map_err(|_| "Invalid checkout request")?;
        bytes.push(b'\n');
        if bytes.len() > 16384 {
            return Err("Checkout request exceeds limit".into());
        }
        writer
            .write_all(&bytes)
            .await
            .map_err(|_| "Checkout request was not confirmed; inspect status")?;
        let mut line = String::new();
        BufReader::new(reader.take(131073))
            .read_line(&mut line)
            .await
            .map_err(|_| "Checkout response unavailable")?;
        if line.len() > 131072 {
            return Err("Checkout response exceeds limit".into());
        }
        // Re-serialize closed public projections. Unknown fields never reach VFS.
        match request {
            Request::Browse { .. } => serde_json::from_str::<BrowseResponse>(&line)
                .and_then(serde_json::to_value)
                .map_err(|_| "Checkout browsing is paused or unavailable".into()),
            _ => serde_json::from_str::<Status>(&line)
                .and_then(serde_json::to_value)
                .map_err(|_| "Checkout request rejected; inspect status before retrying".into()),
        }
    }
}
