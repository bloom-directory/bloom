use bloom_checkout_api::{BrowseResponse, HistoryEntry, Request, Status};
use serde_json::Value;
use std::{path::PathBuf, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

/// One checkout call may read attention, the shopping tab, and the payment page.
/// The page read is tried three times. Each browser command waits 30 seconds,
/// approval intake waits 15, and closing a refused page waits 10.
const CHECKOUT_CALL_TIMEOUT: Duration = Duration::from_secs(30 * (2 + 2 + 3 * 3 + 2) + 15 + 10);

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
        tokio::time::timeout(CHECKOUT_CALL_TIMEOUT, self.exchange(request))
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
            Request::Browse { .. } => match serde_json::from_str::<BrowseResponse>(&line) {
                Ok(response) => {
                    serde_json::to_value(response).map_err(|_| "Invalid browse response".into())
                }
                Err(_) => Err(serde_json::from_str::<BrowseError>(&line)
                    .ok()
                    .map(|e| e.error.chars().take(200).collect())
                    .unwrap_or_else(|| "Checkout browsing is unavailable".into())),
            },
            Request::History => serde_json::from_str::<Vec<HistoryEntry>>(&line)
                .and_then(serde_json::to_value)
                .map_err(|_| "Checkout history unavailable".into()),
            _ => serde_json::from_str::<Status>(&line)
                .and_then(serde_json::to_value)
                .map_err(|_| {
                    checkout_refusal(&line).unwrap_or_else(|| {
                        "Checkout request rejected; inspect status before retrying".into()
                    })
                }),
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowseError {
    error: String,
}

#[derive(serde::Deserialize)]
#[serde(tag = "error_code", rename_all = "snake_case", deny_unknown_fields)]
enum CheckoutRefusal {
    Blocked { operation_id: String },
    FormErrors,
    UnlockPending,
    IdUsed,
}

fn checkout_refusal(line: &str) -> Option<String> {
    let value: Value = serde_json::from_str(line).ok()?;
    let fields = value.as_object()?;
    let expected = if fields.get("error_code")?.as_str()? == "blocked" {
        2
    } else {
        1
    };
    if fields.len() != expected {
        return None;
    }
    match serde_json::from_value::<CheckoutRefusal>(value).ok()? {
        CheckoutRefusal::Blocked { operation_id }
            if operation_id.len() == 64
                && operation_id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) =>
        {
            Some(format!(
                "{operation_id}: payment result unknown. Ask the person to check it: request a take-over with \"resolves\": \"{operation_id}\""
            ))
        }
        CheckoutRefusal::FormErrors => {
            Some("The page shows form errors; fix them before payment".into())
        }
        CheckoutRefusal::UnlockPending => Some(
            "A saved traveler unlock is waiting for approval; finish or cancel it before payment"
                .into(),
        ),
        CheckoutRefusal::IdUsed => Some("Operation ID already used; check its status".into()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn checkout_refusals_cross_the_socket_without_page_text() {
        use std::os::unix::fs::MetadataExt;
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("api.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let uid = socket.metadata().unwrap().uid();
        let id = "a".repeat(64);
        let reply_id = id.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut input = String::new();
            BufReader::new(reader).read_line(&mut input).await.unwrap();
            writer
                .write_all(
                    format!("{{\"error_code\":\"blocked\",\"operation_id\":\"{reply_id}\"}}\n")
                        .as_bytes(),
                )
                .await
                .unwrap();
        });
        let error = CheckoutClient::new(socket, uid)
            .call(&Request::Checkout {
                operation_id: "b".repeat(64),
                card_id: None,
                agent_description: "Fixture".into(),
                take_over: false,
                resolves: None,
            })
            .await
            .unwrap_err();
        assert!(error.contains(&id) && error.contains("resolves"));
        assert!(
            checkout_refusal("{\"error_code\":\"form_errors\",\"value\":\"private\"}").is_none()
        );
        assert!(
            checkout_refusal("{\"error_code\":\"blocked\",\"operation_id\":\"private\"}").is_none()
        );
    }

    async fn response(value: &'static str, uid: u32) -> Result<Value, String> {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("api.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut input = String::new();
            let _ = BufReader::new(reader).read_line(&mut input).await;
            let _ = writer.write_all(value.as_bytes()).await;
        });
        let result = CheckoutClient::new(socket, uid)
            .call(&Request::Browse {
                request: bloom_checkout_api::BrowseRequest::Snapshot,
            })
            .await;
        task.abort();
        result
    }
    #[tokio::test]
    async fn unknown_private_projection_and_wrong_principal_are_rejected() {
        use std::os::unix::fs::MetadataExt;
        let uid = tempfile::tempdir()
            .unwrap()
            .path()
            .metadata()
            .unwrap()
            .uid();
        assert!(
            response(
                "{\"url\":\"https://shop.invalid\",\"text\":\"Shop\",\"elements\":[]}\n",
                uid
            )
            .await
            .is_ok()
        );
        assert!(response("{\"url\":\"https://shop.invalid\",\"text\":\"Shop\",\"elements\":[],\"challenge_url\":\"private capability\"}\n",uid).await.is_err());
        assert!(response("{\"state\":\"opened\"}\n", uid + 1).await.is_err());
        assert_eq!(
            response(
                "{\"error\":\"Stale element reference; request a new snapshot\"}\n",
                uid
            )
            .await
            .unwrap_err(),
            "Stale element reference; request a new snapshot"
        );
    }

    #[tokio::test]
    async fn slow_checkout_response_is_delivered() {
        use std::os::unix::fs::MetadataExt;
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("api.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let uid = socket.metadata().unwrap().uid();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut input = String::new();
            let _ = BufReader::new(reader).read_line(&mut input).await;
            // A slow page read. A paused clock skips this socket read.
            tokio::time::sleep(Duration::from_secs(46)).await;
            let _ = writer
                .write_all(b"{\"operation_id\":\"ab\",\"state\":\"requested\",\"ceremony_url\":null,\"filled_fields\":[],\"outcome\":null}\n")
                .await;
        });
        let result = CheckoutClient::new(socket, uid)
            .call(&Request::Status {
                operation_id: "ab".into(),
            })
            .await;
        assert!(result.is_ok(), "{result:?}");
    }
}
