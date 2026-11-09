//! Public card metadata and the keyless shopping surface. No plaintext card inputs.
use crate::{
    handler::{Entry, Handler, HandlerError},
    path::VfsPath,
};
use async_trait::async_trait;
use bloom_broker_api::{
    CardAddRequest, CardDeleteRequest, MachineBrokerRequest as BrokerRequest,
    MachineBrokerResponse as BrokerResponse, OperationId, OperationRequest, TravelerDeleteRequest,
    TravelerSaveRequest,
};
use bloom_checkout_api::{BrowseRequest, Request};
use bloom_machine_client::{MachineBrokerClient, checkout::CheckoutClient};
use serde::Deserialize;
use serde_json::Value;
use std::path::PathBuf;

pub struct CardsHandler {
    broker: Option<MachineBrokerClient>,
    root: PathBuf,
    travelers: bool,
}
impl CardsHandler {
    pub fn new(broker: Option<MachineBrokerClient>, root: PathBuf) -> Self {
        Self {
            broker,
            root,
            travelers: false,
        }
    }
    pub fn travelers(broker: Option<MachineBrokerClient>, root: PathBuf) -> Self {
        Self {
            broker,
            root,
            travelers: true,
        }
    }
    async fn call(&self, request: BrokerRequest) -> Result<BrokerResponse, HandlerError> {
        self.broker
            .as_ref()
            .ok_or_else(|| HandlerError::backend("Card custody unavailable"))?
            .request(request)
            .await
            .map_err(|_| {
                HandlerError::backend(
                    "Card custody request rejected; inspect status before retrying",
                )
            })
    }
}

fn safe_json(value: impl serde::Serialize) -> Result<Vec<u8>, HandlerError> {
    serde_json::to_vec_pretty(&value)
        .map_err(|_| HandlerError::backend("Public checkout projection unavailable"))
}
fn input<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, HandlerError> {
    if bytes.len() > 16384 {
        return Err(HandlerError::invalid("Checkout input exceeds limit"));
    }
    serde_json::from_slice(bytes).map_err(|_| {
        HandlerError::invalid("Invalid public checkout request; never include card details")
    })
}
fn operation(id: &str) -> Result<OperationId, HandlerError> {
    OperationId::new(id)
        .map_err(|_| HandlerError::invalid("Operation ID must be 64 hexadecimal characters"))
}
fn record(
    root: &std::path::Path,
    id: &str,
    value: &impl serde::Serialize,
) -> Result<(), HandlerError> {
    operation(id)?;
    std::fs::create_dir_all(root)?;
    let bytes = safe_json(value)?;
    // Projection only; custody and replay protection stay in the services.
    std::fs::write(root.join(format!("{id}.json")), bytes)?;
    Ok(())
}
fn operations(root: &std::path::Path) -> Vec<Entry> {
    std::fs::read_dir(root)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|e| {
            e.file_name()
                .to_str()
                .and_then(|s| s.strip_suffix(".json"))
                .map(str::to_owned)
        })
        .filter(|s| operation(s).is_ok())
        .map(|s| Entry::dir(&s))
        .collect()
}

#[async_trait]
impl Handler for CardsHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let segments = path
            .segments()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let s = segments.as_slice();
        match s {
            [] | ["operations"] => Ok(Entry::dir(s.last().copied().unwrap_or(if self.travelers {
                "travelers"
            } else {
                "cards"
            }))),
            ["index.json"] => Ok(Entry::file("index.json")),
            ["delete.json"] => Ok(Entry::writable_file(s[0])),
            ["save.json"] if self.travelers => Ok(Entry::writable_file(s[0])),
            ["add.json"] if !self.travelers => Ok(Entry::writable_file(s[0])),
            ["operations", id] => {
                operation(id)?;
                Ok(Entry::dir(id))
            }
            ["operations", id, "status.json" | "ceremony.json"] => {
                operation(id)?;
                Ok(Entry::file(s[2]))
            }
            _ => Err(HandlerError::not_found(path.to_string_path())),
        }
    }
    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let segments = path
            .segments()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        match segments.as_slice() {
            ["index.json"] => match self
                .call(if self.travelers {
                    BrokerRequest::TravelerList(bloom_broker_api::Empty {})
                } else {
                    BrokerRequest::CardList(bloom_broker_api::Empty {})
                })
                .await?
            {
                BrokerResponse::CardList(cards) if !self.travelers => safe_json(cards),
                BrokerResponse::TravelerList(travelers) if self.travelers => safe_json(travelers),
                _ => Err(HandlerError::backend("Invalid card listing")),
            },
            ["operations", id, "status.json"] => match self
                .call(BrokerRequest::CardStatus(OperationRequest {
                    operation_id: operation(id)?,
                }))
                .await?
            {
                BrokerResponse::CardStatus(status) => safe_json(status),
                _ => Err(HandlerError::backend("Invalid card status")),
            },
            ["operations", id, "ceremony.json"] => {
                operation(id)?;
                Ok(std::fs::read(self.root.join(format!("{id}.json")))?)
            }
            _ => Err(HandlerError::not_found(path.to_string_path())),
        }
    }
    async fn write(&self, path: &VfsPath, bytes: &[u8]) -> Result<(), HandlerError> {
        let segments = path
            .segments()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let (id, response) = match segments.as_slice() {
            ["save.json"] if self.travelers => {
                let request: TravelerSaveRequest = input(bytes)?;
                let id = request.operation_id.to_string();
                (id, self.call(BrokerRequest::TravelerSave(request)).await?)
            }
            ["add.json"] if !self.travelers => {
                let request: CardAddRequest = input(bytes)?;
                let id = request.operation_id.to_string();
                (id, self.call(BrokerRequest::CardAdd(request)).await?)
            }
            ["delete.json"] => {
                if self.travelers {
                    let request: TravelerDeleteRequest = input(bytes)?;
                    let id = request.operation_id.to_string();
                    let response = self.call(BrokerRequest::TravelerDelete(request)).await?;
                    if let BrokerResponse::TravelerDelete(prepared) = response {
                        return record(&self.root, &id, &prepared);
                    }
                    return Err(HandlerError::backend("Invalid traveler ceremony response"));
                }
                let request: CardDeleteRequest = input(bytes)?;
                let id = request.operation_id.to_string();
                (id, self.call(BrokerRequest::CardDelete(request)).await?)
            }
            _ => return Err(HandlerError::PermissionDenied),
        };
        let prepared = match response {
            BrokerResponse::CardAdd(r) | BrokerResponse::CardDelete(r) if !self.travelers => r,
            BrokerResponse::TravelerSave(r) if self.travelers => r,
            _ => return Err(HandlerError::backend("Invalid card ceremony response")),
        };
        record(&self.root, &id, &prepared)
    }
    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let segments = path
            .segments()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        match segments.as_slice() {
            [] => Ok(vec![
                Entry::file("index.json"),
                Entry::writable_file(if self.travelers {
                    "save.json"
                } else {
                    "add.json"
                }),
                Entry::writable_file("delete.json"),
                Entry::dir("operations"),
            ]),
            ["operations"] => Ok(operations(&self.root)),
            ["operations", id] => {
                operation(id)?;
                Ok(vec![
                    Entry::file("status.json"),
                    Entry::file("ceremony.json"),
                ])
            }
            _ => Err(HandlerError::NotADir(path.to_string_path())),
        }
    }
}

pub struct CheckoutHandler {
    client: CheckoutClient,
    root: PathBuf,
    browse: parking_lot::Mutex<std::collections::BTreeMap<String, (std::time::Instant, Vec<u8>)>>,
}
impl CheckoutHandler {
    pub fn new(client: CheckoutClient, root: PathBuf) -> Self {
        Self {
            client,
            root,
            browse: parking_lot::Mutex::new(std::collections::BTreeMap::new()),
        }
    }
    async fn call(&self, request: Request) -> Result<Value, HandlerError> {
        self.client
            .call(&request)
            .await
            .map_err(HandlerError::backend)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckoutInput {
    #[serde(default)]
    card_id: Option<String>,
    #[serde(default)]
    agent_description: String,
    #[serde(default)]
    take_over: bool,
    #[serde(default)]
    resolves: Option<String>,
}

#[async_trait]
impl Handler for CheckoutHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let segments = path
            .segments()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let s = segments.as_slice();
        match s {
            [] | ["browse"] | ["requests"] => {
                Ok(Entry::dir(s.last().copied().unwrap_or("checkout")))
            }
            ["history.json"] => Ok(Entry::file("history.json")),
            ["browse" | "requests", id] => {
                operation(id)?;
                Ok(Entry::dir(id))
            }
            ["browse" | "requests", id, "in.json"] | ["requests", id, "cancel"] => {
                operation(id)?;
                Ok(Entry::writable_file(s[2]))
            }
            ["browse", id, "out.json"] | ["requests", id, "status.json"] => {
                operation(id)?;
                Ok(Entry::file(s[2]))
            }
            _ => Err(HandlerError::not_found(path.to_string_path())),
        }
    }
    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let segments = path
            .segments()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        match segments.as_slice() {
            ["history.json"] => safe_json(self.call(Request::History).await?),
            ["browse", id, "out.json"] => {
                operation(id)?;
                self.browse
                    .lock()
                    .get(*id)
                    .filter(|(at, _)| at.elapsed() < std::time::Duration::from_secs(300))
                    .map(|(_, bytes)| bytes.clone())
                    .ok_or_else(|| HandlerError::not_found("No browse result"))
            }
            ["requests", id, "status.json"] => {
                operation(id)?;
                let status: bloom_checkout_api::Status = serde_json::from_value(
                    self.call(Request::Status {
                        operation_id: (*id).into(),
                    })
                    .await?,
                )
                .map_err(|_| HandlerError::backend("Invalid public checkout status"))?;
                safe_json(status)
            }
            _ => Err(HandlerError::not_found(path.to_string_path())),
        }
    }
    async fn write(&self, path: &VfsPath, bytes: &[u8]) -> Result<(), HandlerError> {
        let segments = path
            .segments()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        match segments.as_slice() {
            ["browse", id, "in.json"] => {
                operation(id)?;
                let request: BrowseRequest = input(bytes)?;
                let full = {
                    let mut browse = self.browse.lock();
                    browse.retain(|_, (at, _)| at.elapsed() < std::time::Duration::from_secs(300));
                    browse.len() >= 64 && !browse.contains_key(*id)
                };
                if full {
                    return Err(HandlerError::backend("Too many browse result slots"));
                }
                let response = self.call(Request::Browse { request }).await?;
                self.browse.lock().insert(
                    (*id).into(),
                    (std::time::Instant::now(), safe_json(response)?),
                );
                Ok(())
            }
            ["requests", id, "in.json"] => {
                operation(id)?;
                let request: CheckoutInput = input(bytes)?;
                let response = self
                    .call(Request::Checkout {
                        operation_id: (*id).into(),
                        card_id: request.card_id,
                        agent_description: request.agent_description,
                        take_over: request.take_over,
                        resolves: request.resolves,
                    })
                    .await?;
                let response: bloom_checkout_api::Status = serde_json::from_value(response)
                    .map_err(|_| HandlerError::backend("Invalid public checkout status"))?;
                record(&self.root, id, &response)
            }
            ["requests", id, "cancel"] => {
                operation(id)?;
                self.call(Request::Cancel {
                    operation_id: (*id).into(),
                })
                .await?;
                Ok(())
            }
            _ => Err(HandlerError::PermissionDenied),
        }
    }
    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let segments = path
            .segments()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        match segments.as_slice() {
            [] => Ok(vec![
                Entry::file("history.json"),
                Entry::dir("browse"),
                Entry::dir("requests"),
            ]),
            ["requests"] => Ok(operations(&self.root)),
            ["browse"] => Ok(self.browse.lock().keys().map(|id| Entry::dir(id)).collect()),
            ["browse", id] => {
                operation(id)?;
                Ok(vec![
                    Entry::writable_file("in.json"),
                    Entry::file("out.json"),
                ])
            }
            ["requests", id] => {
                operation(id)?;
                Ok(vec![
                    Entry::writable_file("in.json"),
                    Entry::file("status.json"),
                    Entry::writable_file("cancel"),
                ])
            }
            _ => Err(HandlerError::NotADir(path.to_string_path())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lookup, list, read and write agree on every operation path.
    #[tokio::test]
    async fn lookup_advertises_only_paths_that_read_or_write_accept() {
        let dir = tempfile::tempdir().unwrap();
        let handler = CheckoutHandler::new(
            CheckoutClient::new(dir.path().join("unused.sock"), 0),
            dir.path().join("requests"),
        );
        let id = "a".repeat(64);
        assert!(
            handler
                .lookup(&VfsPath::parse("/profile.json").unwrap())
                .await
                .is_err()
        );
        for dir in ["browse", "requests"] {
            let listed = handler
                .list(&VfsPath::parse(&format!("/{dir}/{id}")).unwrap())
                .await
                .unwrap();
            for name in ["in.json", "out.json", "status.json", "cancel"] {
                let path = VfsPath::parse(&format!("/{dir}/{id}/{name}")).unwrap();
                let shown = listed.iter().find(|e| e.name == name);
                let looked = handler.lookup(&path).await;
                assert_eq!(looked.is_ok(), shown.is_some(), "{dir}/{name}");
                let unknown = |r: &Result<_, HandlerError>| {
                    matches!(r, Err(HandlerError::NotFound(p)) if *p == path.to_string_path())
                };
                let write = handler.write(&path, b"{}").await;
                match shown {
                    None => {
                        assert!(unknown(&handler.read(&path).await), "{dir}/{name}");
                        assert!(matches!(write, Err(HandlerError::PermissionDenied)));
                    }
                    Some(entry) => {
                        assert_eq!(looked.unwrap().mode, entry.mode, "{dir}/{name}");
                        let writable = entry.mode & 0o200 != 0;
                        assert_eq!(
                            matches!(write, Err(HandlerError::PermissionDenied)),
                            !writable,
                            "{dir}/{name}"
                        );
                        if !writable {
                            assert!(!unknown(&handler.read(&path).await), "{dir}/{name}");
                        }
                    }
                }
            }
        }
    }
}
