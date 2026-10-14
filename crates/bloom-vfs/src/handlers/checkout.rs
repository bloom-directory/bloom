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
    profile: PathBuf,
    browse: parking_lot::Mutex<std::collections::BTreeMap<String, (std::time::Instant, Vec<u8>)>>,
}
impl CheckoutHandler {
    pub fn new(client: CheckoutClient, root: PathBuf, profile: PathBuf) -> Self {
        Self {
            client,
            root,
            profile,
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
/// Saved contact and billing details the agent types into ordinary checkout
/// fields. Convenience only: not custody, not behind a passkey.
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    phone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    billing_address: Option<Address>,
}
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Address {
    line1: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    line2: Option<String>,
    city: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    region: Option<String>,
    postal_code: String,
    /// ISO 3166-1 alpha-2, for example `US`.
    country: String,
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
    traveler_id: Option<String>,
    #[serde(default)]
    continue_private: Option<String>,
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
            ["profile.json"] => Ok(Entry::writable_file("profile.json")),
            ["history.json"] => Ok(Entry::file("history.json")),
            ["browse" | "requests", id] => {
                operation(id)?;
                Ok(Entry::dir(id))
            }
            ["browse" | "requests", id, "in.json" | "cancel"] => {
                operation(id)?;
                Ok(Entry::writable_file(s[2]))
            }
            ["browse" | "requests", id, "out.json" | "status.json"] => {
                operation(id)?;
                Ok(Entry::file(s[2]))
            }
            ["requests", id, "facts.json"] => {
                operation(id)?;
                Ok(Entry::file("facts.json"))
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
            ["profile.json"] => match std::fs::read(&self.profile) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(b"{}\n".to_vec()),
                result => Ok(result?),
            },
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
            ["requests", id, "facts.json"] => {
                operation(id)?;
                let facts: bloom_checkout_api::PaymentFacts = serde_json::from_value(
                    self.call(Request::PrivateFacts {
                        operation_id: (*id).into(),
                    })
                    .await?,
                )
                .map_err(|_| HandlerError::backend("Invalid public payment facts"))?;
                safe_json(facts)
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
            ["profile.json"] => {
                let profile: Profile = serde_json::from_slice(bytes)
                    .ok()
                    .filter(|_| bytes.len() <= 4096)
                    .ok_or_else(|| {
                        HandlerError::invalid(
                            "Profile takes email, name, phone and billing_address \
                             (line1, line2, city, region, postal_code, country); \
                             never card details",
                        )
                    })?;
                let temp = self.profile.with_extension("json.tmp");
                std::fs::write(&temp, safe_json(&profile)?)?;
                std::fs::rename(&temp, &self.profile)?;
                Ok(())
            }
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
                if let Some(traveler_id) = request.traveler_id {
                    if request.card_id.is_some()
                        || request.take_over
                        || request.continue_private.is_some()
                    {
                        return Err(HandlerError::invalid(
                            "Traveler autofill does not accept payment or takeover options",
                        ));
                    }
                    let response = self
                        .call(Request::Traveler {
                            operation_id: (*id).into(),
                            traveler_id,
                        })
                        .await?;
                    let response: bloom_checkout_api::Status = serde_json::from_value(response)
                        .map_err(|_| HandlerError::backend("Invalid public traveler status"))?;
                    return record(&self.root, id, &response);
                }
                let response = self
                    .call(Request::Checkout {
                        operation_id: (*id).into(),
                        card_id: request.card_id,
                        agent_description: request.agent_description,
                        take_over: request.take_over,
                        continue_private: request.continue_private,
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
                Entry::writable_file("profile.json"),
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
                    Entry::file("facts.json"),
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

    #[tokio::test]
    async fn profile_round_trips_and_rejects_card_details() {
        let dir = tempfile::tempdir().unwrap();
        let handler = CheckoutHandler::new(
            CheckoutClient::new(dir.path().join("unused.sock"), 0),
            dir.path().join("requests"),
            dir.path().join("checkout-profile.json"),
        );
        let path = VfsPath::parse("/profile.json").unwrap();
        assert_eq!(handler.read(&path).await.unwrap(), b"{}\n");
        let profile = br#"{"email":"a@example.com","name":"A B","billing_address":{"line1":"1 Main St","city":"Springfield","region":"IL","postal_code":"62701","country":"US"}}"#;
        handler.write(&path, profile).await.unwrap();
        let saved: Value = serde_json::from_slice(&handler.read(&path).await.unwrap()).unwrap();
        assert_eq!(saved["billing_address"]["postal_code"], "62701");
        for rejected in [
            &br#"{"email":"a@example.com","card_number":"4242424242424242"}"#[..],
            br#"{"billing_address":{"line1":"1 Main St"}}"#,
        ] {
            assert!(handler.write(&path, rejected).await.is_err());
        }
        let kept: Value = serde_json::from_slice(&handler.read(&path).await.unwrap()).unwrap();
        assert_eq!(kept["email"], "a@example.com");
    }
}
