//! Public card metadata and the keyless shopping surface. No plaintext card inputs.
use crate::{
    handler::{Entry, Handler, HandlerError},
    path::VfsPath,
};
use async_trait::async_trait;
use bloom_broker_api::{
    CardAddRequest, CardDeleteRequest, MachineBrokerRequest as BrokerRequest,
    MachineBrokerResponse as BrokerResponse, OperationId, OperationRequest,
};
use bloom_checkout_api::{BrowseRequest, Request};
use bloom_machine_client::{MachineBrokerClient, checkout::CheckoutClient};
use serde::Deserialize;
use serde_json::Value;
use std::path::PathBuf;

pub struct CardsHandler {
    broker: Option<MachineBrokerClient>,
    root: PathBuf,
}
impl CardsHandler {
    pub fn new(broker: Option<MachineBrokerClient>, root: PathBuf) -> Self {
        Self { broker, root }
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
            [] | ["operations"] => Ok(Entry::dir(s.last().copied().unwrap_or("cards"))),
            ["index.json"] => Ok(Entry::file("index.json")),
            ["add.json" | "delete.json"] => Ok(Entry::writable_file(s[0])),
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
                .call(BrokerRequest::CardList(bloom_broker_api::Empty {}))
                .await?
            {
                BrokerResponse::CardList(cards) => safe_json(cards),
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
            ["add.json"] => {
                let request: CardAddRequest = input(bytes)?;
                let id = request.operation_id.to_string();
                (id, self.call(BrokerRequest::CardAdd(request)).await?)
            }
            ["delete.json"] => {
                let request: CardDeleteRequest = input(bytes)?;
                let id = request.operation_id.to_string();
                (id, self.call(BrokerRequest::CardDelete(request)).await?)
            }
            _ => return Err(HandlerError::PermissionDenied),
        };
        let prepared = match response {
            BrokerResponse::CardAdd(r) | BrokerResponse::CardDelete(r) => r,
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
                Entry::writable_file("add.json"),
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    travelers: Vec<Traveler>,
}

/// Ordinary booking data visible to the agent, never card or login credentials.
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Traveler {
    id: String,
    given_name: String,
    family_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    born_on: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gender: Option<TravelerGender>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nationality: Option<String>,
    /// Save document data only when the owner explicitly requests it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    document: Option<TravelDocument>,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum TravelerGender {
    Female,
    Male,
    Unspecified,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct TravelDocument {
    kind: DocumentKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    number: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    issuing_country: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_on: Option<String>,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum DocumentKind {
    Passport,
    NationalId,
}

fn booking_date(value: &str) -> bool {
    if value.len() != 10 || !value.is_ascii() || &value[4..5] != "-" || &value[7..8] != "-" {
        return false;
    }
    if !value
        .bytes()
        .enumerate()
        .all(|(i, byte)| matches!(i, 4 | 7) || byte.is_ascii_digit())
    {
        return false;
    }
    let Ok(year) = value[..4].parse::<u32>() else {
        return false;
    };
    let Ok(month) = value[5..7].parse::<usize>() else {
        return false;
    };
    let Ok(day) = value[8..].parse::<u32>() else {
        return false;
    };
    if year == 0 || !(1..=12).contains(&month) {
        return false;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    (1..=days[month - 1]).contains(&day)
}

impl Profile {
    fn validate(&self) -> Result<(), HandlerError> {
        let mut ids = std::collections::BTreeSet::new();
        if self.travelers.len() > 8 {
            return Err(HandlerError::invalid(
                "Profile supports up to eight travelers",
            ));
        }
        let country =
            |value: &str| value.len() == 2 && value.bytes().all(|c| c.is_ascii_uppercase());
        for traveler in &self.travelers {
            if traveler.id.is_empty()
                || traveler.id.len() > 64
                || !ids.insert(&traveler.id)
                || traveler.given_name.trim().is_empty()
                || traveler.family_name.trim().is_empty()
                || traveler
                    .born_on
                    .as_deref()
                    .is_some_and(|date| !booking_date(date))
                || traveler
                    .nationality
                    .as_deref()
                    .is_some_and(|code| !country(code))
            {
                return Err(HandlerError::invalid(
                    "Travelers need unique IDs and given/family names; dates use YYYY-MM-DD and countries use two uppercase letters",
                ));
            }
            if traveler.document.as_ref().is_some_and(|document| {
                document
                    .number
                    .as_deref()
                    .is_some_and(|number| number.trim().is_empty() || number.len() > 64)
                    || document
                        .issuing_country
                        .as_deref()
                        .is_some_and(|code| !country(code))
                    || document
                        .expires_on
                        .as_deref()
                        .is_some_and(|date| !booking_date(date))
            }) {
                return Err(HandlerError::invalid(
                    "Invalid traveler document; dates use YYYY-MM-DD and countries use two uppercase letters",
                ));
            }
        }
        Ok(())
    }
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
    agent_description: String,
    #[serde(default)]
    take_over: bool,
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
                safe_json(
                    self.call(Request::Status {
                        operation_id: (*id).into(),
                    })
                    .await?,
                )
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
                            "Profile takes email, name, phone, travelers and billing_address \
                             (line1, line2, city, region, postal_code, country); \
                             never card details",
                        )
                    })?;
                profile.validate()?;
                let temp = self.profile.with_extension("json.tmp");
                use std::io::Write;
                let mut options = std::fs::OpenOptions::new();
                options.write(true).create(true).truncate(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                let mut file = options.open(&temp)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
                }
                file.write_all(&safe_json(&profile)?)?;
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
                let response = self
                    .call(Request::Checkout {
                        operation_id: (*id).into(),
                        card_id: request.card_id,
                        agent_description: request.agent_description,
                        take_over: request.take_over,
                    })
                    .await?;
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

    #[tokio::test]
    async fn traveler_profiles_persist_and_invalid_updates_preserve_saved_data() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("checkout-profile.json");
        let handler = CheckoutHandler::new(
            CheckoutClient::new(dir.path().join("unused.sock"), 0),
            dir.path().join("requests"),
            file.clone(),
        );
        let path = VfsPath::parse("/profile.json").unwrap();
        let saved = serde_json::json!({"email":"fixture@example.com","travelers":[{
            "id":"self","given_name":"Ada","family_name":"Fixture","born_on":"1992-02-29",
            "gender":"female","nationality":"CA","document":{"kind":"passport",
                "number":"FIXTURE123","issuing_country":"CA","expires_on":"2030-06-30"}
        }]});
        handler
            .write(&path, &serde_json::to_vec(&saved).unwrap())
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&handler.read(&path).await.unwrap()).unwrap(),
            saved
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        for (field, value) in [
            ("born_on", "1991-02-29"),
            ("born_on", "2000-04-31"),
            ("born_on", "+001-01-01"),
            ("nationality", "Canada"),
            ("gender", "guess"),
            ("card_number", "4242424242424242"),
            ("password", "fixture-not-a-password"),
        ] {
            let mut invalid = saved.clone();
            invalid["travelers"][0][field] = value.into();
            assert!(
                handler
                    .write(&path, &serde_json::to_vec(&invalid).unwrap())
                    .await
                    .is_err()
            );
            assert_eq!(
                serde_json::from_slice::<Value>(&handler.read(&path).await.unwrap()).unwrap(),
                saved
            );
        }
        let mut duplicate = saved.clone();
        duplicate["travelers"]
            .as_array_mut()
            .unwrap()
            .push(saved["travelers"][0].clone());
        assert!(
            handler
                .write(&path, &serde_json::to_vec(&duplicate).unwrap())
                .await
                .is_err()
        );
        let mut too_many = saved.clone();
        too_many["travelers"] = (0..9)
            .map(|i| {
                let mut traveler = saved["travelers"][0].clone();
                traveler["id"] = format!("fixture-{i}").into();
                traveler
            })
            .collect::<Vec<_>>()
            .into();
        assert!(
            handler
                .write(&path, &serde_json::to_vec(&too_many).unwrap())
                .await
                .is_err()
        );
        let mut no_document = saved.clone();
        no_document["travelers"][0]
            .as_object_mut()
            .unwrap()
            .remove("document");
        handler
            .write(&path, &serde_json::to_vec(&no_document).unwrap())
            .await
            .unwrap();
        assert!(
            !String::from_utf8(handler.read(&path).await.unwrap())
                .unwrap()
                .contains("FIXTURE123")
        );
        handler.write(&path, br#"{"travelers":[]}"#).await.unwrap();
        assert_eq!(handler.read(&path).await.unwrap(), b"{}");
    }
}
