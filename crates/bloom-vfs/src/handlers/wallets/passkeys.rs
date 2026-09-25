//! `wallets/<wallet>/passkeys/`: the wallet's passkeys and their enrollment.
//!
//! ```text
//! passkeys/<date>-<surface>-<hex>/   one enrolled passkey (credential)
//!     name                           writable Machine-only nickname
//!     surface  created  state  credential_id
//! passkeys/by-name/<nickname>        symlink to its passkey directory
//! passkeys/new                       write `remote`, `local` or nothing to enroll
//! passkeys/latest                    symlink to the newest enrollment
//! passkeys/enrollments/<operation>/  url  status  status.json  cancel
//! ```
//!
//! Directory names are derived from Broker's public credential projection
//! (creation date, surface and a short digest of the credential ID) and are
//! presentation only: every operation resolves them back to the full
//! credential ID. Nicknames are user preferences kept by Machine in one file
//! keyed by full credential ID. They never reach Broker or Signer, so they
//! cannot appear on a ceremony page, and renaming needs no ceremony.
//!
//! Enrollment adds a passkey on another device through Broker's paired
//! ceremony; Broker picks which existing passkey approves. A device that
//! already holds one of the wallet's passkeys ends as `already_registered`
//! with nothing enrolled. As with registrations, listing and GETATTR stay
//! local; only reading `url`, `status` or `status.json` asks Broker.

use super::*;
use bloom_broker_api::{
    CeremonyCrossSurfacePrepareRequest, CeremonyKind, CeremonyState, CeremonySurfaceSelection,
    CredentialPublic, CredentialState, DecimalU64, OperationId,
};

const ENROLLMENT_SCHEMA: &str = "bloom.machine-passkey-enrollment.1";
const NAMES_SCHEMA: &str = "bloom.machine-passkey-names.1";
const PASSKEY_FILES: [&str; 5] = ["name", "surface", "created", "state", "credential_id"];
const ENROLLMENT_FILES: [&str; 3] = ["url", "status", "status.json"];
const NICKNAME_MAX_CHARS: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PasskeyEnrollmentProjection {
    schema: String,
    wallet: String,
    destination: CeremonySurfaceSelection,
    operation_id: OperationId,
    ceremony_state: CeremonyState,
    ceremony_url: Option<String>,
    ceremony_expires_at_ms: Option<DecimalU64>,
    created_at_ms: u64,
}

#[derive(Debug, Default, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct PasskeyNames {
    schema: String,
    /// Full base64url credential ID to nickname.
    names: std::collections::BTreeMap<String, String>,
}

fn terminal(state: CeremonyState) -> bool {
    matches!(
        state,
        CeremonyState::Completed
            | CeremonyState::Succeeded
            | CeremonyState::Cancelled
            | CeremonyState::Expired
            | CeremonyState::Failed
            | CeremonyState::AlreadyRegistered
    )
}

fn state_word(state: CeremonyState) -> Result<String, HandlerError> {
    serde_json::to_value(state)
        .ok()
        .and_then(|value| value.as_str().map(str::to_ascii_lowercase))
        .ok_or_else(|| HandlerError::backend("unrepresentable ceremony state"))
}

fn credential_key(credential: &CredentialPublic) -> String {
    credential.credential_id.encoded().to_owned()
}

fn surface_word(credential: &CredentialPublic) -> &str {
    // Credentials enrolled before surfaces existed are localhost wraps.
    credential
        .surface
        .as_ref()
        .map_or("local", |surface| surface.surface_id.as_str())
}

fn civil(ms: u64) -> (i64, u32, u32, u32, u32, u32) {
    crate::handlers::status::unix_to_civil(ms / 1000)
}

/// `<YYYY-MM-DD>-<surface>-<hex>`, with the digest suffix lengthened only
/// where two passkeys would otherwise share a name.
fn passkey_dir_names(credentials: &[CredentialPublic]) -> Vec<(String, &CredentialPublic)> {
    let described: Vec<(String, String, &CredentialPublic)> = credentials
        .iter()
        .map(|credential| {
            let (y, mo, d, ..) = civil(credential.created_at_ms.get());
            let prefix = format!("{y:04}-{mo:02}-{d:02}-{}", surface_word(credential));
            let digest = hex::encode(sha2::Sha256::digest(credential.credential_id.decode()));
            (prefix, digest, credential)
        })
        .collect();
    described
        .iter()
        .map(|(prefix, digest, credential)| {
            let mut length = 4;
            while length < digest.len()
                && described.iter().any(|(other_prefix, other_digest, other)| {
                    !std::ptr::eq(*other, *credential)
                        && other_prefix == prefix
                        && other_digest[..length] == digest[..length]
                })
            {
                length += 2;
            }
            (format!("{prefix}-{}", &digest[..length]), *credential)
        })
        .collect()
}

/// A nickname becomes a symlink name under `by-name/`, so it must be one
/// ordinary path segment. An empty write clears it.
fn validate_nickname(data: &[u8]) -> Result<Option<String>, HandlerError> {
    let text = std::str::from_utf8(data)
        .map_err(|_| HandlerError::invalid("passkey name must be UTF-8"))?
        .trim();
    if text.is_empty() {
        return Ok(None);
    }
    if text.chars().count() > NICKNAME_MAX_CHARS
        || text.starts_with('.')
        || !text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.'))
    {
        return Err(HandlerError::invalid(
            "passkey name must be 1-64 ASCII letters, digits, spaces, '-', '_' or '.', not starting with '.'",
        ));
    }
    Ok(Some(text.to_owned()))
}

impl WalletsHandler {
    fn passkey_names_file(&self) -> std::path::PathBuf {
        self.passkey_names_path
            .clone()
            .unwrap_or_else(|| self.policy_projection_root.join("passkey-names.json"))
    }

    fn load_passkey_names(&self) -> Result<PasskeyNames, HandlerError> {
        let path = self.passkey_names_file();
        if !path.exists() {
            return Ok(PasskeyNames {
                schema: NAMES_SCHEMA.into(),
                names: Default::default(),
            });
        }
        let names: PasskeyNames = read_json(&path)?;
        if names.schema != NAMES_SCHEMA {
            return Err(HandlerError::backend(
                "passkey name file schema is unsupported",
            ));
        }
        Ok(names)
    }

    fn nickname(names: &PasskeyNames, credential: &CredentialPublic) -> Option<String> {
        names.names.get(&credential_key(credential)).cloned()
    }

    async fn set_nickname(
        &self,
        credentials: &[CredentialPublic],
        target: &CredentialPublic,
        nickname: Option<String>,
    ) -> Result<(), HandlerError> {
        let _guard = self.passkey_names_lock.lock().await;
        let mut names = self.load_passkey_names()?;
        if let Some(nickname) = &nickname
            && credentials.iter().any(|other| {
                other.credential_id != target.credential_id
                    && names.names.get(&credential_key(other)) == Some(nickname)
            })
        {
            return Err(HandlerError::invalid(format!(
                "{nickname:?} already names another passkey of this wallet"
            )));
        }
        match nickname {
            Some(nickname) => names.names.insert(credential_key(target), nickname),
            None => names.names.remove(&credential_key(target)),
        };
        write_atomic_json(&self.passkey_names_file(), &names)
    }

    fn resolve_passkey<'a>(
        credentials: &'a [CredentialPublic],
        dir: &str,
    ) -> Result<&'a CredentialPublic, HandlerError> {
        passkey_dir_names(credentials)
            .into_iter()
            .find(|(name, _)| name == dir)
            .map(|(_, credential)| credential)
            .ok_or_else(|| HandlerError::not_found(format!("passkey {dir}")))
    }

    fn by_name_links(
        &self,
        credentials: &[CredentialPublic],
    ) -> Result<Vec<(String, String)>, HandlerError> {
        let names = self.load_passkey_names()?;
        Ok(passkey_dir_names(credentials)
            .into_iter()
            .filter_map(|(dir, credential)| {
                Self::nickname(&names, credential).map(|nick| (nick, format!("../{dir}")))
            })
            .collect())
    }

    fn enrollment_root(&self, wallet: &str) -> std::path::PathBuf {
        self.policy_projection_root
            .join("passkey-enrollments")
            .join(wallet)
    }

    fn enrollment_records(
        &self,
        wallet: &str,
    ) -> Result<Vec<(std::path::PathBuf, PasskeyEnrollmentProjection)>, HandlerError> {
        let entries = match std::fs::read_dir(self.enrollment_root(wallet)) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut records = Vec::new();
        for entry in entries {
            let path = entry?.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let record: PasskeyEnrollmentProjection = read_json(&path)?;
            let stem = path.file_stem().and_then(|value| value.to_str());
            if record.schema != ENROLLMENT_SCHEMA
                || record.wallet != wallet
                || stem != Some(record.operation_id.as_str())
            {
                return Err(HandlerError::backend(
                    "Machine passkey enrollment projection identity is invalid",
                ));
            }
            records.push((path, record));
        }
        records.sort_by(|(_, a), (_, b)| {
            b.created_at_ms
                .cmp(&a.created_at_ms)
                .then_with(|| a.operation_id.as_str().cmp(b.operation_id.as_str()))
        });
        Ok(records)
    }

    fn enrollment_record(
        &self,
        wallet: &str,
        operation: &str,
    ) -> Result<(std::path::PathBuf, PasskeyEnrollmentProjection), HandlerError> {
        self.enrollment_records(wallet)?
            .into_iter()
            .find(|(_, record)| record.operation_id.as_str() == operation)
            .ok_or_else(|| HandlerError::not_found(format!("passkey enrollment {operation}")))
    }

    fn latest_enrollment(&self, wallet: &str) -> Result<Option<String>, HandlerError> {
        Ok(self
            .enrollment_records(wallet)?
            .into_iter()
            .next()
            .map(|(_, record)| record.operation_id.as_str().to_owned()))
    }

    /// Refresh one enrollment from Broker, clearing a spent or stale link.
    async fn enrollment_projection(
        &self,
        wallet: &str,
        operation: &str,
    ) -> Result<PasskeyEnrollmentProjection, HandlerError> {
        let (path, mut record) = self.enrollment_record(wallet, operation)?;
        if terminal(record.ceremony_state) {
            return Ok(record);
        }
        let status = self
            .custody_broker()?
            .ceremony_status(record.operation_id.clone())
            .await
            .map_err(|error| HandlerError::backend(error.to_string()))?;
        if status.operation_id != record.operation_id
            || status.ceremony_kind != CeremonyKind::CredentialAdd
        {
            return Err(HandlerError::backend(
                "Broker returned a mismatched passkey enrollment status",
            ));
        }
        record.ceremony_state = status.state;
        if status.state == CeremonyState::AwaitingUser && status.expires_at_ms.get() > now_ms_u64()
        {
            // Broker omits a remote link once its one-time capability is used.
            record.ceremony_url = status.ceremony_url.filter(|url| !url.trim().is_empty());
            record.ceremony_expires_at_ms = Some(status.expires_at_ms);
        } else {
            record.ceremony_url = None;
            record.ceremony_expires_at_ms = None;
        }
        write_atomic_json(&path, &record)?;
        Ok(record)
    }

    async fn prepare_passkey_enrollment(
        &self,
        wallet: &str,
        data: &[u8],
    ) -> Result<(), HandlerError> {
        // An empty write takes the default: the hosted surface when it is
        // effective, otherwise this host's browser.
        let destination = match std::str::from_utf8(data).map(str::trim) {
            Ok("") => CeremonySurfaceSelection::Default,
            Ok("remote") => CeremonySurfaceSelection::Remote,
            Ok("local") => CeremonySurfaceSelection::Local,
            _ => {
                return Err(HandlerError::invalid(
                    "write nothing or `remote` for the default surface, or `local` for this host's browser",
                ));
            }
        };
        // A shell retry or a replayed NFS write must not start a second
        // enrollment while one to the same surface is still usable.
        for (_, record) in self.enrollment_records(wallet)? {
            if (destination == CeremonySurfaceSelection::Default
                || record.destination == destination)
                && !terminal(record.ceremony_state)
            {
                let refreshed = self
                    .enrollment_projection(wallet, record.operation_id.as_str())
                    .await?;
                if refreshed.ceremony_state == CeremonyState::AwaitingUser {
                    return Ok(());
                }
            }
        }
        let mut operation_bytes = [0_u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut operation_bytes);
        let operation_id = OperationId::from_bytes(operation_bytes);
        let prepared = self
            .custody_broker()?
            .prepare_cross_surface_credential(CeremonyCrossSurfacePrepareRequest {
                operation_id: operation_id.clone(),
                wallet_id: Self::wallet_id(wallet)?,
                destination,
            })
            .await
            .map_err(|error| {
                // No active wallet passkey can approve on any usable surface.
                // Broker refuses before a link exists, and repeating the
                // write cannot change that.
                if error.code == bloom_broker_api::ProtocolErrorCode::ApprovalNotFound {
                    HandlerError::OperationNotPermitted
                } else {
                    HandlerError::backend(error.to_string())
                }
            })?;
        if prepared.operation_id != operation_id
            || prepared.state != CeremonyState::AwaitingUser
            || prepared.destination_url.trim().is_empty()
            || prepared.expires_at_ms.get() <= now_ms_u64()
        {
            return Err(HandlerError::backend(
                "Broker returned an invalid passkey enrollment prepare response",
            ));
        }
        // Record the surface Broker chose, so `status.json` names it.
        let destination = match destination {
            CeremonySurfaceSelection::Default
                if prepared.destination_url.starts_with("https://") =>
            {
                CeremonySurfaceSelection::Remote
            }
            CeremonySurfaceSelection::Default => CeremonySurfaceSelection::Local,
            chosen => chosen,
        };
        let record = PasskeyEnrollmentProjection {
            schema: ENROLLMENT_SCHEMA.into(),
            wallet: wallet.to_owned(),
            destination,
            operation_id: operation_id.clone(),
            ceremony_state: CeremonyState::AwaitingUser,
            ceremony_url: Some(prepared.destination_url),
            ceremony_expires_at_ms: Some(prepared.expires_at_ms),
            created_at_ms: now_ms_u64(),
        };
        write_atomic_json(
            &self
                .enrollment_root(wallet)
                .join(format!("{}.json", operation_id.as_str())),
            &record,
        )
    }

    async fn cancel_passkey_enrollment(
        &self,
        wallet: &str,
        operation: &str,
    ) -> Result<(), HandlerError> {
        let record = self.enrollment_projection(wallet, operation).await?;
        if record.ceremony_state != CeremonyState::AwaitingUser {
            return Err(HandlerError::invalid(
                "passkey enrollment is no longer cancellable",
            ));
        }
        let status = self
            .custody_broker()?
            .cancel_ceremony(record.operation_id.clone())
            .await
            .map_err(|error| HandlerError::backend(error.to_string()))?;
        if status.operation_id != record.operation_id
            || status.ceremony_kind != CeremonyKind::CredentialAdd
            || status.state != CeremonyState::Cancelled
        {
            return Err(HandlerError::backend(
                "Broker did not confirm passkey enrollment cancellation",
            ));
        }
        let _ = self.enrollment_projection(wallet, operation).await?;
        Ok(())
    }

    pub(super) async fn lookup_passkeys(
        &self,
        wallet: &str,
        projection: &WalletProjection,
        rest: &[String],
    ) -> Result<Entry, HandlerError> {
        let credentials = &projection.credentials;
        let missing =
            || HandlerError::not_found(format!("wallets/{wallet}/passkeys/{}", rest.join("/")));
        match rest {
            [] => Ok(Entry::dir("passkeys")),
            [leaf] if leaf == "new" => Ok(Entry::writable_file("new")),
            [leaf] if leaf == "by-name" || leaf == "enrollments" => Ok(Entry::dir(leaf)),
            [leaf] if leaf == "latest" => self
                .latest_enrollment(wallet)?
                .map(|operation| Entry::symlink("latest", &format!("enrollments/{operation}")))
                .ok_or_else(missing),
            [by_name, nick] if by_name == "by-name" => self
                .by_name_links(credentials)?
                .into_iter()
                .find(|(name, _)| name == nick)
                .map(|(name, target)| Entry::symlink(&name, &target))
                .ok_or_else(missing),
            [enrollments, operation] if enrollments == "enrollments" => {
                self.enrollment_record(wallet, operation)?;
                Ok(Entry::dir(operation))
            }
            [enrollments, operation, leaf] if enrollments == "enrollments" => {
                self.enrollment_record(wallet, operation)?;
                match leaf.as_str() {
                    "cancel" => Ok(Entry::writable_file("cancel")),
                    leaf if ENROLLMENT_FILES.contains(&leaf) => Ok(Entry::file(leaf)),
                    _ => Err(missing()),
                }
            }
            [dir] => {
                Self::resolve_passkey(credentials, dir)?;
                Ok(Entry::dir(dir))
            }
            [dir, leaf] => {
                Self::resolve_passkey(credentials, dir)?;
                match leaf.as_str() {
                    "name" => Ok(Entry::writable_file("name")),
                    leaf if PASSKEY_FILES.contains(&leaf) => Ok(Entry::file(leaf)),
                    _ => Err(missing()),
                }
            }
            _ => Err(missing()),
        }
    }

    pub(super) async fn list_passkeys(
        &self,
        wallet: &str,
        projection: &WalletProjection,
        rest: &[String],
    ) -> Result<Vec<Entry>, HandlerError> {
        let credentials = &projection.credentials;
        match rest {
            [] => {
                let mut entries: Vec<Entry> = passkey_dir_names(credentials)
                    .into_iter()
                    .map(|(dir, _)| Entry::dir(&dir))
                    .collect();
                entries.push(Entry::writable_file("new"));
                entries.push(Entry::dir("by-name"));
                entries.push(Entry::dir("enrollments"));
                if let Some(operation) = self.latest_enrollment(wallet)? {
                    entries.push(Entry::symlink(
                        "latest",
                        &format!("enrollments/{operation}"),
                    ));
                }
                Ok(entries)
            }
            [leaf] if leaf == "by-name" => Ok(self
                .by_name_links(credentials)?
                .into_iter()
                .map(|(name, target)| Entry::symlink(&name, &target))
                .collect()),
            [leaf] if leaf == "enrollments" => Ok(self
                .enrollment_records(wallet)?
                .into_iter()
                .map(|(_, record)| Entry::dir(record.operation_id.as_str()))
                .collect()),
            [enrollments, operation] if enrollments == "enrollments" => {
                self.enrollment_record(wallet, operation)?;
                let mut entries: Vec<Entry> = ENROLLMENT_FILES
                    .iter()
                    .map(|leaf| Entry::file(leaf))
                    .collect();
                entries.push(Entry::writable_file("cancel"));
                Ok(entries)
            }
            [dir] if Self::resolve_passkey(credentials, dir).is_ok() => Ok(PASSKEY_FILES
                .iter()
                .map(|leaf| match *leaf {
                    "name" => Entry::writable_file(leaf),
                    leaf => Entry::file(leaf),
                })
                .collect()),
            _ => Err(HandlerError::NotADir(format!(
                "wallets/{wallet}/passkeys/{}",
                rest.join("/")
            ))),
        }
    }

    pub(super) async fn read_passkeys(
        &self,
        wallet: &str,
        rest: &[String],
    ) -> Result<Vec<u8>, HandlerError> {
        let line = |value: &str| format!("{value}\n").into_bytes();
        match rest {
            [enrollments, operation, leaf] if enrollments == "enrollments" => {
                let record = self.enrollment_projection(wallet, operation).await?;
                match leaf.as_str() {
                    "status" => Ok(line(&state_word(record.ceremony_state)?)),
                    "url" => record.ceremony_url.as_deref().map(line).ok_or_else(|| {
                        HandlerError::not_found(
                            "no live enrollment link: it was already opened, finished, cancelled or expired",
                        )
                    }),
                    "status.json" => {
                        let mut bytes = serde_json::to_vec_pretty(&record)
                            .map_err(|error| HandlerError::backend(error.to_string()))?;
                        bytes.push(b'\n');
                        Ok(bytes)
                    }
                    _ => Err(HandlerError::NotAFile(leaf.clone())),
                }
            }
            [dir, leaf] if dir != "by-name" && dir != "enrollments" => {
                let projection = self.wallet_projection(wallet).await?;
                let credential = Self::resolve_passkey(&projection.credentials, dir)?;
                match leaf.as_str() {
                    "name" => Ok(Self::nickname(&self.load_passkey_names()?, credential)
                        .map_or_else(Vec::new, |nick| line(&nick))),
                    "surface" => Ok(line(surface_word(credential))),
                    "created" => {
                        let (y, mo, d, h, mi, s) = civil(credential.created_at_ms.get());
                        Ok(line(&format!(
                            "{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z"
                        )))
                    }
                    "state" => Ok(line(match credential.state {
                        CredentialState::Active => "active",
                        CredentialState::Revoked => "revoked",
                    })),
                    "credential_id" => Ok(line(&credential_key(credential))),
                    _ => Err(HandlerError::NotAFile(leaf.clone())),
                }
            }
            _ => Err(HandlerError::NotAFile(format!(
                "wallets/{wallet}/passkeys/{}",
                rest.join("/")
            ))),
        }
    }

    pub(super) async fn write_passkeys(
        &self,
        wallet: &str,
        rest: &[String],
        data: &[u8],
    ) -> Result<(), HandlerError> {
        self.write_permit()?;
        match rest {
            [leaf] if leaf == "new" => self.prepare_passkey_enrollment(wallet, data).await,
            [enrollments, operation, leaf] if enrollments == "enrollments" && leaf == "cancel" => {
                self.cancel_passkey_enrollment(wallet, operation).await
            }
            [dir, leaf] if leaf == "name" && dir != "by-name" && dir != "enrollments" => {
                let projection = self.wallet_projection(wallet).await?;
                let credential = Self::resolve_passkey(&projection.credentials, dir)?;
                let nickname = validate_nickname(data)?;
                self.set_nickname(&projection.credentials, credential, nickname)
                    .await
            }
            _ => Err(HandlerError::PermissionDenied),
        }
    }
}

#[cfg(test)]
pub(super) mod tests_support {
    use bloom_broker_api::CredentialPublic;

    pub fn dir_names(credentials: &[CredentialPublic]) -> Vec<String> {
        super::passkey_dir_names(credentials)
            .into_iter()
            .map(|(name, _)| name)
            .collect()
    }
}
