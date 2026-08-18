use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use bloom_broker_api::{
    CredentialPublic, DerivationRef, Digest32, KeyPublic, KeyRequest, KeyRole, KeySpec,
    ProtocolError, ProtocolErrorCode, SignedPolicySnapshot, Token, WalletPublic,
};
use fs2::FileExt as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::MachineBrokerClient;

const CACHE_SCHEMA: &str = "bloom.machine-wallet-projections.v1";
const SOURCE_PROTOCOL: &str = "bloom.machine-broker.v1";
const LIVE_REFRESH_FRESHNESS_MS: u64 = 30_000;
// Kernel-mounted reads commonly render the same dynamic file for GETATTR and
// then READ. Coalesce only that burst; authority changes remain observable on
// the next ordinary interaction rather than waiting for the stale-read TTL.
const LIVE_REFRESH_COALESCE_MS: u64 = 100;
static TEMPORARY_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionFreshness {
    Fresh,
    Stale,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionVerification {
    AuthenticatedBroker,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WalletProjection {
    pub wallet: WalletPublic,
    pub keys: Vec<KeyPublic>,
    pub credentials: Vec<CredentialPublic>,
    pub policy: SignedPolicySnapshot,
    pub source_protocol: String,
    pub response_digest: Digest32,
    pub observed_at_ms: u64,
    pub freshness: ProjectionFreshness,
    pub verification: ProjectionVerification,
}

impl WalletProjection {
    pub fn wallet_id(&self) -> &Token {
        &self.wallet.wallet_id
    }

    pub fn primary_key(&self) -> Result<&KeyPublic, ProtocolError> {
        match &self.wallet.root_key_ref {
            Some(root) => self
                .keys
                .iter()
                .find(|key| &key.key_ref == root && key.role == KeyRole::WalletRoot)
                .ok_or_else(|| {
                    invalid_projection(format!(
                        "wallet {} primary key is absent from projection",
                        self.wallet.wallet_id.as_str()
                    ))
                }),
            // A BIP-39 wallet has no signable root; its primary key is the
            // canonical initial EVM child m/44'/60'/0'/0/0.
            None => {
                let evm_children = self.keys.iter().filter(|key| {
                    key.role == KeyRole::Derived && key.key_ref.key_spec == KeySpec::Secp256k1
                });
                evm_children
                    .clone()
                    .find(|key| {
                        matches!(
                            &key.key_ref.derivation,
                            Some(DerivationRef::Bip39Multicurve { path, .. })
                                if path == "m/44'/60'/0'/0/0"
                        )
                    })
                    .or_else(|| evm_children.into_iter().next())
                    .ok_or_else(|| {
                        invalid_projection(format!(
                            "wallet {} has no derived EVM primary key",
                            self.wallet.wallet_id.as_str()
                        ))
                    })
            }
        }
    }

    pub fn primary_address(&self) -> Result<&str, ProtocolError> {
        self.primary_key()?
            .addresses
            .first()
            .map(String::as_str)
            .ok_or_else(|| {
                invalid_projection(format!(
                    "wallet {} primary key has no address",
                    self.wallet.wallet_id.as_str()
                ))
            })
    }

    fn stale(mut self) -> Self {
        self.freshness = ProjectionFreshness::Stale;
        self
    }
}

#[async_trait]
pub trait WalletProjectionReader: Send + Sync {
    async fn list_wallets(&self) -> Result<Vec<WalletProjection>, ProtocolError>;
    async fn get_wallet(&self, wallet_id: &Token) -> Result<WalletProjection, ProtocolError>;
    fn cached_wallets(&self) -> Result<Vec<WalletProjection>, ProtocolError>;
}

#[derive(Clone)]
pub struct FileProjectionStore {
    path: PathBuf,
}

struct ProjectionRefreshLock {
    file: fs::File,
}

impl Drop for ProjectionRefreshLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

impl FileProjectionStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn load(&self) -> Result<ProjectionCache, ProtocolError> {
        match fs::read(&self.path) {
            Ok(bytes) => {
                let cache: ProjectionCache = serde_json::from_slice(&bytes).map_err(|error| {
                    unavailable(format!("read Machine wallet projection cache: {error}"))
                })?;
                cache.validate()?;
                Ok(cache)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(ProjectionCache::empty())
            }
            Err(error) => Err(unavailable(format!(
                "read Machine wallet projection cache: {error}"
            ))),
        }
    }

    fn acquire_refresh_lock(&self) -> Result<ProjectionRefreshLock, ProtocolError> {
        let parent = self.path.parent().ok_or_else(|| {
            unavailable("Machine wallet projection cache path has no parent directory")
        })?;
        fs::create_dir_all(parent).map_err(|error| {
            unavailable(format!("create Machine projection directory: {error}"))
        })?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(parent.join("wallet-projections.lock"))
            .map_err(|error| unavailable(format!("open Machine projection lock: {error}")))?;
        file.lock_exclusive()
            .map_err(|error| unavailable(format!("lock Machine projections: {error}")))?;
        Ok(ProjectionRefreshLock { file })
    }

    fn replace_after_live_refresh(
        &self,
        observed: BTreeMap<String, WalletProjection>,
        _refresh_lock: &ProjectionRefreshLock,
    ) -> Result<ProjectionCache, ProtocolError> {
        let mut cache = self.load()?;
        cache.apply_live_refresh(observed)?;
        self.save_unlocked(&cache)?;
        Ok(cache)
    }

    fn save_unlocked(&self, cache: &ProjectionCache) -> Result<(), ProtocolError> {
        cache.validate()?;
        let parent = self.path.parent().ok_or_else(|| {
            unavailable("Machine wallet projection cache path has no parent directory")
        })?;
        fs::create_dir_all(parent).map_err(|error| {
            unavailable(format!("create Machine projection directory: {error}"))
        })?;
        let name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| unavailable("Machine projection cache filename is invalid"))?;
        let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(".{name}.{}.{sequence}.tmp", std::process::id()));
        let bytes = serde_json::to_vec(cache)
            .map_err(|error| unavailable(format!("encode Machine projection cache: {error}")))?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| unavailable(format!("create Machine projection update: {error}")))?;
        let result = file
            .write_all(&bytes)
            .and_then(|()| file.sync_all())
            .and_then(|()| fs::rename(&temporary, &self.path));
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result.map_err(|error| unavailable(format!("commit Machine projection update: {error}")))
    }
}

#[derive(Clone)]
pub struct CachedWalletProjectionReader {
    broker: Option<MachineBrokerClient>,
    store: FileProjectionStore,
    cache: Arc<Mutex<ProjectionCache>>,
    last_live_refresh_ms: Arc<AtomicU64>,
}

impl CachedWalletProjectionReader {
    pub fn new(
        broker: Option<MachineBrokerClient>,
        store: FileProjectionStore,
    ) -> Result<Self, ProtocolError> {
        let cache = store.load()?;
        Ok(Self {
            broker,
            store,
            cache: Arc::new(Mutex::new(cache)),
            last_live_refresh_ms: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn broker(&self) -> Option<&MachineBrokerClient> {
        self.broker.as_ref()
    }

    async fn refresh(&self) -> Result<Vec<WalletProjection>, ProtocolError> {
        let broker = self
            .broker
            .as_ref()
            .ok_or_else(|| unavailable("authenticated Broker edge is unavailable"))?;
        // Serialize the observation as well as the commit. Otherwise an older
        // full-list response can arrive after a newer process has cached a
        // newly-created wallet and incorrectly tombstone it.
        let store = self.store.clone();
        let refresh_lock = tokio::task::spawn_blocking(move || store.acquire_refresh_lock())
            .await
            .map_err(|error| {
                unavailable(format!("join Machine projection lock task: {error}"))
            })??;
        let wallets = broker.wallets().await?;
        let mut observed = BTreeMap::new();
        for wallet in wallets {
            let wallet_id = wallet.wallet_id.clone();
            if observed.contains_key(wallet_id.as_str()) {
                return Err(invalid_projection(format!(
                    "Broker returned duplicate wallet {}",
                    wallet_id.as_str()
                )));
            }
            let mut keys = broker.keys(wallet_id.clone()).await?;
            let mut described = keys
                .iter()
                .map(|key| serde_json::to_string(&key.key_ref))
                .collect::<Result<BTreeSet<_>, _>>()
                .map_err(|error| {
                    invalid_projection(format!("encode Broker key reference: {error}"))
                })?;
            for key_ref in &wallet.key_refs {
                let encoded = serde_json::to_string(key_ref).map_err(|error| {
                    invalid_projection(format!("encode wallet key reference: {error}"))
                })?;
                if described.contains(&encoded) {
                    continue;
                }
                let key = broker
                    .key(KeyRequest {
                        key_ref: key_ref.clone(),
                    })
                    .await?;
                if key.key_ref != *key_ref {
                    return Err(invalid_projection(format!(
                        "Broker returned a different key for wallet {}",
                        wallet_id.as_str()
                    )));
                }
                described.insert(encoded);
                keys.push(key);
            }
            let credentials = broker.credentials(wallet_id.clone()).await?;
            let policy = broker.policy(wallet_id.clone()).await?;
            let projection = build_projection(wallet, keys, credentials, policy, now_ms()?)?;
            observed.insert(wallet_id.as_str().to_owned(), projection);
        }
        let updated = self
            .store
            .replace_after_live_refresh(observed, &refresh_lock)?;
        let projections = updated.live(false);
        *self
            .cache
            .lock()
            .map_err(|_| unavailable("Machine projection cache mutex poisoned"))? = updated;
        self.last_live_refresh_ms.store(now_ms()?, Ordering::SeqCst);
        Ok(projections)
    }

    async fn refresh_coalesced(&self) -> Result<Vec<WalletProjection>, ProtocolError> {
        let refreshed_at = self.last_live_refresh_ms.load(Ordering::SeqCst);
        if refreshed_at != 0 && now_ms()?.saturating_sub(refreshed_at) <= LIVE_REFRESH_COALESCE_MS {
            let cache = self
                .cache
                .lock()
                .map_err(|_| unavailable("Machine projection cache mutex poisoned"))?;
            return Ok(cache.live(false));
        }
        self.refresh().await
    }

    fn cached(&self) -> Result<Vec<WalletProjection>, ProtocolError> {
        let cache = self
            .cache
            .lock()
            .map_err(|_| unavailable("Machine projection cache mutex poisoned"))?;
        let projections = cache.live(true);
        if projections.is_empty() {
            return Err(unavailable(
                "Broker is unavailable and no cached wallet projection exists",
            ));
        }
        Ok(projections)
    }
}

#[async_trait]
impl WalletProjectionReader for CachedWalletProjectionReader {
    async fn list_wallets(&self) -> Result<Vec<WalletProjection>, ProtocolError> {
        match self.refresh().await {
            Ok(projections) => Ok(projections),
            Err(error) if error.code == ProtocolErrorCode::ServiceUnavailable => {
                tracing::warn!(
                    error = %error,
                    "Machine authority edge unavailable; serving cached wallet projections"
                );
                self.cached()
            }
            Err(error) => Err(error),
        }
    }

    async fn get_wallet(&self, wallet_id: &Token) -> Result<WalletProjection, ProtocolError> {
        let broker_error = match self.refresh_coalesced().await {
            Ok(projections) => {
                return projections
                    .into_iter()
                    .find(|projection| projection.wallet_id() == wallet_id)
                    .ok_or_else(|| {
                        invalid_projection(format!("wallet {} not found", wallet_id.as_str()))
                    });
            }
            Err(error) if error.code == ProtocolErrorCode::ServiceUnavailable => error,
            Err(error) => return Err(error),
        };
        tracing::warn!(
            error = %broker_error,
            wallet_id = %wallet_id.as_str(),
            "Machine authority edge unavailable; serving cached wallet projection"
        );
        let cache = self
            .cache
            .lock()
            .map_err(|_| unavailable("Machine projection cache mutex poisoned"))?;
        match cache.wallets.get(wallet_id.as_str()) {
            Some(CachedWallet::Live(projection)) => Ok(projection.clone().stale()),
            Some(CachedWallet::Tombstone { .. }) => Err(invalid_projection(format!(
                "wallet {} was deleted",
                wallet_id.as_str()
            ))),
            None => Err(unavailable(format!(
                "{}; wallet {} has no cached projection",
                broker_error.message,
                wallet_id.as_str()
            ))),
        }
    }

    fn cached_wallets(&self) -> Result<Vec<WalletProjection>, ProtocolError> {
        let cache = self
            .cache
            .lock()
            .map_err(|_| unavailable("Machine projection cache mutex poisoned"))?;
        let refreshed_at = self.last_live_refresh_ms.load(Ordering::SeqCst);
        if cache.wallets.is_empty() && refreshed_at == 0 {
            return Err(unavailable(
                "no live or cached Machine wallet projection is available",
            ));
        }
        let fresh = refreshed_at != 0
            && now_ms()?.saturating_sub(refreshed_at) <= LIVE_REFRESH_FRESHNESS_MS;
        Ok(cache.live(!fresh))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectionCache {
    schema: String,
    wallets: BTreeMap<String, CachedWallet>,
}

impl ProjectionCache {
    fn empty() -> Self {
        Self {
            schema: CACHE_SCHEMA.to_owned(),
            wallets: BTreeMap::new(),
        }
    }

    fn live(&self, stale: bool) -> Vec<WalletProjection> {
        self.wallets
            .values()
            .filter_map(|wallet| match wallet {
                CachedWallet::Live(projection) if stale => Some(projection.clone().stale()),
                CachedWallet::Live(projection) => Some(projection.clone()),
                CachedWallet::Tombstone { .. } => None,
            })
            .collect()
    }

    fn apply_live_refresh(
        &mut self,
        observed: BTreeMap<String, WalletProjection>,
    ) -> Result<(), ProtocolError> {
        for (wallet_id, candidate) in &observed {
            match self.wallets.get(wallet_id) {
                Some(CachedWallet::Live(current))
                    if candidate.policy.version.get() < current.policy.version.get() =>
                {
                    return Err(ProtocolError::new(
                        ProtocolErrorCode::PolicyBaselineStale,
                        format!(
                            "Broker policy version for {wallet_id} rolled back from {} to {}",
                            current.policy.version.get(),
                            candidate.policy.version.get()
                        ),
                    ));
                }
                Some(CachedWallet::Tombstone {
                    policy_version,
                    wallet_revocation_epoch,
                    ..
                }) if candidate.policy.version.get() < policy_version.get()
                    || candidate.wallet.wallet_revocation_epoch.get()
                        <= wallet_revocation_epoch.get() =>
                {
                    return Err(ProtocolError::new(
                        ProtocolErrorCode::PolicyBaselineStale,
                        format!(
                            "Broker attempted to resurrect tombstoned wallet {wallet_id} with a stale policy version or revocation epoch"
                        ),
                    ));
                }
                _ => {}
            }
        }
        for previous in self.wallets.keys().cloned().collect::<Vec<_>>() {
            if !observed.contains_key(&previous) {
                let tombstone = match self.wallets.get(&previous) {
                    Some(CachedWallet::Live(projection)) => Some(CachedWallet::Tombstone {
                        policy_version: projection.wallet.policy_version.clone(),
                        wallet_revocation_epoch: projection.wallet.wallet_revocation_epoch.clone(),
                        response_digest: projection.response_digest.clone(),
                        observed_at_ms: now_ms()?,
                    }),
                    _ => None,
                };
                if let Some(tombstone) = tombstone {
                    self.wallets.insert(previous, tombstone);
                }
            }
        }
        for (wallet_id, projection) in observed {
            self.wallets
                .insert(wallet_id, CachedWallet::Live(projection));
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        if self.schema != CACHE_SCHEMA {
            return Err(unavailable(
                "Machine projection cache schema is unsupported",
            ));
        }
        for (wallet_id, cached) in &self.wallets {
            if let CachedWallet::Live(projection) = cached {
                if projection.wallet_id().as_str() != wallet_id {
                    return Err(unavailable(format!(
                        "Machine projection cache key does not match wallet {wallet_id}"
                    )));
                }
                validate_projection(projection).map_err(|error| {
                    unavailable(format!(
                        "Machine projection cache is invalid: {}",
                        error.message
                    ))
                })?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "projection")]
#[allow(clippy::large_enum_variant)]
enum CachedWallet {
    Live(WalletProjection),
    Tombstone {
        policy_version: bloom_broker_api::DecimalU64,
        wallet_revocation_epoch: bloom_broker_api::DecimalU64,
        response_digest: Digest32,
        observed_at_ms: u64,
    },
}

fn build_projection(
    wallet: WalletPublic,
    keys: Vec<KeyPublic>,
    credentials: Vec<CredentialPublic>,
    policy: SignedPolicySnapshot,
    observed_at_ms: u64,
) -> Result<WalletProjection, ProtocolError> {
    let response_digest = projection_digest(&wallet, &keys, &credentials, &policy)?;
    let projection = WalletProjection {
        wallet,
        keys,
        credentials,
        policy,
        source_protocol: SOURCE_PROTOCOL.to_owned(),
        response_digest,
        observed_at_ms,
        freshness: ProjectionFreshness::Fresh,
        verification: ProjectionVerification::AuthenticatedBroker,
    };
    validate_projection(&projection)?;
    Ok(projection)
}

fn validate_projection(projection: &WalletProjection) -> Result<(), ProtocolError> {
    if projection.source_protocol != SOURCE_PROTOCOL {
        return Err(invalid_projection("projection source protocol is invalid"));
    }
    if projection.freshness != ProjectionFreshness::Fresh {
        return Err(invalid_projection(
            "persisted projection freshness must be fresh-at-observation",
        ));
    }
    if projection.verification != ProjectionVerification::AuthenticatedBroker {
        return Err(invalid_projection(
            "projection verification status is invalid",
        ));
    }
    let wallet_id = &projection.wallet.wallet_id;
    if projection.policy.wallet_id != *wallet_id
        || projection.policy.version != projection.wallet.policy_version
        || projection.policy.policy_digest != projection.wallet.policy_digest
    {
        return Err(invalid_projection(format!(
            "wallet {} policy identity, version, or digest is inconsistent",
            wallet_id.as_str()
        )));
    }
    let policy_bytes = projection.policy.canonical_policy.decode();
    if Digest32::from_bytes(Sha256::digest(&policy_bytes).into()) != projection.policy.policy_digest
    {
        return Err(invalid_projection(format!(
            "wallet {} policy bytes do not match the signed digest",
            wallet_id.as_str()
        )));
    }
    if projection
        .credentials
        .iter()
        .any(|credential| credential.wallet_id != *wallet_id)
    {
        return Err(invalid_projection(format!(
            "wallet {} projection contains a foreign credential",
            wallet_id.as_str()
        )));
    }
    let key_refs = projection
        .keys
        .iter()
        .map(|key| serde_json::to_string(&key.key_ref))
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|error| invalid_projection(format!("encode public key reference: {error}")))?;
    match &projection.wallet.root_key_ref {
        Some(root) => {
            let encoded_root = serde_json::to_string(root).map_err(|error| {
                invalid_projection(format!("encode wallet root key reference: {error}"))
            })?;
            if !projection.wallet.key_refs.contains(root)
                || !projection
                    .keys
                    .iter()
                    .any(|key| key.key_ref == *root && key.role == KeyRole::WalletRoot)
                || projection
                    .keys
                    .iter()
                    .any(|key| key.role == KeyRole::WalletRoot && key.key_ref != *root)
                || !key_refs.contains(&encoded_root)
            {
                return Err(invalid_projection(format!(
                    "wallet {} root key projection is inconsistent",
                    wallet_id.as_str()
                )));
            }
        }
        None => {
            // A BIP-39 wallet has no signable root; only derived children.
            if projection
                .keys
                .iter()
                .any(|key| key.role == KeyRole::WalletRoot)
            {
                return Err(invalid_projection(format!(
                    "wallet {} projection claims a root for a BIP-39 wallet",
                    wallet_id.as_str()
                )));
            }
        }
    }
    for key_ref in &projection.wallet.key_refs {
        let encoded = serde_json::to_string(key_ref)
            .map_err(|error| invalid_projection(format!("encode wallet key reference: {error}")))?;
        if !key_refs.contains(&encoded) {
            return Err(invalid_projection(format!(
                "wallet {} references a key absent from its projection",
                wallet_id.as_str()
            )));
        }
    }
    if projection.response_digest
        != projection_digest(
            &projection.wallet,
            &projection.keys,
            &projection.credentials,
            &projection.policy,
        )?
    {
        return Err(invalid_projection(format!(
            "wallet {} response digest is invalid",
            wallet_id.as_str()
        )));
    }
    Ok(())
}

fn projection_digest(
    wallet: &WalletPublic,
    keys: &[KeyPublic],
    credentials: &[CredentialPublic],
    policy: &SignedPolicySnapshot,
) -> Result<Digest32, ProtocolError> {
    #[derive(Serialize)]
    struct DigestInput<'a> {
        schema: &'static str,
        wallet: &'a WalletPublic,
        keys: &'a [KeyPublic],
        credentials: &'a [CredentialPublic],
        policy: &'a SignedPolicySnapshot,
    }
    let bytes = serde_jcs::to_vec(&DigestInput {
        schema: CACHE_SCHEMA,
        wallet,
        keys,
        credentials,
        policy,
    })
    .map_err(|error| invalid_projection(format!("canonicalize projection: {error}")))?;
    Ok(Digest32::from_bytes(Sha256::digest(bytes).into()))
}

fn now_ms() -> Result<u64, ProtocolError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| unavailable("system clock precedes Unix epoch"))?;
    u64::try_from(duration.as_millis())
        .map_err(|_| unavailable("system time does not fit projection timestamp"))
}

fn invalid_projection(message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ProtocolErrorCode::BackendInvalidRequest, message)
}

fn unavailable(message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ProtocolErrorCode::ServiceUnavailable, message)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use bloom_broker_api::{
        Base64UrlBytes, CryptoSuite, DecimalU64, KeyRef, KeySpec, MachineBrokerRequest,
        MachineBrokerResponse, MachineBrokerService, ServiceFuture, WalletRequest,
    };

    use super::*;

    #[derive(Clone)]
    struct ProjectionFixture {
        wallet: WalletPublic,
        keys: Vec<KeyPublic>,
        credentials: Vec<CredentialPublic>,
        policy: SignedPolicySnapshot,
    }

    struct FakeBroker {
        available: Mutex<bool>,
        wallets: Mutex<BTreeMap<String, ProjectionFixture>>,
    }

    struct BlockingEmptyBroker {
        entered: Arc<tokio::sync::Semaphore>,
        release: Arc<tokio::sync::Semaphore>,
    }

    impl MachineBrokerService for BlockingEmptyBroker {
        fn dispatch<'a>(
            &'a self,
            request: MachineBrokerRequest,
        ) -> ServiceFuture<'a, MachineBrokerResponse> {
            Box::pin(async move {
                match request {
                    MachineBrokerRequest::WalletListPublic(_) => {
                        self.entered.add_permits(1);
                        self.release.acquire().await.unwrap().forget();
                        Ok(MachineBrokerResponse::WalletListPublic(Vec::new()))
                    }
                    _ => Err(invalid_projection("unexpected blocking Broker method")),
                }
            })
        }
    }

    impl FakeBroker {
        fn new(fixture: ProjectionFixture) -> Self {
            Self {
                available: Mutex::new(true),
                wallets: Mutex::new(BTreeMap::from([(
                    fixture.wallet.wallet_id.as_str().to_owned(),
                    fixture,
                )])),
            }
        }

        fn set_available(&self, available: bool) {
            *self.available.lock().unwrap() = available;
        }
    }

    impl MachineBrokerService for FakeBroker {
        fn dispatch<'a>(
            &'a self,
            request: MachineBrokerRequest,
        ) -> ServiceFuture<'a, MachineBrokerResponse> {
            Box::pin(async move {
                if !*self.available.lock().unwrap() {
                    return Err(unavailable("fake Broker unavailable"));
                }
                let wallets = self.wallets.lock().unwrap();
                let wallet_id = match &request {
                    MachineBrokerRequest::KeyListPublic(WalletRequest { wallet_id })
                    | MachineBrokerRequest::CredentialListPublic(WalletRequest { wallet_id })
                    | MachineBrokerRequest::PolicyRead(WalletRequest { wallet_id }) => {
                        Some(wallet_id.as_str())
                    }
                    _ => None,
                };
                let fixture = wallet_id
                    .and_then(|wallet_id| wallets.get(wallet_id))
                    .cloned();
                match request {
                    MachineBrokerRequest::WalletListPublic(_) => {
                        Ok(MachineBrokerResponse::WalletListPublic(
                            wallets.values().map(|value| value.wallet.clone()).collect(),
                        ))
                    }
                    MachineBrokerRequest::KeyListPublic(_) => fixture
                        .map(|value| MachineBrokerResponse::KeyListPublic(value.keys))
                        .ok_or_else(|| invalid_projection("unknown fake wallet")),
                    MachineBrokerRequest::CredentialListPublic(_) => fixture
                        .map(|value| MachineBrokerResponse::CredentialListPublic(value.credentials))
                        .ok_or_else(|| invalid_projection("unknown fake wallet")),
                    MachineBrokerRequest::PolicyRead(_) => fixture
                        .map(|value| MachineBrokerResponse::PolicyRead(value.policy))
                        .ok_or_else(|| invalid_projection("unknown fake wallet")),
                    _ => Err(invalid_projection("unexpected fake Broker method")),
                }
            })
        }
    }

    #[tokio::test]
    async fn refreshes_atomically_and_serves_explicitly_stale_cache() {
        let directory = tempfile::tempdir().unwrap();
        let store = FileProjectionStore::new(directory.path().join("wallets.json"));
        let broker = Arc::new(FakeBroker::new(fixture(2)));
        let reader = CachedWalletProjectionReader::new(
            Some(MachineBrokerClient::new(broker.clone())),
            store.clone(),
        )
        .unwrap();

        let live = reader.list_wallets().await.unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].freshness, ProjectionFreshness::Fresh);
        assert_eq!(
            live[0].primary_address().unwrap(),
            "0x0000000000000000000000000000000000000001"
        );
        assert!(store.path().is_file());

        broker.set_available(false);
        let restarted = CachedWalletProjectionReader::new(None, store).unwrap();
        let stale = restarted.get_wallet(&token("alice")).await.unwrap();
        assert_eq!(stale.freshness, ProjectionFreshness::Stale);
        assert_eq!(stale.policy.version.get(), 2);
    }

    #[test]
    fn primary_key_uses_the_declared_root_not_key_list_order() {
        let mut fixture = fixture(1);
        let mut derived = fixture.keys[0].clone();
        derived.key_ref.locator = "alice/derived/same-suite".into();
        derived.role = KeyRole::Derived;
        fixture.wallet.key_refs.insert(0, derived.key_ref.clone());
        fixture.keys.insert(0, derived);
        let expected_root = fixture.wallet.root_key_ref.clone().unwrap();
        let projection = build_projection(
            fixture.wallet,
            fixture.keys,
            fixture.credentials,
            fixture.policy,
            1,
        )
        .unwrap();
        assert_eq!(projection.primary_key().unwrap().key_ref, expected_root);
    }

    #[tokio::test]
    async fn rejects_policy_rollback_without_replacing_cached_generation() {
        let directory = tempfile::tempdir().unwrap();
        let store = FileProjectionStore::new(directory.path().join("wallets.json"));
        let broker = Arc::new(FakeBroker::new(fixture(2)));
        let reader = CachedWalletProjectionReader::new(
            Some(MachineBrokerClient::new(broker.clone())),
            store.clone(),
        )
        .unwrap();
        reader.list_wallets().await.unwrap();
        broker
            .wallets
            .lock()
            .unwrap()
            .insert("alice".into(), fixture(1));
        let error = reader.list_wallets().await.unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::PolicyBaselineStale);

        let cached = CachedWalletProjectionReader::new(None, store)
            .unwrap()
            .get_wallet(&token("alice"))
            .await
            .unwrap();
        assert_eq!(cached.policy.version.get(), 2);
    }

    #[tokio::test]
    async fn cross_process_style_stale_reader_cannot_overwrite_newer_cache() {
        let directory = tempfile::tempdir().unwrap();
        let store = FileProjectionStore::new(directory.path().join("wallets.json"));
        let stale_reader = CachedWalletProjectionReader::new(
            Some(MachineBrokerClient::new(Arc::new(FakeBroker::new(
                fixture(1),
            )))),
            store.clone(),
        )
        .unwrap();
        let current_reader = CachedWalletProjectionReader::new(
            Some(MachineBrokerClient::new(Arc::new(FakeBroker::new(
                fixture(2),
            )))),
            store.clone(),
        )
        .unwrap();
        current_reader.list_wallets().await.unwrap();

        let error = stale_reader.list_wallets().await.unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::PolicyBaselineStale);
        let durable = CachedWalletProjectionReader::new(None, store)
            .unwrap()
            .get_wallet(&token("alice"))
            .await
            .unwrap();
        assert_eq!(durable.policy.version.get(), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn full_refresh_lock_orders_observation_before_wallet_creation() {
        let directory = tempfile::tempdir().unwrap();
        let store = FileProjectionStore::new(directory.path().join("wallets.json"));
        let entered = Arc::new(tokio::sync::Semaphore::new(0));
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let old_reader = CachedWalletProjectionReader::new(
            Some(MachineBrokerClient::new(Arc::new(BlockingEmptyBroker {
                entered: entered.clone(),
                release: release.clone(),
            }))),
            store.clone(),
        )
        .unwrap();
        let new_reader = CachedWalletProjectionReader::new(
            Some(MachineBrokerClient::new(Arc::new(FakeBroker::new(
                fixture(1),
            )))),
            store.clone(),
        )
        .unwrap();

        let old_refresh = tokio::spawn(async move { old_reader.list_wallets().await });
        entered.acquire().await.unwrap().forget();
        let mut new_refresh = tokio::spawn(async move { new_reader.list_wallets().await });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut new_refresh)
                .await
                .is_err(),
            "a newer refresh must wait before observing while the older generation is in flight"
        );

        release.add_permits(1);
        assert!(old_refresh.await.unwrap().unwrap().is_empty());
        assert_eq!(new_refresh.await.unwrap().unwrap().len(), 1);
        let durable = CachedWalletProjectionReader::new(None, store)
            .unwrap()
            .get_wallet(&token("alice"))
            .await
            .unwrap();
        assert_eq!(durable.policy.version.get(), 1);
    }

    #[tokio::test]
    async fn tombstones_deleted_wallets_and_never_resurrects_them_offline() {
        let directory = tempfile::tempdir().unwrap();
        let store = FileProjectionStore::new(directory.path().join("wallets.json"));
        let broker = Arc::new(FakeBroker::new(fixture(1)));
        let reader = CachedWalletProjectionReader::new(
            Some(MachineBrokerClient::new(broker.clone())),
            store.clone(),
        )
        .unwrap();
        reader.list_wallets().await.unwrap();
        broker.wallets.lock().unwrap().clear();
        assert!(reader.list_wallets().await.unwrap().is_empty());
        broker
            .wallets
            .lock()
            .unwrap()
            .insert("alice".into(), fixture(1));
        let resurrection = reader.list_wallets().await.unwrap_err();
        assert_eq!(resurrection.code, ProtocolErrorCode::PolicyBaselineStale);
        broker.set_available(false);

        let restarted = CachedWalletProjectionReader::new(None, store).unwrap();
        let error = restarted.get_wallet(&token("alice")).await.unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::BackendInvalidRequest);
    }

    #[tokio::test]
    async fn tombstone_rejects_lower_policy_even_with_a_higher_revocation_epoch() {
        let directory = tempfile::tempdir().unwrap();
        let store = FileProjectionStore::new(directory.path().join("wallets.json"));
        let mut initial = fixture(2);
        initial.wallet.wallet_revocation_epoch = DecimalU64::new(1);
        let broker = Arc::new(FakeBroker::new(initial));
        let reader = CachedWalletProjectionReader::new(
            Some(MachineBrokerClient::new(broker.clone())),
            store,
        )
        .unwrap();
        reader.list_wallets().await.unwrap();
        broker.wallets.lock().unwrap().clear();
        assert!(reader.list_wallets().await.unwrap().is_empty());

        let mut rolled_back = fixture(1);
        rolled_back.wallet.wallet_revocation_epoch = DecimalU64::new(2);
        broker
            .wallets
            .lock()
            .unwrap()
            .insert("alice".into(), rolled_back);
        let error = reader.list_wallets().await.unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::PolicyBaselineStale);
    }

    #[test]
    fn altered_or_partial_cache_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wallets.json");
        fs::write(&path, b"{\"schema\":").unwrap();
        let error = CachedWalletProjectionReader::new(None, FileProjectionStore::new(&path))
            .err()
            .expect("partial cache must fail");
        assert_eq!(error.code, ProtocolErrorCode::ServiceUnavailable);

        let projection = build_projection(
            fixture(1).wallet,
            fixture(1).keys,
            fixture(1).credentials,
            fixture(1).policy,
            1,
        )
        .unwrap();
        let mut cache = ProjectionCache::empty();
        cache
            .wallets
            .insert("alice".into(), CachedWallet::Live(projection));
        let mut value = serde_json::to_value(cache).unwrap();
        value["wallets"]["alice"]["projection"]["observed_at_ms"] = 2.into();
        value["wallets"]["alice"]["projection"]["wallet"]["policy_version"] = "9".into();
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let error = CachedWalletProjectionReader::new(None, FileProjectionStore::new(&path))
            .err()
            .expect("altered cache must fail");
        assert_eq!(error.code, ProtocolErrorCode::ServiceUnavailable);
    }

    fn fixture(version: u64) -> ProjectionFixture {
        let wallet_id = token("alice");
        let key_ref = KeyRef {
            backend: token("local"),
            backend_instance: token("primary"),
            locator: "alice/root".into(),
            key_spec: KeySpec::Secp256k1,
            public_key_fingerprint: Digest32::from_bytes([3; 32]),
            derivation: None,
        };
        let policy_bytes = br#"{"wallet_id":"alice"}"#.to_vec();
        let policy_digest = Digest32::from_bytes(Sha256::digest(&policy_bytes).into());
        ProjectionFixture {
            wallet: WalletPublic {
                wallet_id: wallet_id.clone(),
                wallet_kind: token("passkey"),
                root_key_ref: Some(key_ref.clone()),
                key_refs: vec![key_ref.clone()],
                policy_version: DecimalU64::new(version),
                policy_digest: policy_digest.clone(),
                wallet_revocation_epoch: DecimalU64::new(0),
            },
            keys: vec![KeyPublic {
                key_ref,
                role: KeyRole::WalletRoot,
                canonical_public_key: Base64UrlBytes::from_bytes(&[4; 33]),
                addresses: vec!["0x0000000000000000000000000000000000000001".into()],
                supported_crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
            }],
            credentials: Vec::new(),
            policy: SignedPolicySnapshot {
                wallet_id,
                version: DecimalU64::new(version),
                canonical_policy: Base64UrlBytes::from_bytes(&policy_bytes),
                policy_digest,
                policy_signing_key_id: token("policy-key"),
                policy_verifying_key: Base64UrlBytes::from_bytes(&[5; 32]),
                signer_signature: Base64UrlBytes::from_bytes(&[6; 64]),
            },
        }
    }

    fn token(value: &str) -> Token {
        Token::new(value).unwrap()
    }
}
