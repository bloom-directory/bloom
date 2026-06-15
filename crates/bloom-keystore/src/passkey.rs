//! WebAuthn passkey ceremony helper for bloom.
//!
//! Spins up a short-lived local HTTP server on a fixed port, opens the system
//! browser, and awaits the completion of a WebAuthn registration or
//! authentication ceremony. The browser POSTs the credential JSON back to the
//! local server, which forwards it to `webauthn-rs` for verification.
//!
//! ## PRF-based key derivation
//! The passkey uses the WebAuthn PRF extension (pseudo-random function) to
//! derive a wrap key from the authenticator's internal secret. During each
//! ceremony, the browser extracts a 32-byte PRF output from the authenticator
//! and POSTs it to the local ceremony server. The Rust keystore then derives
//! `wrap_key = blake3::derive_key("bloom passkey wrap key", prf_output)` and
//! uses it to encrypt/decrypt the secp256k1 private key.
//!
//! `prf_salt` (32 random bytes, stored in `prf.salt`) is the input fed to the
//! authenticator's PRF. It is not secret. PRF output is never stored on disk.
//! Without the physical authenticator you cannot reproduce the PRF output and
//! therefore cannot decrypt the private key.
//!
//! ## RP identity
//! The Relying Party ID is `"localhost"`. For a local CLI daemon the
//! phishing-protection property of RP IDs is not relevant (no remote RP to
//! impersonate), and `localhost` keeps credentials portable across machines
//! and satisfies the WebAuthn origin-domain check.

use std::path::Path;
use std::sync::Arc;

use axum::extract::State;
use axum::http::header::{CACHE_CONTROL, PRAGMA};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use parking_lot::Mutex;
use rand::RngCore;
use url::Url;
use webauthn_rs::prelude::*;

use bloom_proto::CeremonyIntent;

// ── constants ────────────────────────────────────────────────────────────────

/// Fixed local port for the ceremony HTTP server. Chosen to avoid common
/// service ports. Fails with a clear error if already in use.
pub(crate) const CEREMONY_PORT: u16 = 18734;

/// Timeout for the authentication ceremony. The WebAuthn prompt fires
/// automatically on page load, so 120 s is ample.
const AUTH_TIMEOUT_SECS: u64 = 120;

/// Timeout for the registration ceremony. The user must read the policy
/// form and optionally edit fields before clicking — allow 5 minutes.
const REG_TIMEOUT_SECS: u64 = 300;

/// Port for the recovery-key display page (must differ from CEREMONY_PORT
/// so it can run immediately after the ceremony without a bind conflict).
const RECOVERY_PORT: u16 = 18735;

/// Timeout for the recovery-key display page.
const RECOVERY_TIMEOUT_SECS: u64 = 300;

/// WebAuthn Relying Party ID for all bloom passkey credentials.
pub(crate) const RP_ID: &str = "localhost";

/// Error text shown when the authenticator does not support the PRF extension.
/// Referenced from both the Rust ceremony path and (via const) from lib.rs.
pub(crate) const PRF_NOT_SUPPORTED_MSG: &str = "PRF output not received from authenticator. \
     Bloom requires the WebAuthn PRF extension for passkey wallets. \
     Supported authenticators: Touch ID (macOS/iOS), YubiKey 5+, \
     Windows Hello (Chrome 147+), security keys with hmac-secret.";

// ── browser launcher ──────────────────────────────────────────────────────────

/// Open the ceremony URL in the default browser.
///
/// Normal (non-incognito) mode is used so the OS credential store persists
/// the passkey across sessions. If a browser extension interferes with the
/// WebAuthn API, the in-page error message advises the user to open the URL
/// manually in an incognito/private window — but we do not force that by
/// default because incognito windows on Linux do NOT persist passkeys to the
/// OS keychain, which is exactly the failure mode we are avoiding.
///
/// Returns an error if no browser could be launched.
fn launch_browser(url: &str) -> Result<(), String> {
    let browsers: &[&str] = &[
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chrome",
        "firefox", // last: Firefox on Linux has no built-in passkey manager
                   // and does not support WebAuthn PRF — the ceremony page
                   // will show the unsupported-authenticator error message.
    ];
    for name in browsers {
        if std::process::Command::new(name)
            .arg(url)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .is_ok()
        {
            return Ok(());
        }
    }
    // macOS: try Chrome / Chromium via `open -a` (no --incognito).
    #[cfg(target_os = "macos")]
    {
        for app in &["Google Chrome", "Chromium"] {
            if std::process::Command::new("open")
                .args(["-a", app, url])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .is_ok()
            {
                return Ok(());
            }
        }
    }
    // Fall back to the system default browser.
    open::that(url)
        .map_err(|e| format!("could not open browser: {e} (install Chrome, Chromium, or Firefox)"))
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Inject PRF extension into a WebAuthn challenge JSON value.
/// Merges into existing extensions rather than replacing them.
fn inject_prf_into_challenge_json(
    mut v: serde_json::Value,
    prf_salt: &[u8; 32],
) -> serde_json::Value {
    let prf_salt_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(prf_salt);
    if let Some(pk) = v["publicKey"].as_object_mut() {
        let exts = pk
            .entry("extensions".to_string())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        if let Some(obj) = exts.as_object_mut() {
            obj.insert(
                "prf".to_string(),
                serde_json::json!({ "eval": { "first": prf_salt_b64 } }),
            );
        }
    }
    v
}

/// Bind a local TCP listener on `127.0.0.1:{port}`. `ctx` is used in error
/// messages to identify which server failed (e.g. "passkey ceremony").
fn bind_local(port: u16, ctx: &str) -> Result<tokio::net::TcpListener, String> {
    let sock = tokio::net::TcpSocket::new_v4().map_err(|e| format!("create {ctx} socket: {e}"))?;
    sock.set_reuseaddr(true)
        .map_err(|e| format!("SO_REUSEADDR: {e}"))?;
    sock.bind(format!("127.0.0.1:{port}").parse().expect("valid addr"))
        .map_err(|e| format!("cannot bind port {port} for {ctx}: {e}"))?;
    sock.listen(128).map_err(|e| format!("listen: {e}"))
}

fn default_unlock_intent(wallet_name: &str, wallet_dir: &Path) -> CeremonyIntent {
    let mut intent = CeremonyIntent::new(
        wallet_name,
        "Unlock Wallet",
        bloom_proto::CeremonyIntentKind::WalletUnlock,
    );
    intent.wallet_address = std::fs::read_to_string(wallet_dir.join("address"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    intent
        .summary_lines
        .push("Unlock wallet key for this foreground command.".into());
    intent
        .risk_lines
        .push("The OS passkey prompt will show bloom/localhost, not transaction details.".into());
    intent.canonical_subject = serde_json::json!({
        "kind": "wallet_unlock",
        "wallet": wallet_name,
        "address": intent.wallet_address,
    });
    intent
}

// ── builder ──────────────────────────────────────────────────────────────────

fn build_webauthn() -> Result<Webauthn, String> {
    let origin =
        Url::parse(&format!("http://localhost:{CEREMONY_PORT}")).map_err(|e| e.to_string())?;
    WebauthnBuilder::new(RP_ID, &origin)
        .map_err(|e| format!("WebauthnBuilder: {e}"))?
        .rp_name("bloom")
        .build()
        .map_err(|e| format!("Webauthn build: {e}"))
}

// ── registration ─────────────────────────────────────────────────────────────

/// Run a WebAuthn registration ceremony for `wallet_name` with PRF key
/// derivation. Opens `http://localhost:CEREMONY_PORT` in the default browser
/// and blocks until the ceremony completes or the timeout elapses.
///
/// `prf_salt` is a 32-byte value generated by the caller and stored in
/// `prf.salt` (public, not secret). It is embedded in the challenge so the
/// authenticator's PRF function produces a deterministic output for this
/// wallet. The returned PRF output is the raw 32-byte value from the
/// authenticator — never store it; use it to derive `wrap_key` via BLAKE3.
///
/// `policy_toml` is the wallet's initial policy content. It is served at
/// `/policy` so the registration page can display spend limits before the
/// user completes the ceremony.
pub(crate) async fn register_ceremony(
    wallet_name: &str,
    policy_toml: &str,
    prf_salt: &[u8; 32],
) -> Result<(Passkey, String, [u8; 32]), String> {
    let webauthn = build_webauthn()?;

    // Derive a stable UUID from the wallet name so re-registrations on the
    // same machine map to the same resident-key slot.  We do this with
    // blake3 (already in the dependency tree) rather than requiring the
    // uuid crate's `v5` feature.
    let hash = blake3::hash(wallet_name.as_bytes());
    let mut uuid_bytes = [0u8; 16];
    uuid_bytes.copy_from_slice(&hash.as_bytes()[..16]);
    uuid_bytes[6] = (uuid_bytes[6] & 0x0f) | 0x50; // version = 5
    uuid_bytes[8] = (uuid_bytes[8] & 0x3f) | 0x80; // variant = RFC 4122
    let user_id = Uuid::from_bytes(uuid_bytes);
    let (ccr, reg_state) = webauthn
        .start_passkey_registration(user_id, wallet_name, wallet_name, None)
        .map_err(|e| format!("start_passkey_registration: {e}"))?;

    let mut challenge_json = serde_json::to_string(&ccr).map_err(|e| e.to_string())?;

    // Patch the challenge JSON to (a) require resident keys and (b) inject
    // the PRF extension. webauthn-rs 0.5.5 has no non-attested resident-key
    // API and no PRF API. Drop this patch block when those are added upstream.
    {
        let mut v: serde_json::Value =
            serde_json::from_str(&challenge_json).map_err(|e| e.to_string())?;
        if let Some(sel) = v["publicKey"]["authenticatorSelection"].as_object_mut() {
            sel.insert("requireResidentKey".into(), serde_json::Value::Bool(true));
            sel.insert(
                "residentKey".into(),
                serde_json::Value::String("required".into()),
            );
        } else {
            tracing::warn!(
                "challenge JSON missing authenticatorSelection — QR code cross-device flow may not be offered"
            );
        }
        let v = inject_prf_into_challenge_json(v, prf_salt);
        challenge_json = serde_json::to_string(&v).map_err(|e| e.to_string())?;
    }

    let (tx, rx) = tokio::sync::oneshot::channel::<RegisterPublicKeyCredential>();
    let challenge_b64 = extract_challenge_b64(&challenge_json);
    let state = RegState {
        challenge_json,
        challenge_b64,
        wallet_name: wallet_name.to_string(),
        token: gen_token(),
        prf_output: Arc::new(Mutex::new(None)),
        fallback_challenge: Arc::new(Mutex::new(None)),
        policy_toml: Arc::new(Mutex::new(policy_toml.to_string())),
        tx: Arc::new(Mutex::new(Some(tx))),
        shutdown: Arc::new(tokio::sync::Notify::new()),
    };

    let listener = bind_local(CEREMONY_PORT, "passkey ceremony")?;
    let app = build_reg_app(state.clone());
    let shutdown = state.shutdown.clone();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move { shutdown.notified().await })
            .await;
    });

    let url = format!("http://localhost:{CEREMONY_PORT}/?t={}", state.token);
    eprintln!(
        "[bloom] Opening browser for passkey registration — \
         complete the ceremony at {url}"
    );
    if let Err(e) = launch_browser(&url) {
        state.shutdown.notify_one();
        let _ = server.await;
        return Err(e);
    }

    let rpkc =
        match tokio::time::timeout(std::time::Duration::from_secs(REG_TIMEOUT_SECS), rx).await {
            Ok(Ok(cred)) => cred,
            Ok(Err(_)) => {
                state.shutdown.notify_one();
                let _ = server.await;
                return Err("ceremony cancelled (browser closed without completing)".into());
            }
            Err(_) => {
                state.shutdown.notify_one();
                let _ = server.await;
                return Err(format!("ceremony timed out after {REG_TIMEOUT_SECS}s"));
            }
        };

    state.shutdown.notify_one();
    let _ = server.await;

    let passkey = webauthn
        .finish_passkey_registration(&rpkc, &reg_state)
        .map_err(|e| format!("finish_passkey_registration: {e}"))?;
    let final_policy = state.policy_toml.lock().clone();

    // PRF output must have arrived before /register was POSTed (JS awaits
    // /prf-output before calling fetch('/register')).
    let prf_output = state
        .prf_output
        .lock()
        .take()
        .ok_or_else(|| PRF_NOT_SUPPORTED_MSG.to_string())?;

    Ok((passkey, final_policy, prf_output))
}

// ── authentication ────────────────────────────────────────────────────────────

/// Run a WebAuthn authentication ceremony against a stored `credential`.
/// Opens the browser and blocks until completion or timeout.
///
/// If `prf_salt` is `Some`, the PRF extension is injected into the auth
/// challenge so the authenticator produces PRF output. The browser POSTs
/// it to `/prf-output`; the returned tuple includes `Some(prf_output)`.
///
/// If `prf_salt` is `None` (legacy/non-PRF path), no PRF extension is
/// injected and the second element of the return tuple is `None`.
///
/// Returns `(AuthenticationResult, Option<prf_output>, Option<edited_policy>)`.
/// The caller must update the credential counter if `auth_result.needs_update()`.
pub(crate) async fn auth_ceremony(
    credential: &Passkey,
    prf_salt: Option<&[u8; 32]>,
    intent: Option<CeremonyIntent>,
    editable_policy: Option<String>,
) -> Result<(AuthenticationResult, Option<[u8; 32]>, Option<String>), String> {
    let webauthn = build_webauthn()?;

    let (rcr, auth_state) = webauthn
        .start_passkey_authentication(std::slice::from_ref(credential))
        .map_err(|e| format!("start_passkey_authentication: {e}"))?;

    let mut challenge_json = serde_json::to_string(&rcr).map_err(|e| e.to_string())?;

    // Inject PRF extension if a salt is provided.
    if let Some(salt) = prf_salt {
        let v: serde_json::Value =
            serde_json::from_str(&challenge_json).map_err(|e| e.to_string())?;
        let v = inject_prf_into_challenge_json(v, salt);
        challenge_json = serde_json::to_string(&v).map_err(|e| e.to_string())?;
    }

    let (tx, rx) = tokio::sync::oneshot::channel::<PublicKeyCredential>();
    let challenge_b64 = extract_challenge_b64(&challenge_json);
    let state = AuthState {
        challenge_json,
        challenge_b64,
        token: gen_token(),
        intent: Arc::new(Mutex::new(intent)),
        editable_policy: Arc::new(Mutex::new(editable_policy)),
        reviewed: Arc::new(Mutex::new(false)),
        prf_output: Arc::new(Mutex::new(None)),
        fallback_challenge: Arc::new(Mutex::new(None)),
        tx: Arc::new(Mutex::new(Some(tx))),
        shutdown: Arc::new(tokio::sync::Notify::new()),
    };

    let listener = bind_local(CEREMONY_PORT, "passkey ceremony")?;
    let app = build_auth_app(state.clone());
    let shutdown = state.shutdown.clone();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move { shutdown.notified().await })
            .await;
    });

    let url = format!("http://localhost:{CEREMONY_PORT}/?t={}", state.token);
    eprintln!(
        "[bloom] Opening browser for passkey authentication — \
         complete the ceremony at {url}"
    );
    if let Some(intent) = state.intent.lock().as_ref() {
        eprintln!(
            "[bloom] Review intent: {} ({})",
            intent.title,
            intent.intent_hash()
        );
    }
    if let Err(e) = launch_browser(&url) {
        state.shutdown.notify_one();
        let _ = server.await;
        return Err(e);
    }

    let pkc =
        match tokio::time::timeout(std::time::Duration::from_secs(AUTH_TIMEOUT_SECS), rx).await {
            Ok(Ok(cred)) => cred,
            Ok(Err(_)) => {
                state.shutdown.notify_one();
                let _ = server.await;
                return Err("ceremony cancelled (browser closed without completing)".into());
            }
            Err(_) => {
                state.shutdown.notify_one();
                let _ = server.await;
                return Err(format!("ceremony timed out after {AUTH_TIMEOUT_SECS}s"));
            }
        };

    state.shutdown.notify_one();
    let _ = server.await;

    let auth_result = webauthn
        .finish_passkey_authentication(&pkc, &auth_state)
        .map_err(|e| format!("finish_passkey_authentication: {e}"))?;

    let prf_output = state.prf_output.lock().take();
    let edited_policy = state.editable_policy.lock().take();
    Ok((auth_result, prf_output, edited_policy))
}

// ── axum apps ─────────────────────────────────────────────────────────────────

/// Body sent to POST /prf-output. The bundled clientDataJSON lets the server
/// check the PRF output was produced for the challenge it issued, which stops a
/// cross-tab *browser* script from racing in a forged output. It does NOT by
/// itself stop a local non-browser process (which can spoof `Origin` and read
/// the challenge from GET /challenge) — that is what the per-server capability
/// token enforced by `require_token` is for.
#[derive(serde::Deserialize)]
struct PrfOutputBody {
    prf_output_b64: String,
    client_data_json_b64: String,
}

/// Extract the base64url-encoded challenge from a serialised WebAuthn
/// challenge JSON object (shape: `{"publicKey":{"challenge":"<b64url>",…}}`).
fn extract_challenge_b64(challenge_json: &str) -> String {
    serde_json::from_str::<serde_json::Value>(challenge_json)
        .ok()
        .and_then(|v| {
            v.get("publicKey")?
                .get("challenge")?
                .as_str()
                .map(str::to_string)
        })
        .unwrap_or_default()
}

fn parse_prf_output_body(
    body: &PrfOutputBody,
    main_challenge: &str,
    fallback: &Mutex<Option<String>>,
) -> Result<[u8; 32], axum::http::StatusCode> {
    use base64::Engine as _;
    let Ok(bytes) =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(body.prf_output_b64.trim())
    else {
        return Err(axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    };
    if bytes.len() != 32 {
        return Err(axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }
    if !prf_challenge_ok(&body.client_data_json_b64, main_challenge, fallback) {
        return Err(axum::http::StatusCode::FORBIDDEN);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn issue_fallback_challenge(fallback_challenge: &Mutex<Option<String>>) -> Json<serde_json::Value> {
    let mut challenge = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge);
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge);
    *fallback_challenge.lock() = Some(b64.clone());
    Json(serde_json::json!({ "challenge": b64 }))
}

/// Verify that the `clientDataJSON` supplied by the browser contains a
/// `challenge` field matching either the main ceremony challenge or the
/// stored fallback challenge (used on the secondary `credentials.get()` path).
fn prf_challenge_ok(
    client_data_json_b64: &str,
    main_challenge: &str,
    fallback: &Mutex<Option<String>>,
) -> bool {
    use base64::Engine as _;
    let Ok(bytes) =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(client_data_json_b64.trim())
    else {
        return false;
    };
    let Ok(cdj) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    let Some(got) = cdj.get("challenge").and_then(|v| v.as_str()) else {
        return false;
    };
    got == main_challenge || fallback.lock().as_deref() == Some(got)
}

#[derive(Clone)]
struct RegState {
    challenge_json: String,
    /// Base64url of the challenge bytes sent to the browser (extracted from
    /// `challenge_json` at construction time for fast comparison).
    challenge_b64: String,
    wallet_name: String,
    /// Per-server capability token embedded in the launched URL; required on
    /// state-changing requests by `require_token`.
    token: String,
    /// Filled by POST /prf-output once the browser extracts PRF output from
    /// the authenticator.
    prf_output: Arc<Mutex<Option<[u8; 32]>>>,
    /// Set by GET /auth-challenge when the browser needs a second ceremony
    /// to extract PRF output (the `prf.enabled=true` fallback path).
    fallback_challenge: Arc<Mutex<Option<String>>>,
    /// Shared mutable policy TOML — updated when the user edits fields in the
    /// browser before completing the ceremony.
    policy_toml: Arc<Mutex<String>>,
    tx: Arc<Mutex<Option<tokio::sync::oneshot::Sender<RegisterPublicKeyCredential>>>>,
    shutdown: Arc<tokio::sync::Notify>,
}

/// Returns `true` if the request is allowed through the origin check.
/// POST requests must carry `Origin: http://localhost:<port>`; all other
/// methods are unconditionally allowed (no Origin header on same-origin GETs).
fn origin_ok(req: &axum::extract::Request, port: u16) -> bool {
    if req.method() != axum::http::Method::POST {
        return true;
    }
    let expected = format!("http://localhost:{port}");
    req.headers()
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|o| o.eq_ignore_ascii_case(&expected))
}

/// Axum middleware that rejects POST requests whose `Origin` header is not
/// exactly `http://localhost:<CEREMONY_PORT>`. This prevents a cross-site
/// script running in another browser tab from racing to inject a fake PRF
/// output before the legitimate ceremony page does.
async fn require_localhost_origin(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    if !origin_ok(&req, CEREMONY_PORT) {
        return axum::http::StatusCode::FORBIDDEN.into_response();
    }
    next.run(req).await
}

/// Same as `require_localhost_origin` but for the recovery-key page, which
/// runs on `RECOVERY_PORT` (18735), not `CEREMONY_PORT` (18734).
async fn require_recovery_origin(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    if !origin_ok(&req, RECOVERY_PORT) {
        return axum::http::StatusCode::FORBIDDEN.into_response();
    }
    next.run(req).await
}

/// Generate an unguessable 256-bit capability token (base64url, no pad). It is
/// embedded in the URL bloom opens and required on every state-changing request
/// (and the recovery `/data` read), binding the loopback server to the browser
/// page bloom launched.
fn gen_token() -> String {
    let mut t = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut t);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(t)
}

/// Capability-token gate. POSTs (and the recovery-page `GET /data`) must carry
/// an `x-bloom-token` header equal to the per-server token embedded in the URL
/// bloom opened. The `Origin` header is trivially spoofable by a local
/// non-browser process and the challenge is readable via `GET /challenge`, so
/// the origin check alone does not stop a local process from POSTing a forged
/// PRF output or scraping the recovery key. The token — never sent to the
/// network, only present in the URL bloom launched — closes that gap.
async fn require_token(
    axum::extract::State(token): axum::extract::State<String>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    let sensitive = req.method() == axum::http::Method::POST
        || (req.method() == axum::http::Method::GET && req.uri().path() == "/data");
    if sensitive {
        let ok = req
            .headers()
            .get("x-bloom-token")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|t| t == token);
        if !ok {
            return axum::http::StatusCode::FORBIDDEN.into_response();
        }
    }
    next.run(req).await
}

fn build_reg_app(state: RegState) -> Router {
    let token = state.token.clone();
    Router::new()
        .route("/", get(reg_index))
        .route("/challenge", get(reg_challenge))
        .route("/name", get(reg_name))
        .route("/policy", get(reg_policy))
        .route("/policy/update", post(reg_policy_update))
        .route("/prf-output", post(reg_prf_output))
        .route("/auth-challenge", get(reg_auth_challenge))
        .route("/register", post(reg_post))
        .layer(axum::middleware::from_fn(require_localhost_origin))
        .layer(axum::middleware::from_fn_with_state(token, require_token))
        .with_state(state)
}

async fn reg_index() -> Html<&'static str> {
    Html(REGISTER_HTML)
}

async fn reg_challenge(
    State(state): State<RegState>,
) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
    serde_json::from_str(&state.challenge_json)
        .map(Json)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)
}

async fn reg_name(State(state): State<RegState>) -> impl axum::response::IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )],
        state.wallet_name.clone(),
    )
}

async fn reg_policy(State(state): State<RegState>) -> impl axum::response::IntoResponse {
    let toml = state.policy_toml.lock().clone();
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )],
        toml,
    )
}

async fn reg_policy_update(State(state): State<RegState>, body: String) -> axum::http::StatusCode {
    // Validate before accepting — must parse as a valid Policy (not just valid TOML).
    if toml::from_str::<bloom_proto::Policy>(&body).is_err() {
        return axum::http::StatusCode::UNPROCESSABLE_ENTITY;
    }
    *state.policy_toml.lock() = body;
    axum::http::StatusCode::OK
}

async fn reg_prf_output(
    State(state): State<RegState>,
    Json(body): Json<PrfOutputBody>,
) -> axum::http::StatusCode {
    match parse_prf_output_body(&body, &state.challenge_b64, &state.fallback_challenge) {
        Ok(arr) => {
            // Reject a second PRF output rather than letting a late/racing POST
            // overwrite the first — the value is consumed only at /register.
            let mut g = state.prf_output.lock();
            if g.is_some() {
                return axum::http::StatusCode::CONFLICT;
            }
            *g = Some(arr);
            axum::http::StatusCode::OK
        }
        Err(status) => status,
    }
}

/// Issue a random challenge for the fallback PRF extraction flow (registration).
async fn reg_auth_challenge(State(state): State<RegState>) -> Json<serde_json::Value> {
    issue_fallback_challenge(&state.fallback_challenge)
}

/// Issue a random challenge for the fallback PRF extraction flow (authentication).
async fn auth_auth_challenge(State(state): State<AuthState>) -> Json<serde_json::Value> {
    if !*state.reviewed.lock() {
        return Json(serde_json::json!({ "error": "review_required" }));
    }
    issue_fallback_challenge(&state.fallback_challenge)
}

async fn reg_post(
    State(state): State<RegState>,
    Json(cred): Json<RegisterPublicKeyCredential>,
) -> axum::http::StatusCode {
    let sent = state
        .tx
        .lock()
        .take()
        .is_some_and(|tx| tx.send(cred).is_ok());
    state.shutdown.notify_one();
    if sent {
        axum::http::StatusCode::OK
    } else {
        // Receiver was already dropped (ceremony timed out) — the credential is
        // discarded; tell the browser so it does not show a false success.
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    }
}

// ──

#[derive(Clone)]
struct AuthState {
    challenge_json: String,
    /// Base64url of the challenge bytes sent to the browser.
    challenge_b64: String,
    /// Per-server capability token embedded in the launched URL; required on
    /// state-changing requests by `require_token`.
    token: String,
    /// Human-review payload displayed before WebAuthn starts.
    intent: Arc<Mutex<Option<CeremonyIntent>>>,
    /// Optional editable policy draft. When present, `/policy-edit` updates
    /// both this text and the intent digest shown on the review page.
    editable_policy: Arc<Mutex<Option<String>>>,
    /// Set by POST /reviewed when the user clicks the review-page approval.
    reviewed: Arc<Mutex<bool>>,
    /// Filled by POST /prf-output.
    prf_output: Arc<Mutex<Option<[u8; 32]>>>,
    /// Set by GET /auth-challenge on the fallback PRF extraction path.
    fallback_challenge: Arc<Mutex<Option<String>>>,
    tx: Arc<Mutex<Option<tokio::sync::oneshot::Sender<PublicKeyCredential>>>>,
    shutdown: Arc<tokio::sync::Notify>,
}

fn build_auth_app(state: AuthState) -> Router {
    let token = state.token.clone();
    Router::new()
        .route("/", get(auth_index))
        .route("/intent.json", get(auth_intent))
        .route("/reviewed", post(auth_reviewed))
        .route("/reject", post(auth_reject))
        .route("/edit-policy", post(auth_edit_policy))
        .route("/policy-edit", post(auth_policy_edit))
        .route("/policy-autonomy", post(auth_policy_autonomy))
        .route("/challenge", get(auth_challenge))
        .route("/auth-challenge", get(auth_auth_challenge))
        .route("/prf-output", post(auth_prf_output))
        .route("/auth", post(auth_post))
        .layer(axum::middleware::from_fn(require_localhost_origin))
        .layer(axum::middleware::from_fn_with_state(token, require_token))
        .with_state(state)
}

async fn auth_index() -> Response {
    (
        [
            (CACHE_CONTROL, "no-store, no-cache, must-revalidate"),
            (PRAGMA, "no-cache"),
        ],
        Html(AUTH_HTML),
    )
        .into_response()
}

async fn auth_intent(State(state): State<AuthState>) -> Response {
    let intent = state.intent.lock().clone().unwrap_or_else(|| {
        CeremonyIntent::new(
            "unknown",
            "Unlock Wallet",
            bloom_proto::CeremonyIntentKind::WalletUnlock,
        )
    });
    (
        [
            (CACHE_CONTROL, "no-store, no-cache, must-revalidate"),
            (PRAGMA, "no-cache"),
        ],
        Json(serde_json::json!({
            "intent": intent,
            "intent_hash": intent.intent_hash(),
        })),
    )
        .into_response()
}

async fn auth_reviewed(State(state): State<AuthState>) -> axum::http::StatusCode {
    *state.reviewed.lock() = true;
    axum::http::StatusCode::OK
}

async fn auth_reject(State(state): State<AuthState>) -> axum::http::StatusCode {
    state.tx.lock().take();
    state.shutdown.notify_one();
    axum::http::StatusCode::OK
}

async fn auth_edit_policy(State(state): State<AuthState>) -> axum::http::StatusCode {
    *state.reviewed.lock() = false;
    axum::http::StatusCode::OK
}

#[derive(Debug, serde::Deserialize)]
struct PolicyEditBody {
    policy_text: String,
}

#[derive(Debug, serde::Deserialize)]
struct PolicyAutonomyBody {
    mode: String,
}

fn set_policy_autonomy(text: &str, mode: &str) -> Result<String, String> {
    if !matches!(mode, "prompt_all" | "under_policy") {
        return Err("expected mode prompt_all or under_policy".into());
    }

    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    if text.ends_with('\n') {
        lines.push(String::new());
    }

    let mut approval_start = None;
    let mut approval_end = lines.len();
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') && trimmed == "[approval]" {
            approval_start = Some(idx);
            approval_end = lines.len();
            for (j, later) in lines.iter().enumerate().skip(idx + 1) {
                let t = later.trim();
                if t.starts_with('[') && t.ends_with(']') {
                    approval_end = j;
                    break;
                }
            }
            break;
        }
    }

    match approval_start {
        Some(start) => {
            let mut replaced = false;
            for line in lines.iter_mut().take(approval_end).skip(start + 1) {
                if line.trim_start().starts_with("agent_autonomy") {
                    *line = format!("agent_autonomy = \"{mode}\"");
                    replaced = true;
                    break;
                }
            }
            if !replaced {
                lines.insert(start + 1, format!("agent_autonomy = \"{mode}\""));
            }
        }
        None => {
            lines.splice(
                0..0,
                [
                    "[approval]".to_string(),
                    format!("agent_autonomy = \"{mode}\""),
                    String::new(),
                ],
            );
        }
    }

    let updated = lines.join("\n");
    toml::from_str::<bloom_proto::Policy>(&updated)
        .map_err(|e| format!("policy would be invalid after changing autonomy: {e}"))?;
    Ok(updated)
}

fn update_policy_intent(state: &AuthState, policy_text: &str) -> String {
    let digest = blake3::hash(policy_text.as_bytes()).to_hex().to_string();
    if let Some(intent) = state.intent.lock().as_mut() {
        intent.policy_lines = policy_text.lines().map(str::to_string).collect();
        for line in &mut intent.summary_lines {
            if line.starts_with("Policy digest: ") {
                *line = format!("Policy digest: {digest}");
            }
        }
        if let Some(obj) = intent.canonical_subject.as_object_mut() {
            obj.insert(
                "policy_blake3".to_string(),
                serde_json::Value::String(digest.clone()),
            );
        }
    }
    digest
}

async fn auth_policy_edit(
    State(state): State<AuthState>,
    Json(body): Json<PolicyEditBody>,
) -> Response {
    if state.editable_policy.lock().is_none() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": "this review does not have an editable policy draft"
            })),
        )
            .into_response();
    }
    if let Err(e) = toml::from_str::<bloom_proto::Policy>(&body.policy_text) {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": format!("invalid policy.toml: {e}")
            })),
        )
            .into_response();
    }
    *state.reviewed.lock() = false;
    *state.editable_policy.lock() = Some(body.policy_text.clone());
    let digest = update_policy_intent(&state, &body.policy_text);
    (
        axum::http::StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "policy_blake3": digest })),
    )
        .into_response()
}

async fn auth_policy_autonomy(
    State(state): State<AuthState>,
    Json(body): Json<PolicyAutonomyBody>,
) -> Response {
    let Some(current) = state.editable_policy.lock().clone() else {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": "this review does not have an editable policy draft"
            })),
        )
            .into_response();
    };
    let updated = match set_policy_autonomy(&current, body.mode.trim()) {
        Ok(updated) => updated,
        Err(e) => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            )
                .into_response();
        }
    };
    *state.reviewed.lock() = false;
    *state.editable_policy.lock() = Some(updated.clone());
    let digest = update_policy_intent(&state, &updated);
    (
        axum::http::StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "mode": body.mode.trim(),
            "policy_blake3": digest
        })),
    )
        .into_response()
}

async fn auth_challenge(
    State(state): State<AuthState>,
) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
    if !*state.reviewed.lock() {
        return Err(axum::http::StatusCode::PRECONDITION_REQUIRED);
    }
    serde_json::from_str(&state.challenge_json)
        .map(Json)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)
}

async fn auth_prf_output(
    State(state): State<AuthState>,
    Json(body): Json<PrfOutputBody>,
) -> axum::http::StatusCode {
    if !*state.reviewed.lock() {
        return axum::http::StatusCode::PRECONDITION_REQUIRED;
    }
    match parse_prf_output_body(&body, &state.challenge_b64, &state.fallback_challenge) {
        Ok(arr) => {
            // Reject a second PRF output rather than letting a late/racing POST
            // overwrite the first — the value is consumed only at /auth.
            let mut g = state.prf_output.lock();
            if g.is_some() {
                return axum::http::StatusCode::CONFLICT;
            }
            *g = Some(arr);
            axum::http::StatusCode::OK
        }
        Err(status) => status,
    }
}

async fn auth_post(
    State(state): State<AuthState>,
    Json(cred): Json<PublicKeyCredential>,
) -> axum::http::StatusCode {
    if !*state.reviewed.lock() {
        return axum::http::StatusCode::PRECONDITION_REQUIRED;
    }
    let sent = state
        .tx
        .lock()
        .take()
        .is_some_and(|tx| tx.send(cred).is_ok());
    state.shutdown.notify_one();
    if sent {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    }
}

// ── HTML pages ────────────────────────────────────────────────────────────────

const REGISTER_HTML: &str = include_str!("passkey_register.html");

const AUTH_HTML: &str = include_str!("passkey_auth.html");

// ── recovery key display ──────────────────────────────────────────────────────

/// Open a browser page that shows the recovery key for a newly created or
/// rebound passkey wallet. Blocks until the user confirms they have stored
/// it (POST /done) or the timeout elapses. The caller must already have
/// printed the key to stderr as a fallback — this is the visual display.
pub(crate) async fn display_recovery_key(
    wallet_name: &str,
    recovery_key_hex: &str,
) -> Result<(), String> {
    let state = RecoveryState {
        wallet_name: wallet_name.to_string(),
        recovery_key_hex: recovery_key_hex.to_string(),
        token: gen_token(),
        done: Arc::new(tokio::sync::Notify::new()),
        shutdown: Arc::new(tokio::sync::Notify::new()),
    };

    let app = build_recovery_app(state.clone());
    let listener = bind_local(RECOVERY_PORT, "recovery key page")?;
    let shutdown = state.shutdown.clone();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move { shutdown.notified().await })
            .await;
    });

    let url = format!("http://localhost:{RECOVERY_PORT}/?t={}", state.token);
    eprintln!("[bloom] Recovery key page: {url}");
    if let Err(e) = launch_browser(&url) {
        state.shutdown.notify_one();
        let _ = server.await;
        return Err(e);
    }

    let timed_out = tokio::time::timeout(
        std::time::Duration::from_secs(RECOVERY_TIMEOUT_SECS),
        state.done.notified(),
    )
    .await
    .is_err();

    state.shutdown.notify_one();
    let _ = server.await;

    if timed_out {
        eprintln!("[bloom] Recovery key page timed out after {RECOVERY_TIMEOUT_SECS}s");
        Err(format!(
            "recovery key page timed out after {RECOVERY_TIMEOUT_SECS}s"
        ))
    } else {
        Ok(())
    }
}

#[derive(Clone)]
struct RecoveryState {
    wallet_name: String,
    recovery_key_hex: String,
    /// Per-server capability token embedded in the launched URL; required on
    /// `GET /data` and `POST /done` by `require_token`.
    token: String,
    done: Arc<tokio::sync::Notify>,
    shutdown: Arc<tokio::sync::Notify>,
}

fn build_recovery_app(state: RecoveryState) -> Router {
    let token = state.token.clone();
    Router::new()
        .route("/", get(recovery_index))
        .route("/data", get(recovery_data))
        .route("/done", post(recovery_done))
        .layer(axum::middleware::from_fn(require_recovery_origin))
        .layer(axum::middleware::from_fn_with_state(token, require_token))
        .with_state(state)
}

async fn recovery_index() -> Html<&'static str> {
    Html(RECOVERY_HTML)
}

async fn recovery_data(State(state): State<RecoveryState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "wallet": state.wallet_name,
        "recovery_key": format!("0x{}", state.recovery_key_hex),
        "recovery_command": format!(
            "bloom wallet import {} 0x{}",
            state.wallet_name, state.recovery_key_hex
        ),
    }))
}

async fn recovery_done(State(state): State<RecoveryState>) -> axum::http::StatusCode {
    state.done.notify_one();
    axum::http::StatusCode::OK
}

const RECOVERY_HTML: &str = include_str!("passkey_recovery.html");

// ── keystore integration ──────────────────────────────────────────────────────
//
// Passkey-specific Keystore methods and crypto helpers live here, alongside the
// ceremony code they depend on.  General keystore logic (local wallets, argon2,
// list/info) remains in lib.rs.

use alloy::primitives::{Address, B256};
use alloy::signers::SignerSync as _;
use alloy::signers::local::PrivateKeySigner;
use bloom_proto::{Policy, checksum_address};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use zeroize::{Zeroize, Zeroizing};

use super::{KeystoreError, PasskeyEncrypted, WalletInfo, WalletKind, read_trim, write_atomic};

// ── passkey crypto constants ──────────────────────────────────────────────────

const PASSKEY_ENCRYPTED_VERSION: u8 = 1;
const PASSKEY_AAD: &[u8] = b"bloom-keystore-passkey";

// ── passkey crypto helpers ────────────────────────────────────────────────────

/// Show the recovery key in a browser page; if that fails, return it so
/// `main.rs` can display a terminal prompt instead. Either way the key is
/// shown exactly once and never written to disk.
async fn recovery_key_field(name: &str, signer: &PrivateKeySigner) -> Option<Zeroizing<String>> {
    let hex_key = Zeroizing::new(hex::encode(signer.to_bytes()));
    if display_recovery_key(name, &hex_key).await.is_ok() {
        None
    } else {
        Some(hex_key)
    }
}

/// Encrypt a 32-byte private key using a wrap key derived from `prf_output`.
/// `wrap_key = blake3::derive_key("bloom passkey wrap key", prf_output)`.
pub(super) fn encrypt_passkey_key(
    plaintext: &[u8; 32],
    prf_output: &[u8; 32],
) -> Result<PasskeyEncrypted, KeystoreError> {
    let wrap_key = Zeroizing::new(blake3::derive_key("bloom passkey wrap key", prf_output));
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&*wrap_key));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: PASSKEY_AAD,
            },
        )
        .map_err(|e| KeystoreError::Aead(e.to_string()))?;
    Ok(PasskeyEncrypted {
        v: PASSKEY_ENCRYPTED_VERSION,
        nonce_hex: hex::encode(nonce_bytes),
        ciphertext_hex: hex::encode(&ciphertext),
    })
}

/// Decrypt a `PasskeyEncrypted` blob using a wrap key derived from `prf_output`.
pub(super) fn decrypt_passkey_key(
    enc: &PasskeyEncrypted,
    prf_output: &[u8; 32],
) -> Result<[u8; 32], KeystoreError> {
    if enc.v != PASSKEY_ENCRYPTED_VERSION {
        return Err(KeystoreError::Malformed(format!(
            "unsupported passkey encrypted version {}; expected {}",
            enc.v, PASSKEY_ENCRYPTED_VERSION
        )));
    }
    let wrap_key = Zeroizing::new(blake3::derive_key("bloom passkey wrap key", prf_output));
    let nonce_b =
        hex::decode(&enc.nonce_hex).map_err(|e| KeystoreError::Malformed(format!("nonce: {e}")))?;
    if nonce_b.len() != 12 {
        return Err(KeystoreError::Malformed("nonce length".into()));
    }
    let ct = hex::decode(&enc.ciphertext_hex)
        .map_err(|e| KeystoreError::Malformed(format!("ciphertext: {e}")))?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&*wrap_key));
    let nonce = Nonce::from_slice(&nonce_b);
    let pt = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &ct,
                aad: PASSKEY_AAD,
            },
        )
        .map_err(|e| KeystoreError::Aead(e.to_string()))?;
    if pt.len() != 32 {
        return Err(KeystoreError::Malformed(format!(
            "plaintext len {} != 32",
            pt.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&pt);
    Ok(out)
}

/// Verify `policy.toml.sig` for a PasskeyGated wallet. Returns an error if
/// the hash doesn't match the current content or the recovered signer address
/// doesn't match the wallet address.
pub(super) fn verify_policy_sig(
    wallet_name: &str,
    content: &str,
    address: &Address,
    sig_path: &std::path::Path,
) -> Result<(), KeystoreError> {
    let sig_json_str = std::fs::read_to_string(sig_path).map_err(|source| KeystoreError::Io {
        path: sig_path.to_path_buf(),
        source,
    })?;
    let sig_data: serde_json::Value = serde_json::from_str(&sig_json_str)
        .map_err(|e| KeystoreError::Policy(format!("policy.toml.sig parse: {e}")))?;
    let blake3_hex = sig_data["blake3_hex"]
        .as_str()
        .ok_or_else(|| KeystoreError::Policy("policy.toml.sig: missing blake3_hex".into()))?;
    let sig_hex = sig_data["sig_hex"]
        .as_str()
        .ok_or_else(|| KeystoreError::Policy("policy.toml.sig: missing sig_hex".into()))?;

    // Hash includes the wallet name to prevent a sig from one wallet being
    // transplanted to another wallet with the same address.
    let computed_hash = {
        let input = format!("{wallet_name}:{content}");
        blake3::hash(input.as_bytes())
    };
    let computed = hex::encode(computed_hash.as_bytes());
    if computed != blake3_hex {
        return Err(KeystoreError::Policy(
            "policy.toml has been modified since it was signed — run sign-policy to re-sign".into(),
        ));
    }

    let sig = sig_hex
        .parse::<alloy::primitives::Signature>()
        .map_err(|e| KeystoreError::Policy(format!("policy.toml.sig: bad signature: {e}")))?;
    let hash_b256 = B256::from_slice(computed_hash.as_bytes());
    let recovered = sig
        .recover_address_from_prehash(&hash_b256)
        .map_err(|e| KeystoreError::Policy(format!("policy.toml.sig: recovery failed: {e}")))?;
    if &recovered != address {
        return Err(KeystoreError::Policy(
            "policy.toml.sig: signature does not match wallet address".into(),
        ));
    }
    Ok(())
}

// ── shared helpers ────────────────────────────────────────────────────────────

/// Compute the BLAKE3 name-scoped policy hash, sign it with `signer`, and
/// atomically write `policy.toml.sig` into `dir`.
///
/// The name is included in the hash to prevent a signature from one wallet
/// being transplanted to another wallet with the same address.
fn write_policy_sig(
    dir: &std::path::Path,
    name: &str,
    policy_toml: &str,
    signer: &PrivateKeySigner,
) -> Result<(), KeystoreError> {
    let policy_hash = blake3::hash(format!("{name}:{policy_toml}").as_bytes());
    let hash_b256 = B256::from_slice(policy_hash.as_bytes());
    let sig = signer
        .sign_hash_sync(&hash_b256)
        .map_err(|e| KeystoreError::Signer(format!("sign_policy: {e}")))?;
    let sig_json = serde_json::json!({
        "blake3_hex": hex::encode(policy_hash.as_bytes()),
        "sig_hex": sig.to_string(),
    });
    write_atomic(
        &dir.join("policy.toml.sig"),
        sig_json.to_string().as_bytes(),
    )
}

fn copy_wallet_dir_files(
    from: &std::path::Path,
    to: &std::path::Path,
) -> Result<(), KeystoreError> {
    for entry in std::fs::read_dir(from).map_err(|source| KeystoreError::Io {
        path: from.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| KeystoreError::Io {
            path: from.to_path_buf(),
            source,
        })?;
        let file_type = entry.file_type().map_err(|source| KeystoreError::Io {
            path: entry.path(),
            source,
        })?;
        if file_type.is_file() {
            let dest = to.join(entry.file_name());
            std::fs::copy(entry.path(), &dest)
                .map_err(|source| KeystoreError::Io { path: dest, source })?;
        }
    }
    Ok(())
}

fn unique_rebind_backup_dir(root: &std::path::Path, name: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    root.join(format!(".bloom-rebind-backup-{name}-{nanos}"))
}

// ── impl Keystore — passkey operations ───────────────────────────────────────

impl super::Keystore {
    /// Inner: write wallet files and run the registration ceremony.
    /// Called by `create_passkey` and `import_passkey`.
    pub(super) async fn import_passkey_inner(
        &self,
        name: &str,
        signer: &PrivateKeySigner,
    ) -> Result<WalletInfo, KeystoreError> {
        Self::validate_name(name)?;
        let dir = self.wallet_path(name);
        if dir.exists() {
            return Err(KeystoreError::AlreadyExists(name.into()));
        }

        // Generate the default policy string before the ceremony so the
        // browser page can display it for the user to review.
        let mut default_policy = Policy::default();
        default_policy.approval.agent_autonomy = Some(bloom_proto::AgentAutonomyMode::Disabled);
        let policy_toml_str = toml::to_string_pretty(&default_policy)
            .map_err(|e| KeystoreError::Policy(e.to_string()))?;

        // Generate a random PRF salt. This is stored on disk (not secret);
        // it is the input fed to the authenticator's PRF function so the
        // same authenticator always produces the same wrap key for this wallet.
        let mut prf_salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut prf_salt);

        // Browser WebAuthn registration ceremony — injects the PRF salt into
        // the challenge. User reviews and edits the policy in the form before
        // completing. Returns (credential, final_policy_toml, prf_output).
        let (credential, final_policy_toml, mut prf_output) =
            register_ceremony(name, &policy_toml_str, &prf_salt)
                .await
                .map_err(KeystoreError::PasskeyCeremony)?;

        // Write all wallet files to a temp directory first, then atomically
        // rename it into place. This prevents leaving a partial wallet on disk
        // if any write fails mid-way (e.g. disk full). The guard removes the
        // temp dir on any early return.
        let tmp_dir = self.inner.root.join(format!(".bloom-tmp-{name}"));
        let _ = std::fs::remove_dir_all(&tmp_dir); // clean up any stale temp dir
        std::fs::create_dir_all(&tmp_dir).map_err(|source| KeystoreError::Io {
            path: tmp_dir.clone(),
            source,
        })?;
        struct TmpGuard(std::path::PathBuf);
        impl Drop for TmpGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let guard = TmpGuard(tmp_dir.clone());

        // Encrypt the secp256k1 private key with the PRF-derived wrap key.
        // Zeroize unconditionally before propagating any error so that
        // prf_output and key_bytes are never left un-zeroed on the error path
        // ([u8;32] does not auto-zeroize on drop).
        let mut key_bytes = signer.to_bytes();
        let enc_result = encrypt_passkey_key(key_bytes.as_ref(), &prf_output);
        prf_output.zeroize();
        key_bytes.zeroize();
        let enc = enc_result?;
        let enc_blob =
            serde_json::to_vec(&enc).map_err(|e| KeystoreError::Malformed(e.to_string()))?;
        write_atomic(&tmp_dir.join("encrypted.key"), &enc_blob)?;

        // Write prf.salt (public, not secret — used to reproduce prf_output
        // on future ceremonies with the same authenticator).
        write_atomic(&tmp_dir.join("prf.salt"), hex::encode(prf_salt).as_bytes())?;

        // Serialise the WebAuthn credential.
        let passkey_json = serde_json::to_string(&credential)
            .map_err(|e| KeystoreError::Malformed(format!("passkey serialise: {e}")))?;
        write_atomic(&tmp_dir.join("passkey.json"), passkey_json.as_bytes())?;

        // Write address, pubkey, kind.
        let address = signer.address();
        let pub_hex = hex::encode(
            signer
                .credential()
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        write_atomic(
            &tmp_dir.join("address"),
            checksum_address(&address).as_bytes(),
        )?;
        write_atomic(&tmp_dir.join("pubkey"), pub_hex.as_bytes())?;
        write_atomic(&tmp_dir.join("kind"), b"passkey")?;

        // Write the final policy — may differ from the pre-generated default
        // if the user edited fields in the browser before completing the ceremony.
        write_atomic(&tmp_dir.join("policy.toml"), final_policy_toml.as_bytes())?;

        // Sign the policy immediately — signer is in scope and policy is freshly
        // written. This eliminates the "unsigned policy" warning on first info().
        write_policy_sig(&tmp_dir, name, &final_policy_toml, signer)?;

        // All writes succeeded — atomically rename temp dir to final location.
        std::fs::rename(&tmp_dir, &dir).map_err(|source| KeystoreError::Io {
            path: dir.clone(),
            source,
        })?;
        // Disarm the cleanup guard — directory is now committed.
        std::mem::forget(guard);

        // Parse the on-disk policy that was written above. This may differ from
        // `default_policy` if the user edited fields in the browser during the
        // ceremony — return what is actually on disk, not the pre-ceremony default.
        let final_policy = toml::from_str::<Policy>(&final_policy_toml)
            .map_err(|e| KeystoreError::Policy(format!("final policy parse: {e}")))?;

        // Show the recovery key in a browser page; fall back to returning it
        // for terminal display if the browser cannot be launched.
        let recovery_key = recovery_key_field(name, signer).await;

        // Cache the signer so the wallet is ready to use immediately after creation.
        self.inner
            .unlocked
            .write()
            .insert(name.to_string(), Arc::new(signer.clone()));

        tracing::debug!(wallet = name, "keystore.passkey_created");
        Ok(WalletInfo {
            name: name.into(),
            address,
            pubkey_hex: pub_hex,
            kind: WalletKind::PasskeyGated,
            policy: final_policy,
            recovery_key,
        })
    }

    /// Unlock a passkey wallet via a browser WebAuthn authentication ceremony.
    /// The ceremony uses the PRF extension to derive the wrap key from the
    /// authenticator's internal secret, then decrypts and caches the signer.
    pub async fn unlock_passkey(&self, name: &str) -> Result<(), KeystoreError> {
        self.unlock_passkey_with_intent(name, None).await
    }

    /// Unlock a passkey wallet and display a ceremony intent before the
    /// WebAuthn prompt. Callers that know the concrete action should pass it;
    /// generic unlocks get a safe default intent.
    pub async fn unlock_passkey_with_intent(
        &self,
        name: &str,
        intent: Option<bloom_proto::CeremonyIntent>,
    ) -> Result<(), KeystoreError> {
        self.unlock_passkey_with_intent_and_policy_edit(name, intent, None)
            .await
            .map(|_| ())
    }

    /// As [`Self::unlock_passkey_with_intent`], but lets the browser review
    /// page edit a policy draft and returns the final approved text.
    pub async fn unlock_passkey_with_intent_and_policy_edit(
        &self,
        name: &str,
        intent: Option<bloom_proto::CeremonyIntent>,
        editable_policy: Option<String>,
    ) -> Result<Option<String>, KeystoreError> {
        Self::validate_name(name)?;
        // Fast path only for generic unlocks. If the caller supplied a concrete
        // intent or editable policy, the browser review is part of the
        // authorization boundary and must run even when a signer is cached.
        if self.is_unlocked(name) && intent.is_none() && editable_policy.is_none() {
            return Ok(editable_policy);
        }
        let dir = self.wallet_path(name);
        if !dir.exists() {
            return Err(KeystoreError::NotFound(name.into()));
        }

        // Load stored passkey credential.
        let passkey_json = std::fs::read_to_string(dir.join("passkey.json")).map_err(|source| {
            KeystoreError::Io {
                path: dir.join("passkey.json"),
                source,
            }
        })?;
        let mut credential: Passkey = serde_json::from_str(&passkey_json)
            .map_err(|e| KeystoreError::PasskeyCredential(e.to_string()))?;

        // Read prf.salt — public, not secret. Passed to the authenticator so
        // it produces the deterministic PRF output for this wallet.
        let prf_salt_hex = read_trim(&dir.join("prf.salt"))?;
        let prf_salt_bytes = hex::decode(&prf_salt_hex)
            .map_err(|e| KeystoreError::Malformed(format!("prf.salt: {e}")))?;
        let prf_salt: [u8; 32] = prf_salt_bytes
            .try_into()
            .map_err(|_| KeystoreError::Malformed("prf.salt length != 32".into()))?;

        let intent = intent.or_else(|| Some(default_unlock_intent(name, &dir)));

        // Authentication ceremony — injects the PRF salt into the challenge.
        // Returns (auth_result, Some(prf_output)).
        let (auth_result, prf_output_opt, edited_policy) =
            auth_ceremony(&credential, Some(&prf_salt), intent, editable_policy)
                .await
                .map_err(KeystoreError::PasskeyCeremony)?;

        // Persist updated counter if the authenticator incremented it. This
        // happens before the decrypt below; if decryption later fails the
        // monotonic counter is harmlessly bumped (no security impact — it only
        // ever moves forward) while the unlock still returns an error.
        if auth_result.needs_update() {
            credential.update_credential(&auth_result);
            let updated_json = serde_json::to_string(&credential)
                .map_err(|e| KeystoreError::Malformed(format!("passkey re-serialise: {e}")))?;
            write_atomic(&dir.join("passkey.json"), updated_json.as_bytes())?;
        }

        let mut prf_output = prf_output_opt
            .ok_or_else(|| KeystoreError::PasskeyCeremony(PRF_NOT_SUPPORTED_MSG.into()))?;

        let enc_blob =
            std::fs::read(dir.join("encrypted.key")).map_err(|source| KeystoreError::Io {
                path: dir.join("encrypted.key"),
                source,
            })?;
        let enc: PasskeyEncrypted = serde_json::from_slice(&enc_blob)
            .map_err(|e| KeystoreError::Malformed(format!("encrypted.key parse: {e}")))?;

        // Decrypt with PRF-derived wrap key, then zeroize PRF output.
        let result = decrypt_passkey_key(&enc, &prf_output);
        prf_output.zeroize();
        let mut key_bytes = result?;

        let signer = PrivateKeySigner::from_bytes(&key_bytes.into())
            .map_err(|e| KeystoreError::Signer(e.to_string()))?;
        key_bytes.zeroize();
        self.inner
            .unlocked
            .write()
            .insert(name.to_string(), Arc::new(signer));
        tracing::debug!(wallet = name, "keystore.passkey_unlocked");
        Ok(edited_policy)
    }

    /// Re-bind a PRF-based passkey wallet to a new passkey credential.
    ///
    /// Use this to add a second authenticator (device rotation, YubiKey
    /// replacement, etc.) without moving funds.
    ///
    /// Flow:
    /// 1. Unlock with the existing credential to prove ownership.
    /// 2. Run a fresh WebAuthn registration ceremony (new credential + new PRF
    ///    salt → new PRF output).
    /// 3. Re-encrypt the private key under the new PRF-derived wrap key.
    /// 4. Atomically replace `encrypted.key`, `prf.salt`, `passkey.json`,
    ///    `policy.toml`, and `policy.toml.sig` on disk.
    /// 5. Re-cache the signer under the same wallet name.
    ///
    /// A recovery key (raw hex private key) is printed once after the rebind.
    /// Store it like a seed phrase: `bloom wallet import <name> 0x<key>`.
    pub async fn rebind_passkey(&self, name: &str) -> Result<WalletInfo, KeystoreError> {
        Self::validate_name(name)?;
        let dir = self.wallet_path(name);
        if !dir.exists() {
            return Err(KeystoreError::NotFound(name.into()));
        }

        // Only valid for PRF-based passkey wallets.
        let kind_str = read_trim(&dir.join("kind"))?;
        if kind_str != "passkey" {
            return Err(KeystoreError::PasskeyCredential(format!(
                "rebind_passkey only applies to passkey wallets ('{name}' is '{kind_str}')"
            )));
        }
        if dir.join("wrap.key").exists() {
            return Err(KeystoreError::PasskeyCredential(format!(
                "'{name}' has a legacy wrap.key on disk; this wallet predates PRF support and \
                 cannot be rebound. Import the private key into a new passkey wallet instead."
            )));
        }

        // Step 1: Unlock with existing credential (proves ownership).
        self.unlock_passkey(name).await?;

        // Step 2: Extract the private key bytes from the in-memory signer.
        let signer = self
            .inner
            .unlocked
            .read()
            .get(name)
            .cloned()
            .ok_or_else(|| KeystoreError::Locked(name.into()))?;
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&signer.credential().to_bytes());
        let mut key_bytes = Zeroizing::new(key_arr);

        // Step 3: Read the existing policy so the browser form can pre-populate it.
        let policy_toml = std::fs::read_to_string(dir.join("policy.toml")).map_err(|source| {
            KeystoreError::Io {
                path: dir.join("policy.toml"),
                source,
            }
        })?;

        // Step 4: Generate a fresh PRF salt and run a new registration ceremony.
        let mut prf_salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut prf_salt);

        let (credential, final_policy_toml, mut prf_output) =
            register_ceremony(name, &policy_toml, &prf_salt)
                .await
                .map_err(KeystoreError::PasskeyCeremony)?;

        // Step 5: Re-encrypt under the new PRF-derived wrap key.
        // Zeroize unconditionally before propagating any error — [u8;32]
        // does not auto-zeroize on drop.
        let enc_result = encrypt_passkey_key(&key_bytes, &prf_output);
        key_bytes.zeroize();
        prf_output.zeroize();
        let enc_new = enc_result?;
        let enc_blob_new =
            serde_json::to_vec(&enc_new).map_err(|e| KeystoreError::Malformed(e.to_string()))?;

        // Step 6: stage a complete replacement wallet directory, then swap
        // directory names. The live wallet path should never contain a mixed
        // old/new passkey triple.
        let passkey_json = serde_json::to_string(&credential)
            .map_err(|e| KeystoreError::Malformed(format!("passkey serialise: {e}")))?;
        let tmp_dir = self.inner.root.join(format!(".bloom-rebind-tmp-{name}"));
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).map_err(|source| KeystoreError::Io {
            path: tmp_dir.clone(),
            source,
        })?;
        struct TmpGuard(std::path::PathBuf);
        impl Drop for TmpGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let tmp_guard = TmpGuard(tmp_dir.clone());

        copy_wallet_dir_files(&dir, &tmp_dir)?;
        write_atomic(&tmp_dir.join("policy.toml"), final_policy_toml.as_bytes())?;
        write_policy_sig(&tmp_dir, name, &final_policy_toml, &signer)?;
        write_atomic(&tmp_dir.join("passkey.json"), passkey_json.as_bytes())?;
        write_atomic(&tmp_dir.join("prf.salt"), hex::encode(prf_salt).as_bytes())?;
        write_atomic(&tmp_dir.join("encrypted.key"), &enc_blob_new)?;

        let backup_dir = unique_rebind_backup_dir(&self.inner.root, name);
        std::fs::rename(&dir, &backup_dir).map_err(|source| KeystoreError::Io {
            path: backup_dir.clone(),
            source,
        })?;
        if let Err(source) = std::fs::rename(&tmp_dir, &dir) {
            let rollback_result = std::fs::rename(&backup_dir, &dir);
            if let Err(rollback_source) = rollback_result {
                tracing::error!(
                    wallet = name,
                    backup = %backup_dir.display(),
                    err = %rollback_source,
                    "keystore.passkey_rebind rollback failed; old wallet preserved at backup path"
                );
            }
            return Err(KeystoreError::Io {
                path: dir.clone(),
                source,
            });
        }
        std::mem::forget(tmp_guard);

        // Step 7: Show recovery key in browser; fall back to terminal if needed.
        let recovery_key = recovery_key_field(name, &signer).await;

        // Re-insert (same signer; new credential is now on disk).
        self.inner.unlocked.write().insert(name.to_string(), signer);
        tracing::info!(wallet = name, "keystore.passkey_rebound");

        let addr_str = read_trim(&dir.join("address"))?;
        let address = addr_str
            .parse::<Address>()
            .map_err(|e| KeystoreError::Malformed(format!("address: {e}")))?;
        let pubkey_hex = read_trim(&dir.join("pubkey"))?;
        let policy = toml::from_str::<Policy>(&final_policy_toml)
            .map_err(|e| KeystoreError::Policy(e.to_string()))?;
        Ok(WalletInfo {
            name: name.into(),
            address,
            pubkey_hex,
            kind: WalletKind::PasskeyGated,
            policy,
            recovery_key,
        })
    }

    /// Sign the current `policy.toml` for a PasskeyGated wallet using the
    /// wallet's secp256k1 key. The wallet must already be unlocked via
    /// `unlock_passkey`. Writes `policy.toml.sig` alongside `policy.toml`.
    pub fn sign_policy(&self, name: &str) -> Result<(), KeystoreError> {
        Self::validate_name(name)?;
        let dir = self.wallet_path(name);
        if !dir.exists() {
            return Err(KeystoreError::NotFound(name.into()));
        }

        // Only PasskeyGated wallets use signed policies.
        let kind_str = read_trim(&dir.join("kind"))?;
        if kind_str != "passkey" {
            return Err(KeystoreError::PasskeyCredential(format!(
                "sign_policy requires a passkey wallet (wallet '{name}' is '{kind_str}')"
            )));
        }

        let policy_path = dir.join("policy.toml");
        let content =
            std::fs::read_to_string(&policy_path).map_err(|source| KeystoreError::Io {
                path: policy_path.clone(),
                source,
            })?;

        // Never sign a policy the engine cannot parse — a signed-but-broken
        // policy.toml would brick every wallet operation behind a valid sig.
        toml::from_str::<bloom_proto::Policy>(&content).map_err(|e| {
            KeystoreError::Policy(format!("refusing to sign unparseable policy.toml: {e}"))
        })?;

        let signer = self.signer(name)?; // must be unlocked
        write_policy_sig(&dir, name, &content, &signer)?;
        tracing::debug!(wallet = name, "keystore.policy_signed");
        Ok(())
    }
}

#[cfg(test)]
mod ceremony_gate_tests {
    use super::*;
    use std::sync::Arc;

    /// Build an `AuthState` with review NOT yet given and a minimal but valid
    /// challenge JSON (so `/challenge` parses *after* review).
    fn unreviewed_state() -> AuthState {
        AuthState {
            challenge_json: r#"{"publicKey":{"challenge":"AAAA"}}"#.to_string(),
            challenge_b64: "AAAA".to_string(),
            token: "test-token".to_string(),
            intent: Arc::new(Mutex::new(Some(bloom_proto::CeremonyIntent::new(
                "minnow",
                "Sign Polygon Transaction",
                bloom_proto::CeremonyIntentKind::EvmTransaction,
            )))),
            editable_policy: Arc::new(Mutex::new(None)),
            reviewed: Arc::new(Mutex::new(false)),
            prf_output: Arc::new(Mutex::new(None)),
            fallback_challenge: Arc::new(Mutex::new(None)),
            tx: Arc::new(Mutex::new(Some(tokio::sync::oneshot::channel().0))),
            shutdown: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Serve `build_auth_app` on an ephemeral port; returns the base URL.
    async fn serve(state: AuthState) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = build_auth_app(state.clone());
        let shutdown = state.shutdown.clone();
        let h = tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move { shutdown.notified().await })
                .await;
        });
        (format!("http://127.0.0.1:{}", addr.port()), h)
    }

    fn client() -> reqwest::Client {
        reqwest::Client::new()
    }

    /// The core safety invariant: no WebAuthn challenge is served before the
    /// user has reviewed and approved.
    #[tokio::test]
    async fn challenge_refuses_428_before_review_then_allows_after() {
        let state = unreviewed_state();
        let (base, _h) = serve(state.clone()).await;
        let c = client();

        // GET /challenge before review → 428 Precondition Required.
        let r = c.get(format!("{base}/challenge")).send().await.unwrap();
        assert_eq!(
            r.status().as_u16(),
            428,
            "challenge must refuse before review"
        );

        // /auth-challenge (fallback PRF path) must not issue a real challenge.
        let r = c
            .get(format!("{base}/auth-challenge"))
            .send()
            .await
            .unwrap();
        let body = r.text().await.unwrap();
        assert!(
            body.contains("review_required"),
            "auth-challenge before review: {body}"
        );

        // Approve.
        let r = c
            .post(format!("{base}/reviewed"))
            .header("x-bloom-token", "test-token")
            .header("origin", format!("http://localhost:{CEREMONY_PORT}"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200);

        // Now /challenge succeeds.
        let r = c.get(format!("{base}/challenge")).send().await.unwrap();
        assert_eq!(
            r.status().as_u16(),
            200,
            "challenge must serve after review"
        );
        state.shutdown.notify_one();
    }

    /// The POST signing-input gate (`/prf-output`) also refuses before review —
    /// same guard as `/auth`, exercised through the token+origin middleware.
    #[tokio::test]
    async fn prf_output_refuses_428_before_review() {
        let state = unreviewed_state();
        let (base, _h) = serve(state.clone()).await;
        let r = client()
            .post(format!("{base}/prf-output"))
            .header("x-bloom-token", "test-token")
            .header("origin", format!("http://localhost:{CEREMONY_PORT}"))
            .json(&serde_json::json!({
                "prf_output_b64": "AAAA",
                "client_data_json_b64": "AAAA"
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status().as_u16(),
            428,
            "prf-output must refuse before review"
        );
        state.shutdown.notify_one();
    }

    /// `/intent.json` returns the intent and a matching short hash.
    #[tokio::test]
    async fn intent_json_returns_matching_hash() {
        let state = unreviewed_state();
        let expected = state.intent.lock().clone().unwrap().intent_hash();
        let (base, _h) = serve(state.clone()).await;
        let v: serde_json::Value = client()
            .get(format!("{base}/intent.json"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(v["intent_hash"].as_str(), Some(expected.as_str()));
        assert_eq!(v["intent"]["kind"].as_str(), Some("evm_transaction"));
        state.shutdown.notify_one();
    }

    /// `/reject` cancels the ceremony promptly (drops the sender, notifies
    /// shutdown) so the CLI exits instead of waiting for timeout.
    #[tokio::test]
    async fn reject_cancels_promptly() {
        let state = unreviewed_state();
        let (base, h) = serve(state.clone()).await;
        let r = client()
            .post(format!("{base}/reject"))
            .header("x-bloom-token", "test-token")
            .header("origin", format!("http://localhost:{CEREMONY_PORT}"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200);
        // graceful shutdown should complete quickly
        tokio::time::timeout(std::time::Duration::from_secs(2), h)
            .await
            .expect("server should shut down after /reject")
            .unwrap();
    }

    /// `/edit-policy` leaves the auth sender and review server alive so the
    /// browser can show editing instructions instead of disappearing.
    #[tokio::test]
    async fn edit_policy_keeps_page_alive() {
        let state = unreviewed_state();
        let (base, h) = serve(state.clone()).await;
        let r = client()
            .post(format!("{base}/edit-policy"))
            .header("x-bloom-token", "test-token")
            .header("origin", format!("http://localhost:{CEREMONY_PORT}"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200);
        assert!(state.tx.lock().is_some());
        assert!(!*state.reviewed.lock());
        let intent = client()
            .get(format!("{base}/intent.json"))
            .send()
            .await
            .unwrap();
        assert_eq!(intent.status().as_u16(), 200);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), h)
                .await
                .is_err(),
            "server should remain alive after /edit-policy"
        );
        state.shutdown.notify_one();
    }

    #[tokio::test]
    async fn policy_edit_rejects_invalid_policy() {
        let state = unreviewed_state();
        *state.editable_policy.lock() =
            Some("[approval]\nagent_autonomy = \"prompt_all\"\n".into());
        let (base, _h) = serve(state.clone()).await;
        let r = client()
            .post(format!("{base}/policy-edit"))
            .header("x-bloom-token", "test-token")
            .header("origin", format!("http://localhost:{CEREMONY_PORT}"))
            .json(&serde_json::json!({
                "policy_text": "[approval]\nagent_autonomy = \"autopilot\"\n"
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 400);
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(body["ok"].as_bool(), Some(false));
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("invalid policy.toml")
        );
        assert_eq!(
            state.editable_policy.lock().as_deref(),
            Some("[approval]\nagent_autonomy = \"prompt_all\"\n")
        );
        state.shutdown.notify_one();
    }

    #[tokio::test]
    async fn policy_edit_accepts_valid_policy_and_updates_hash() {
        let state = unreviewed_state();
        *state.editable_policy.lock() =
            Some("[approval]\nagent_autonomy = \"prompt_all\"\n".into());
        if let Some(intent) = state.intent.lock().as_mut() {
            intent.canonical_subject = serde_json::json!({
                "kind": "vfs_policy_write",
                "policy_blake3": "old"
            });
        }
        let text = "[approval]\nagent_autonomy = \"under_policy\"\n";
        let (base, _h) = serve(state.clone()).await;
        let r = client()
            .post(format!("{base}/policy-edit"))
            .header("x-bloom-token", "test-token")
            .header("origin", format!("http://localhost:{CEREMONY_PORT}"))
            .json(&serde_json::json!({ "policy_text": text }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200);
        assert_eq!(state.editable_policy.lock().as_deref(), Some(text));
        let intent = state.intent.lock().clone().unwrap();
        let digest = blake3::hash(text.as_bytes()).to_hex().to_string();
        assert_eq!(
            intent.policy_lines,
            vec!["[approval]", "agent_autonomy = \"under_policy\""]
        );
        assert_eq!(
            intent.canonical_subject["policy_blake3"].as_str(),
            Some(digest.as_str())
        );
        state.shutdown.notify_one();
    }

    #[tokio::test]
    async fn policy_autonomy_updates_only_policy_mode() {
        let state = unreviewed_state();
        *state.editable_policy.lock() =
            Some("[caps]\nmax_value_eth = 0.1\n\n[approval]\n\n[defi]\nenabled = true\n".into());
        if let Some(intent) = state.intent.lock().as_mut() {
            intent.canonical_subject = serde_json::json!({
                "kind": "vfs_policy_write",
                "policy_blake3": "old"
            });
        }
        let (base, _h) = serve(state.clone()).await;
        let r = client()
            .post(format!("{base}/policy-autonomy"))
            .header("x-bloom-token", "test-token")
            .header("origin", format!("http://localhost:{CEREMONY_PORT}"))
            .json(&serde_json::json!({ "mode": "under_policy" }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200);
        let updated = state.editable_policy.lock().clone().unwrap();
        assert!(updated.contains("[approval]\nagent_autonomy = \"under_policy\""));
        assert!(updated.contains("[defi]\nenabled = true"));
        let intent = state.intent.lock().clone().unwrap();
        assert!(
            intent
                .policy_lines
                .join("\n")
                .contains("agent_autonomy = \"under_policy\"")
        );
        assert_ne!(
            intent.canonical_subject["policy_blake3"].as_str(),
            Some("old")
        );
        state.shutdown.notify_one();
    }

    /// POSTs without the per-server token are rejected by the middleware.
    #[tokio::test]
    async fn post_without_token_is_forbidden() {
        let state = unreviewed_state();
        let (base, _h) = serve(state.clone()).await;
        let r = client()
            .post(format!("{base}/reviewed"))
            .header("origin", format!("http://localhost:{CEREMONY_PORT}"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 403, "missing token must be forbidden");
        // and review state is unchanged
        assert!(!*state.reviewed.lock());
        state.shutdown.notify_one();
    }
}
