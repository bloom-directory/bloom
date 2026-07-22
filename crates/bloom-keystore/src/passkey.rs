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

use bloom_auth_api::{AssuranceLevel, UnsignedApproval, WebAuthnAssertionRecord};
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
pub fn launch_browser(url: &str) -> Result<(), String> {
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

/// Browser WebAuthn options for a daemon-owned Mode 3 sealed-approval ceremony.
///
/// Produced by [`Keystore::sealed_ceremony_challenge`]; the daemon ceremony
/// server serves `challenge_json` to the `/ceremony/{token}` page and uses
/// `challenge_b64` to bind returned PRF output to the assertion.
#[derive(Debug, Clone)]
pub struct SealedCeremonyChallenge {
    /// The full `navigator.credentials.get` options JSON (challenge + PRF ext).
    pub challenge_json: String,
    /// The base64url challenge value embedded in `challenge_json`.
    pub challenge_b64: String,
}

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

fn patch_request_challenge_json(
    challenge_json: &str,
    challenge: &[u8; 32],
    require_uv: bool,
) -> Result<String, String> {
    let challenge_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge);
    let mut v: serde_json::Value =
        serde_json::from_str(challenge_json).map_err(|e| e.to_string())?;
    let Some(pk) = v.get_mut("publicKey").and_then(|v| v.as_object_mut()) else {
        return Err("challenge JSON missing publicKey object".into());
    };
    pk.insert("challenge".into(), serde_json::Value::String(challenge_b64));
    if require_uv {
        pk.insert(
            "userVerification".into(),
            serde_json::Value::String("required".into()),
        );
    }
    serde_json::to_string(&v).map_err(|e| e.to_string())
}

/// Layer-B assurance gate on the WebAuthn UV flag: `Hardened` approvals need a
/// user-verified assertion (PIN/biometric), never a presence-only tap.
///
/// webauthn-rs's `Passkey` API currently also enforces UV (its
/// `start_passkey_authentication` hardcodes `UserVerificationPolicy::Required`),
/// but that is an implementation detail of the dependency. This gate makes the
/// hardened-requires-UV invariant explicit in bloom so it survives library
/// upgrades or a future decision to relax standard-level ceremonies.
fn require_user_verification_for_assurance(
    assurance: AssuranceLevel,
    user_verified: bool,
) -> Result<(), String> {
    if assurance == AssuranceLevel::Hardened && !user_verified {
        return Err(
            "hardened approval requires a user-verified WebAuthn assertion \
             (UV flag not set; presence-only is not sufficient)"
                .into(),
        );
    }
    Ok(())
}

fn patch_passkey_authentication_challenge(
    state: PasskeyAuthentication,
    challenge: &[u8; 32],
) -> Result<PasskeyAuthentication, String> {
    let challenge_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge);
    let mut v = serde_json::to_value(state).map_err(|e| e.to_string())?;
    let Some(ast) = v.get_mut("ast").and_then(|v| v.as_object_mut()) else {
        return Err("passkey authentication state missing ast object".into());
    };
    ast.insert("challenge".into(), serde_json::Value::String(challenge_b64));
    serde_json::from_value(v).map_err(|e| e.to_string())
}

/// Registration equivalent of [`patch_passkey_authentication_challenge`]:
/// patches the *stored* `PasskeyRegistration` verification state (not just
/// the outgoing challenge JSON) so `finish_passkey_registration` verifies
/// against the same domain-separated challenge the browser signed. Without
/// this, only the outgoing JSON is bound to the caller's challenge while
/// verification silently falls back to webauthn-rs's own random challenge —
/// the gap the async registration protocol closes.
fn patch_passkey_registration_challenge(
    state: PasskeyRegistration,
    challenge: &[u8; 32],
) -> Result<PasskeyRegistration, String> {
    let challenge_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge);
    let mut v = serde_json::to_value(state).map_err(|e| e.to_string())?;
    let Some(rs) = v.get_mut("rs").and_then(|v| v.as_object_mut()) else {
        return Err("passkey registration state missing rs object".into());
    };
    rs.insert("challenge".into(), serde_json::Value::String(challenge_b64));
    serde_json::from_value(v).map_err(|e| e.to_string())
}

fn b64_field(value: &impl serde::Serialize, field: &'static str) -> Result<String, String> {
    serde_json::to_value(value)
        .map_err(|e| format!("{field}: {e}"))?
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("{field}: expected base64 string"))
}

fn webauthn_assertion_record(
    credential: &PublicKeyCredential,
) -> Result<WebAuthnAssertionRecord, String> {
    Ok(WebAuthnAssertionRecord {
        credential_id: credential.id.clone(),
        authenticator_data_b64: b64_field(
            &credential.response.authenticator_data,
            "authenticatorData",
        )?,
        client_data_json_b64: b64_field(&credential.response.client_data_json, "clientDataJSON")?,
        signature_b64: b64_field(&credential.response.signature, "signature")?,
        user_handle_b64: credential
            .response
            .user_handle
            .as_ref()
            .map(|v| b64_field(v, "userHandle"))
            .transpose()?,
    })
}

/// Bind a local TCP listener on `127.0.0.1:{port}`. `ctx` is used in error
/// messages to identify which server failed (e.g. "passkey ceremony").
pub fn bind_local(port: u16, ctx: &str) -> Result<tokio::net::TcpListener, String> {
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

// ── registration (browserless primitives) ──────────────────────────────────

/// Derive a stable UUID from a wallet name so re-registrations on the same
/// machine map to the same resident-key slot. Uses blake3 (already in the
/// dependency tree) rather than requiring the `uuid` crate's `v5` feature.
fn wallet_user_id(wallet_name: &str) -> Uuid {
    let hash = blake3::hash(wallet_name.as_bytes());
    let mut uuid_bytes = [0u8; 16];
    uuid_bytes.copy_from_slice(&hash.as_bytes()[..16]);
    uuid_bytes[6] = (uuid_bytes[6] & 0x0f) | 0x50; // version = 5
    uuid_bytes[8] = (uuid_bytes[8] & 0x3f) | 0x80; // variant = RFC 4122
    Uuid::from_bytes(uuid_bytes)
}

/// Start a WebAuthn registration attempt bound to a caller-supplied,
/// domain-separated `challenge` (see `RegistrationIntent::challenge_hash` in
/// `bloom-auth-api`) instead of webauthn-rs's own random challenge. Returns
/// the full `navigator.credentials.create()` options JSON (resident-key +
/// PRF extension already patched in) and the verification state, itself
/// patched so `finish_registration` verifies against the same challenge.
///
/// Does not launch a browser or bind any server — the caller (the daemon
/// registration coordinator) owns the HTTP transport.
pub fn start_registration_challenge(
    wallet_name: &str,
    prf_salt: &[u8; 32],
    challenge: &[u8; 32],
) -> Result<(serde_json::Value, PasskeyRegistration), String> {
    let webauthn = build_webauthn()?;
    let user_id = wallet_user_id(wallet_name);
    let (ccr, reg_state) = webauthn
        .start_passkey_registration(user_id, wallet_name, wallet_name, None)
        .map_err(|e| format!("start_passkey_registration: {e}"))?;
    let reg_state = patch_passkey_registration_challenge(reg_state, challenge)?;

    let mut v = serde_json::to_value(&ccr).map_err(|e| e.to_string())?;
    // Patch (a) require resident keys and (b) inject the PRF extension.
    // webauthn-rs 0.5.5 has no non-attested resident-key API and no PRF API.
    // Drop this patch block when those are added upstream.
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
    let challenge_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge);
    if let Some(pk) = v["publicKey"].as_object_mut() {
        pk.insert("challenge".into(), serde_json::Value::String(challenge_b64));
    }
    let v = inject_prf_into_challenge_json(v, prf_salt);

    Ok((v, reg_state))
}

/// Verify a registration credential against previously-patched state.
/// Cryptographic verification only — the caller decides when it is safe to
/// consume any adjacent PRF output (must be after this succeeds).
pub fn finish_registration(
    credential: &RegisterPublicKeyCredential,
    state: &PasskeyRegistration,
) -> Result<Passkey, String> {
    let webauthn = build_webauthn()?;
    webauthn
        .finish_passkey_registration(credential, state)
        .map_err(|e| format!("finish_passkey_registration: {e}"))
}

/// Start the PRF-fallback authentication challenge for a passkey that was
/// just registered (not yet on disk) — some authenticators report PRF
/// support during `create()` but return the value only during `get()`.
/// Bound to the same domain-separated `challenge` and PRF salt as the
/// original attempt.
pub fn start_registration_fallback_assertion(
    credential: &Passkey,
    prf_salt: &[u8; 32],
    challenge: &[u8; 32],
) -> Result<(serde_json::Value, PasskeyAuthentication), String> {
    let webauthn = build_webauthn()?;
    let (rcr, auth_state) = webauthn
        .start_passkey_authentication(std::slice::from_ref(credential))
        .map_err(|e| format!("start_passkey_authentication: {e}"))?;
    let auth_state = patch_passkey_authentication_challenge(auth_state, challenge)?;
    let challenge_json = serde_json::to_string(&rcr).map_err(|e| e.to_string())?;
    let challenge_json = patch_request_challenge_json(&challenge_json, challenge, false)?;
    let v: serde_json::Value = serde_json::from_str(&challenge_json).map_err(|e| e.to_string())?;
    let v = inject_prf_into_challenge_json(v, prf_salt);
    Ok((v, auth_state))
}

/// Verify the PRF-fallback authentication assertion against previously
/// patched state. Cryptographic verification only — the caller decides when
/// it is safe to consume any adjacent PRF output.
pub fn finish_registration_fallback_assertion(
    credential: &PublicKeyCredential,
    state: &PasskeyAuthentication,
) -> Result<AuthenticationResult, String> {
    let webauthn = build_webauthn()?;
    webauthn
        .finish_passkey_authentication(credential, state)
        .map_err(|e| format!("finish_passkey_authentication: {e}"))
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
pub(crate) struct AuthCeremonyResult {
    auth_result: AuthenticationResult,
    prf_output: Option<[u8; 32]>,
    edited_policy: Option<String>,
    credential: PublicKeyCredential,
}

/// Returns a verified authentication ceremony result.
///
/// Counter persistence depends on who verifies last: unlock-style callers are
/// the only verifier of their assertion and must persist the credential update
/// when `auth_result.needs_update()`. Approval signing must NOT persist — the
/// daemon re-verifies the same assertion against the stored credential, and a
/// pre-bumped counter would read as a cloned authenticator and deny every
/// approval from counter-incrementing (hardware) keys.
pub(crate) async fn auth_ceremony(
    credential: &Passkey,
    prf_salt: Option<&[u8; 32]>,
    intent: Option<CeremonyIntent>,
    editable_policy: Option<String>,
    challenge_override: Option<[u8; 32]>,
    require_uv: bool,
) -> Result<AuthCeremonyResult, String> {
    let webauthn = build_webauthn()?;

    let (rcr, mut auth_state) = webauthn
        .start_passkey_authentication(std::slice::from_ref(credential))
        .map_err(|e| format!("start_passkey_authentication: {e}"))?;

    let mut challenge_json = serde_json::to_string(&rcr).map_err(|e| e.to_string())?;
    if let Some(challenge) = challenge_override {
        challenge_json = patch_request_challenge_json(&challenge_json, &challenge, require_uv)?;
        auth_state = patch_passkey_authentication_challenge(auth_state, &challenge)?;
    }

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
    Ok(AuthCeremonyResult {
        auth_result,
        prf_output,
        edited_policy,
        credential: pkc,
    })
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

/// Generate an unguessable 256-bit capability token (base64url, no pad). It is
/// embedded in the URL bloom opens and required on every state-changing request
/// to bind the loopback server to the browser page bloom launched.
fn gen_token() -> String {
    let mut t = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut t);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(t)
}

/// Capability-token gate. POSTs must carry an `x-bloom-token` header equal to
/// the per-server token embedded in the URL bloom opened. The `Origin` header
/// is trivially spoofable by a local non-browser process and the challenge is
/// readable via `GET /challenge`, so the origin check alone does not stop a
/// local process from POSTing a forged PRF output. The token — never sent to
/// the network, only present in the URL bloom launched — closes that gap.
async fn require_token(
    axum::extract::State(token): axum::extract::State<String>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    let sensitive = req.method() == axum::http::Method::POST;
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

/// Issue a random challenge for the fallback PRF extraction flow (authentication).
async fn auth_auth_challenge(State(state): State<AuthState>) -> Json<serde_json::Value> {
    if !*state.reviewed.lock() {
        return Json(serde_json::json!({ "error": "review_required" }));
    }
    issue_fallback_challenge(&state.fallback_challenge)
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
            "editable_policy": state.editable_policy.lock().is_some(),
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

const AUTH_HTML: &str = include_str!("passkey_auth.html");
const REBIND_HTML: &str = include_str!("passkey_rebind.html");

// ── foreground registration ceremony (not VFS-exposed) ──────────────────────
//
// Used by `Keystore::rebind_passkey` (which proves ownership of the existing
// credential before calling this) and by the CLI's foreground
// `bloom wallet import <name> <key>` passkey path. The URL this binds is
// never persisted or projected anywhere outside this process's own browser
// launch. It shares the same threat model as the foreground unlock ceremony
// (`auth_ceremony`), not the VFS-exposed asynchronous registration protocol,
// so it keeps binding `CEREMONY_PORT` directly rather than routing through
// the daemon-owned coordinator — if `bloom serve` already owns that port,
// this bind fails with a clear error rather than silently degrading.

fn decode_prf_output_b64(s: &str) -> Result<[u8; 32], String> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim())
        .map_err(|e| e.to_string())?;
    if bytes.len() != 32 {
        return Err("prf_output must be 32 bytes".into());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Outcome of a foreground registration/rebind ceremony: the verified
/// credential plus its adjacent PRF output, or an error message.
type RebindOutcome = Result<(Passkey, [u8; 32]), String>;

#[derive(Clone)]
struct RebindState {
    token: String,
    prf_salt: [u8; 32],
    challenge: [u8; 32],
    reg_state: PasskeyRegistration,
    fallback: Arc<Mutex<Option<(Passkey, PasskeyAuthentication)>>>,
    tx: Arc<Mutex<Option<tokio::sync::oneshot::Sender<RebindOutcome>>>>,
    shutdown: Arc<tokio::sync::Notify>,
    creation_options_json: serde_json::Value,
}

fn build_rebind_app(state: RebindState) -> Router {
    let token = state.token.clone();
    Router::new()
        .route("/", get(rebind_index))
        .route("/challenge", get(rebind_challenge))
        .route("/fallback-options", post(rebind_fallback_options))
        .route("/complete", post(rebind_complete))
        .layer(axum::middleware::from_fn(require_localhost_origin))
        .layer(axum::middleware::from_fn_with_state(token, require_token))
        .with_state(state)
}

async fn rebind_index() -> Html<&'static str> {
    Html(REBIND_HTML)
}

async fn rebind_challenge(State(state): State<RebindState>) -> Json<serde_json::Value> {
    Json(state.creation_options_json.clone())
}

#[derive(serde::Deserialize)]
struct RebindFallbackBody {
    credential: RegisterPublicKeyCredential,
}

async fn rebind_fallback_options(
    State(state): State<RebindState>,
    Json(body): Json<RebindFallbackBody>,
) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
    // Verify and consume the registration credential *before* issuing a
    // fallback assertion challenge for it — mirrors the ordering the
    // asynchronous VFS registration protocol requires.
    let passkey = finish_registration(&body.credential, &state.reg_state)
        .map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;
    let (opts, auth_state) =
        start_registration_fallback_assertion(&passkey, &state.prf_salt, &state.challenge)
            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    *state.fallback.lock() = Some((passkey, auth_state));
    Ok(Json(opts))
}

#[derive(serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum RebindCompleteBody {
    Registration {
        credential: RegisterPublicKeyCredential,
        prf_output_b64: String,
    },
    Fallback {
        credential: PublicKeyCredential,
        prf_output_b64: String,
    },
}

async fn rebind_complete(
    State(state): State<RebindState>,
    Json(body): Json<RebindCompleteBody>,
) -> axum::http::StatusCode {
    let result = match body {
        RebindCompleteBody::Registration {
            credential,
            prf_output_b64,
        } => finish_registration(&credential, &state.reg_state)
            .and_then(|passkey| decode_prf_output_b64(&prf_output_b64).map(|prf| (passkey, prf))),
        RebindCompleteBody::Fallback {
            credential,
            prf_output_b64,
        } => match state.fallback.lock().clone() {
            Some((passkey, auth_state)) => {
                finish_registration_fallback_assertion(&credential, &auth_state)
                    .and_then(|_| decode_prf_output_b64(&prf_output_b64).map(|prf| (passkey, prf)))
            }
            None => Err("no fallback attempt in progress".into()),
        },
    };
    let sent = state
        .tx
        .lock()
        .take()
        .is_some_and(|tx| tx.send(result).is_ok());
    state.shutdown.notify_one();
    if sent {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    }
}

/// Run a one-shot foreground WebAuthn registration ceremony that verifies
/// the credential before returning any PRF output. Opens
/// `http://localhost:CEREMONY_PORT` and blocks until the ceremony completes
/// or times out.
pub async fn foreground_registration_ceremony(
    wallet_name: &str,
    prf_salt: &[u8; 32],
) -> RebindOutcome {
    let mut challenge = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge);
    let (creation_options_json, reg_state) =
        start_registration_challenge(wallet_name, prf_salt, &challenge)?;

    let (tx, rx) = tokio::sync::oneshot::channel::<RebindOutcome>();
    let token = gen_token();
    let state = RebindState {
        token: token.clone(),
        prf_salt: *prf_salt,
        challenge,
        reg_state,
        fallback: Arc::new(Mutex::new(None)),
        tx: Arc::new(Mutex::new(Some(tx))),
        shutdown: Arc::new(tokio::sync::Notify::new()),
        creation_options_json,
    };

    let listener = bind_local(CEREMONY_PORT, "passkey rebind ceremony")?;
    let app = build_rebind_app(state.clone());
    let shutdown = state.shutdown.clone();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move { shutdown.notified().await })
            .await;
    });

    let url = format!("http://localhost:{CEREMONY_PORT}/?t={token}");
    eprintln!("[bloom] Opening browser for passkey ceremony — complete it at {url}");
    if let Err(e) = launch_browser(&url) {
        state.shutdown.notify_one();
        let _ = server.await;
        return Err(e);
    }

    let result =
        match tokio::time::timeout(std::time::Duration::from_secs(REG_TIMEOUT_SECS), rx).await {
            Ok(Ok(r)) => r,
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
    result
}

// ── keystore integration ──────────────────────────────────────────────────────
//
// Passkey-specific Keystore methods and crypto helpers live here, alongside the
// ceremony code they depend on.  General keystore logic (local wallets, argon2,
// list/info) remains in lib.rs.

use std::path::PathBuf;

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

/// Decrypt a wallet signing key from a live ceremony's PRF output and return a
/// ready-to-use signer. The 32-byte PRF output is consumed and zeroized here;
/// it never leaves this frame. Shared by the foreground browser ceremony and
/// the daemon-owned Mode 3 ceremony server so signer-decryption semantics stay
/// identical across interaction modes.
fn decrypt_signer_from_prf(
    dir: &Path,
    mut prf_output: [u8; 32],
) -> Result<Arc<PrivateKeySigner>, KeystoreError> {
    let enc_blob =
        std::fs::read(dir.join("encrypted.key")).map_err(|source| KeystoreError::Io {
            path: dir.join("encrypted.key"),
            source,
        })?;
    let enc: PasskeyEncrypted = serde_json::from_slice(&enc_blob)
        .map_err(|e| KeystoreError::Malformed(format!("encrypted.key parse: {e}")))?;
    let result = decrypt_passkey_key(&enc, &prf_output);
    prf_output.zeroize();
    let mut key_bytes = result?;
    let signer = PrivateKeySigner::from_bytes(&key_bytes.into())
        .map_err(|e| KeystoreError::Signer(e.to_string()))?;
    key_bytes.zeroize();
    Ok(Arc::new(signer))
}

/// Extract the base64url `challenge` field from a browser `clientDataJSON`
/// (base64url-encoded). Used by the daemon ceremony server to bind a posted
/// PRF output to the challenge the assertion actually signed. Returns `None`
/// if the blob is not valid base64url JSON with a string `challenge`.
pub fn client_data_challenge_b64(client_data_json_b64: &str) -> Option<String> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(client_data_json_b64.trim())
        .ok()?;
    let cdj: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    cdj.get("challenge")
        .and_then(|v| v.as_str())
        .map(str::to_string)
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

// ── prepared wallet lifecycle ────────────────────────────────────────────────

/// Default policy TOML for a fresh passkey registration, served to the
/// registration page before any attempt exists.
pub fn default_passkey_policy_toml() -> Result<String, KeystoreError> {
    let mut default_policy = Policy::default();
    default_policy.approval.agent_autonomy = Some(bloom_proto::AgentAutonomyMode::Disabled);
    toml::to_string_pretty(&default_policy).map_err(|e| KeystoreError::Policy(e.to_string()))
}

/// A passkey wallet's files, fully encrypted and written to a session-owned
/// temporary directory but not yet visible at its final wallet path.
/// Dropped without [`finalize_passkey_wallet`], the temp directory is
/// removed — the wallet never appears until recovery is acknowledged.
pub struct PreparedPasskeyWallet {
    tmp_dir: PathBuf,
    pub address: Address,
    pub pubkey_hex: String,
    pub policy: Policy,
    /// The plaintext private key, hex-encoded. Shown to the user exactly
    /// once by the HTTP layer's `/complete` response and never persisted to
    /// disk or logged.
    pub recovery_key: Zeroizing<String>,
}

impl Drop for PreparedPasskeyWallet {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.tmp_dir);
    }
}

/// Encrypt `signer` under a PRF-derived wrap key and write a passkey
/// wallet's files into `<root>/.bloom-tmp-registration-<temp_id>`, without
/// making it visible at its final wallet path (`<root>/<name>`).
///
/// The caller must have already cryptographically verified `credential` (and
/// any adjacent WebAuthn assertion, for the PRF-fallback path) before
/// calling this — PRF output must never be consumed before verification.
#[allow(clippy::too_many_arguments)]
pub fn prepare_passkey_wallet(
    root: &Path,
    temp_id: &str,
    name: &str,
    signer: &PrivateKeySigner,
    credential: &Passkey,
    prf_salt: &[u8; 32],
    mut prf_output: [u8; 32],
    policy_toml: &str,
) -> Result<PreparedPasskeyWallet, KeystoreError> {
    let tmp_dir = root.join(format!(".bloom-tmp-registration-{temp_id}"));
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
    let enc_blob = serde_json::to_vec(&enc).map_err(|e| KeystoreError::Malformed(e.to_string()))?;
    write_atomic(&tmp_dir.join("encrypted.key"), &enc_blob)?;

    // prf.salt is public, not secret — used to reproduce prf_output on
    // future ceremonies with the same authenticator.
    write_atomic(&tmp_dir.join("prf.salt"), hex::encode(prf_salt).as_bytes())?;

    let passkey_json = serde_json::to_string(credential)
        .map_err(|e| KeystoreError::Malformed(format!("passkey serialise: {e}")))?;
    write_atomic(&tmp_dir.join("passkey.json"), passkey_json.as_bytes())?;

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
    write_atomic(&tmp_dir.join("policy.toml"), policy_toml.as_bytes())?;
    write_policy_sig(&tmp_dir, name, policy_toml, signer)?;

    let policy = toml::from_str::<Policy>(policy_toml)
        .map_err(|e| KeystoreError::Policy(format!("prepared policy parse: {e}")))?;

    // All writes succeeded — disarm the cleanup guard. Ownership of the temp
    // dir's lifecycle moves to `PreparedPasskeyWallet`'s own `Drop`.
    std::mem::forget(guard);

    Ok(PreparedPasskeyWallet {
        tmp_dir,
        address,
        pubkey_hex: pub_hex,
        policy,
        recovery_key: Zeroizing::new(hex::encode(signer.to_bytes())),
    })
}

/// Public result of [`finalize_passkey_wallet`].
pub struct FinalizedPasskeyWallet {
    pub address: Address,
    pub pubkey_hex: String,
    pub policy: Policy,
}

/// Atomically commit a prepared wallet to `final_dir` (`<root>/<name>`).
///
/// On a failed rename, `prepared` is handed back rather than dropped: its
/// `Drop` unconditionally `remove_dir_all`s the temp directory, which is
/// exactly right when the rename succeeded (the directory has already moved
/// away) but would otherwise destroy the still-valid, not-yet-installed
/// wallet — including the only copy of the recovery key — on nothing more
/// than a transient rename failure (disk full, cross-device, permissions).
/// Callers that have somewhere durable to put `prepared` back (a coordinator
/// session awaiting recovery acknowledgment) should do so and let the
/// caller retry finalization later.
pub fn finalize_passkey_wallet(
    prepared: PreparedPasskeyWallet,
    final_dir: &Path,
) -> Result<FinalizedPasskeyWallet, (Box<PreparedPasskeyWallet>, KeystoreError)> {
    if let Err(source) = std::fs::rename(&prepared.tmp_dir, final_dir) {
        return Err((
            Box::new(prepared),
            KeystoreError::Io {
                path: final_dir.to_path_buf(),
                source,
            },
        ));
    }
    let out = FinalizedPasskeyWallet {
        address: prepared.address,
        pubkey_hex: prepared.pubkey_hex.clone(),
        policy: prepared.policy.clone(),
    };
    // Let `prepared` drop normally rather than `mem::forget`-ing it: its
    // `Drop` only tries to remove `tmp_dir` (already renamed away, so this
    // is a harmless no-op via the ignored `Result`), and letting it run is
    // exactly what zeroizes `recovery_key`. Forgetting the whole struct
    // would skip that zeroization and leak the recovery key in memory.
    Ok(out)
}

// ── impl Keystore — passkey operations ───────────────────────────────────────

impl super::Keystore {
    fn from_auth_api(err: bloom_auth_api::AuthApiError) -> KeystoreError {
        KeystoreError::PasskeyCredential(err.to_string())
    }

    /// Cache a freshly-committed passkey wallet's signer so it is unlocked
    /// immediately after registration completes, without a fresh ceremony.
    pub fn cache_unlocked_signer(&self, name: &str, signer: PrivateKeySigner) {
        self.inner
            .unlocked
            .write()
            .insert(name.to_string(), Arc::new(signer));
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
        let ceremony = auth_ceremony(
            &credential,
            Some(&prf_salt),
            intent,
            editable_policy,
            None,
            false,
        )
        .await
        .map_err(KeystoreError::PasskeyCeremony)?;

        // Persist updated counter if the authenticator incremented it. This
        // happens before the decrypt below; if decryption later fails the
        // monotonic counter is harmlessly bumped (no security impact — it only
        // ever moves forward) while the unlock still returns an error.
        if ceremony.auth_result.needs_update() {
            credential.update_credential(&ceremony.auth_result);
            let updated_json = serde_json::to_string(&credential)
                .map_err(|e| KeystoreError::Malformed(format!("passkey re-serialise: {e}")))?;
            write_atomic(&dir.join("passkey.json"), updated_json.as_bytes())?;
        }

        let mut prf_output = ceremony
            .prf_output
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
        Ok(ceremony.edited_policy)
    }

    /// Run a passkey ceremony whose WebAuthn challenge is the Layer-B approval
    /// payload hash, returning the verified assertion as an approval signature.
    ///
    /// This does not decrypt or cache the wallet signing key. It proves user
    /// presence/verification for the approval payload itself, so the resulting
    /// assertion can authorize out-of-policy or authority-changing actions
    /// without making the wallet key resident in daemon memory.
    pub async fn sign_approval_with_passkey(
        &self,
        name: &str,
        unsigned: &UnsignedApproval,
        intent: Option<bloom_proto::CeremonyIntent>,
    ) -> Result<WebAuthnAssertionRecord, KeystoreError> {
        Self::validate_name(name)?;
        let dir = self.wallet_path(name);
        if !dir.exists() {
            return Err(KeystoreError::NotFound(name.into()));
        }
        let kind_str = read_trim(&dir.join("kind"))?;
        if kind_str != "passkey" {
            return Err(KeystoreError::PasskeyCredential(format!(
                "approval signing requires a passkey wallet (wallet '{name}' is '{kind_str}')"
            )));
        }
        if unsigned.wallet != name {
            return Err(KeystoreError::PasskeyCredential(format!(
                "approval wallet '{}' does not match passkey wallet '{name}'",
                unsigned.wallet
            )));
        }
        // `signer_transport` is transport/audit metadata only (§6.3): every
        // variant is a WebAuthn/CTAP2 authenticator transport, and assurance
        // is enforced from authenticator flags below, so no transport gate is
        // needed here.

        let passkey_json = std::fs::read_to_string(dir.join("passkey.json")).map_err(|source| {
            KeystoreError::Io {
                path: dir.join("passkey.json"),
                source,
            }
        })?;
        let credential: Passkey = serde_json::from_str(&passkey_json)
            .map_err(|e| KeystoreError::PasskeyCredential(e.to_string()))?;
        let challenge = unsigned.challenge_hash().map_err(Self::from_auth_api)?;
        let require_uv = unsigned.assurance == AssuranceLevel::Hardened;
        let ceremony = auth_ceremony(&credential, None, intent, None, Some(challenge), require_uv)
            .await
            .map_err(KeystoreError::PasskeyCeremony)?;

        // Deliberately no credential write-back here: the daemon re-verifies this
        // exact assertion in `verify_approval_signature_with_passkey` and owns the
        // authoritative counter update. Persisting the bump now would make the
        // stored counter equal the assertion's, which webauthn-rs treats as a
        // cloned authenticator — denying every approval from hardware keys with
        // real signature counters.

        require_user_verification_for_assurance(
            unsigned.assurance,
            ceremony.auth_result.user_verified(),
        )
        .map_err(KeystoreError::PasskeyCredential)?;

        let assertion = webauthn_assertion_record(&ceremony.credential)
            .map_err(KeystoreError::PasskeyCredential)?;
        assertion
            .validate_challenge(unsigned)
            .map_err(Self::from_auth_api)?;
        Ok(assertion)
    }

    /// One-ceremony sealed approval: a single WebAuthn get() that simultaneously
    /// (a) binds the assertion to the approval challenge hash, and (b) derives the
    /// PRF output needed to decrypt the wallet signing key. Returns both the
    /// assertion (for grant verification) and the decrypted signer (for the daemon
    /// to cache per-grant so subsequent `sign_hash` calls skip re-ceremony).
    ///
    /// Counter is NOT persisted here — the daemon re-verifies the assertion in
    /// `verify_approval_signature_with_passkey` and owns the authoritative counter
    /// update (same rationale as `sign_approval_with_passkey`, see comment at
    /// line 1759).
    pub async fn sealed_approval_ceremony(
        &self,
        name: &str,
        unsigned: &UnsignedApproval,
    ) -> Result<(WebAuthnAssertionRecord, Arc<PrivateKeySigner>), KeystoreError> {
        self.sealed_approval_ceremony_with_intent(name, unsigned, None)
            .await
    }

    /// As [`Self::sealed_approval_ceremony`], but renders the supplied review
    /// intent in the browser page before the WebAuthn prompt.
    pub async fn sealed_approval_ceremony_with_intent(
        &self,
        name: &str,
        unsigned: &UnsignedApproval,
        intent: Option<bloom_proto::CeremonyIntent>,
    ) -> Result<(WebAuthnAssertionRecord, Arc<PrivateKeySigner>), KeystoreError> {
        Self::validate_name(name)?;
        let dir = self.wallet_path(name);
        if !dir.exists() {
            return Err(KeystoreError::NotFound(name.into()));
        }
        let kind_str = read_trim(&dir.join("kind"))?;
        if kind_str != "passkey" {
            return Err(KeystoreError::PasskeyCredential(format!(
                "sealed ceremony requires a passkey wallet (wallet '{name}' is '{kind_str}')"
            )));
        }
        if unsigned.wallet != name {
            return Err(KeystoreError::PasskeyCredential(format!(
                "approval wallet '{}' does not match passkey wallet '{name}'",
                unsigned.wallet
            )));
        }

        let passkey_json = std::fs::read_to_string(dir.join("passkey.json")).map_err(|source| {
            KeystoreError::Io {
                path: dir.join("passkey.json"),
                source,
            }
        })?;
        let credential: Passkey = serde_json::from_str(&passkey_json)
            .map_err(|e| KeystoreError::PasskeyCredential(e.to_string()))?;

        let prf_salt_hex = read_trim(&dir.join("prf.salt"))?;
        let prf_salt_bytes = hex::decode(&prf_salt_hex)
            .map_err(|e| KeystoreError::Malformed(format!("prf.salt: {e}")))?;
        let prf_salt: [u8; 32] = prf_salt_bytes
            .try_into()
            .map_err(|_| KeystoreError::Malformed("prf.salt length != 32".into()))?;

        let challenge = unsigned.challenge_hash().map_err(Self::from_auth_api)?;
        let require_uv = unsigned.assurance == AssuranceLevel::Hardened;

        let ceremony = auth_ceremony(
            &credential,
            Some(&prf_salt),
            intent,
            None,
            Some(challenge),
            require_uv,
        )
        .await
        .map_err(KeystoreError::PasskeyCeremony)?;

        // Deliberately no credential write-back here: the daemon re-verifies this
        // exact assertion in `verify_approval_signature_with_passkey` and owns the
        // authoritative counter update. Persisting the bump now would make the
        // stored counter equal the assertion's, which webauthn-rs treats as a
        // cloned authenticator — denying every approval from hardware keys with
        // real signature counters.
        require_user_verification_for_assurance(
            unsigned.assurance,
            ceremony.auth_result.user_verified(),
        )
        .map_err(KeystoreError::PasskeyCredential)?;

        let assertion = webauthn_assertion_record(&ceremony.credential)
            .map_err(KeystoreError::PasskeyCredential)?;
        assertion
            .validate_challenge(unsigned)
            .map_err(Self::from_auth_api)?;

        let prf_output = ceremony
            .prf_output
            .ok_or_else(|| KeystoreError::PasskeyCeremony(PRF_NOT_SUPPORTED_MSG.into()))?;

        let signer = decrypt_signer_from_prf(&dir, prf_output)?;

        Ok((assertion, signer))
    }

    /// Build the browser WebAuthn options (with the approval challenge and the
    /// PRF extension) for a daemon-owned Mode 3 ceremony, without launching a
    /// browser or binding a server. The daemon ceremony server serves the
    /// returned `challenge_json` to the page it renders for `/ceremony/{token}`.
    ///
    /// This is the browserless front half of [`Self::sealed_approval_ceremony`]:
    /// it produces exactly the same WebAuthn options the foreground ceremony
    /// would, but the daemon — not the keystore — owns the HTTP transport.
    pub async fn sealed_ceremony_challenge(
        &self,
        wallet: &str,
        unsigned: &UnsignedApproval,
    ) -> Result<SealedCeremonyChallenge, KeystoreError> {
        Self::validate_name(wallet)?;
        let dir = self.wallet_path(wallet);
        if !dir.exists() {
            return Err(KeystoreError::NotFound(wallet.into()));
        }
        let kind_str = read_trim(&dir.join("kind"))?;
        if kind_str != "passkey" {
            return Err(KeystoreError::PasskeyCredential(format!(
                "sealed ceremony requires a passkey wallet (wallet '{wallet}' is '{kind_str}')"
            )));
        }
        if unsigned.wallet != wallet {
            return Err(KeystoreError::PasskeyCredential(format!(
                "approval wallet '{}' does not match passkey wallet '{wallet}'",
                unsigned.wallet
            )));
        }

        let passkey_json = std::fs::read_to_string(dir.join("passkey.json")).map_err(|source| {
            KeystoreError::Io {
                path: dir.join("passkey.json"),
                source,
            }
        })?;
        let credential: Passkey = serde_json::from_str(&passkey_json)
            .map_err(|e| KeystoreError::PasskeyCredential(e.to_string()))?;

        let prf_salt_hex = read_trim(&dir.join("prf.salt"))?;
        let prf_salt_bytes = hex::decode(&prf_salt_hex)
            .map_err(|e| KeystoreError::Malformed(format!("prf.salt: {e}")))?;
        let prf_salt: [u8; 32] = prf_salt_bytes
            .try_into()
            .map_err(|_| KeystoreError::Malformed("prf.salt length != 32".into()))?;

        let challenge = unsigned.challenge_hash().map_err(Self::from_auth_api)?;
        let require_uv = unsigned.assurance == AssuranceLevel::Hardened;

        let webauthn = build_webauthn().map_err(KeystoreError::PasskeyCredential)?;
        let (rcr, _auth_state) = webauthn
            .start_passkey_authentication(std::slice::from_ref(&credential))
            .map_err(|e| {
                KeystoreError::PasskeyCredential(format!("start_passkey_authentication: {e}"))
            })?;
        let challenge_json = serde_json::to_string(&rcr)
            .map_err(|e| KeystoreError::Malformed(format!("challenge serialise: {e}")))?;
        let challenge_json = patch_request_challenge_json(&challenge_json, &challenge, require_uv)
            .map_err(KeystoreError::PasskeyCredential)?;
        let v: serde_json::Value = serde_json::from_str(&challenge_json)
            .map_err(|e| KeystoreError::Malformed(format!("challenge parse: {e}")))?;
        let v = inject_prf_into_challenge_json(v, &prf_salt);
        let challenge_json = serde_json::to_string(&v)
            .map_err(|e| KeystoreError::Malformed(format!("challenge re-serialise: {e}")))?;
        let challenge_b64 = extract_challenge_b64(&challenge_json);

        Ok(SealedCeremonyChallenge {
            challenge_json,
            challenge_b64,
        })
    }

    /// Decrypt the wallet signer from a daemon-owned Mode 3 ceremony's PRF
    /// output. The daemon calls this once the browser has returned PRF output
    /// over the trusted local channel; the 32-byte output is zeroized inside
    /// and never persisted.
    ///
    /// This is the browserless back half of [`Self::sealed_approval_ceremony`].
    /// Assertion/challenge validation is the caller's responsibility (the
    /// daemon uses [`bloom_auth_api::WebAuthnAssertionRecord::validate_challenge`]
    /// and the daemon-side signature verifier); this method only turns PRF
    /// output into a usable signer.
    pub async fn sealed_ceremony_decrypt_signer(
        &self,
        wallet: &str,
        prf_output: [u8; 32],
    ) -> Result<Arc<PrivateKeySigner>, KeystoreError> {
        Self::validate_name(wallet)?;
        let dir = self.wallet_path(wallet);
        if !dir.exists() {
            return Err(KeystoreError::NotFound(wallet.into()));
        }
        let kind_str = read_trim(&dir.join("kind"))?;
        if kind_str != "passkey" {
            return Err(KeystoreError::PasskeyCredential(format!(
                "sealed ceremony requires a passkey wallet (wallet '{wallet}' is '{kind_str}')"
            )));
        }
        decrypt_signer_from_prf(&dir, prf_output)
    }

    pub async fn verify_approval_signature_with_passkey(
        &self,
        unsigned: &UnsignedApproval,
        assertion: &WebAuthnAssertionRecord,
    ) -> Result<(), KeystoreError> {
        assertion
            .validate_challenge(unsigned)
            .map_err(Self::from_auth_api)?;
        Self::validate_name(&unsigned.wallet)?;
        let dir = self.wallet_path(&unsigned.wallet);
        let passkey_json = std::fs::read_to_string(dir.join("passkey.json")).map_err(|source| {
            KeystoreError::Io {
                path: dir.join("passkey.json"),
                source,
            }
        })?;
        let mut credential: Passkey = serde_json::from_str(&passkey_json)
            .map_err(|e| KeystoreError::PasskeyCredential(e.to_string()))?;
        let webauthn = build_webauthn().map_err(KeystoreError::PasskeyCredential)?;
        let (_rcr, auth_state) = webauthn
            .start_passkey_authentication(std::slice::from_ref(&credential))
            .map_err(|e| {
                KeystoreError::PasskeyCredential(format!("start_passkey_authentication: {e}"))
            })?;
        let challenge = unsigned.challenge_hash().map_err(Self::from_auth_api)?;
        let auth_state = patch_passkey_authentication_challenge(auth_state, &challenge)
            .map_err(KeystoreError::PasskeyCredential)?;
        let mut response = serde_json::json!({
            "authenticatorData": assertion.authenticator_data_b64,
            "clientDataJSON": assertion.client_data_json_b64,
            "signature": assertion.signature_b64,
        });
        if let Some(user_handle) = &assertion.user_handle_b64 {
            response["userHandle"] = serde_json::Value::String(user_handle.clone());
        }
        let pkc_value = serde_json::json!({
            "id": assertion.credential_id,
            "rawId": assertion.credential_id,
            "type": "public-key",
            "response": response,
        });
        let pkc: PublicKeyCredential = serde_json::from_value(pkc_value)
            .map_err(|e| KeystoreError::PasskeyCredential(e.to_string()))?;
        let auth_result = webauthn
            .finish_passkey_authentication(&pkc, &auth_state)
            .map_err(|e| {
                KeystoreError::PasskeyCredential(format!("finish_passkey_authentication: {e}"))
            })?;
        require_user_verification_for_assurance(unsigned.assurance, auth_result.user_verified())
            .map_err(KeystoreError::PasskeyCredential)?;
        if auth_result.needs_update() {
            credential.update_credential(&auth_result);
            let updated_json = serde_json::to_string(&credential)
                .map_err(|e| KeystoreError::Malformed(format!("passkey re-serialise: {e}")))?;
            write_atomic(&dir.join("passkey.json"), updated_json.as_bytes())?;
        }
        Ok(())
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

        let (credential, mut prf_output) = foreground_registration_ceremony(name, &prf_salt)
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
        write_atomic(&tmp_dir.join("policy.toml"), policy_toml.as_bytes())?;
        write_policy_sig(&tmp_dir, name, &policy_toml, &signer)?;
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

        // Step 7: Return the recovery key for the one-time terminal prompt.
        let recovery_key = Some(Zeroizing::new(hex::encode(signer.to_bytes())));

        // Re-insert (same signer; new credential is now on disk).
        self.inner.unlocked.write().insert(name.to_string(), signer);
        tracing::info!(wallet = name, "keystore.passkey_rebound");

        let addr_str = read_trim(&dir.join("address"))?;
        let address = addr_str
            .parse::<Address>()
            .map_err(|e| KeystoreError::Malformed(format!("address: {e}")))?;
        let pubkey_hex = read_trim(&dir.join("pubkey"))?;
        let policy = toml::from_str::<Policy>(&policy_toml)
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
        let policy = toml::from_str::<bloom_proto::Policy>(&content).map_err(|e| {
            KeystoreError::Policy(format!("refusing to sign unparseable policy.toml: {e}"))
        })?;
        // Refuse to sign a policy whose autonomy mode is inconsistent with its
        // limits — a signed-but-unbroadcastable policy would fail at every
        // confirm with an opaque "broadcast approval required" error.
        policy
            .validate_autonomy_limits()
            .map_err(|e| KeystoreError::Policy(format!("refusing to sign policy.toml: {e}")))?;

        let signer = self.cached_signer(name)?; // must be unlocked
        write_policy_sig(&dir, name, &content, &signer)?;
        tracing::debug!(wallet = name, "keystore.policy_signed");
        Ok(())
    }
}

#[cfg(test)]
mod registration_primitive_tests {
    use super::*;

    #[test]
    fn start_registration_challenge_binds_requested_challenge_and_prf() {
        let prf_salt = [7u8; 32];
        let challenge = [9u8; 32];
        let (opts, reg_state) =
            start_registration_challenge("wallet-a", &prf_salt, &challenge).unwrap();

        let expected_challenge_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge);
        assert_eq!(
            opts["publicKey"]["challenge"].as_str(),
            Some(expected_challenge_b64.as_str())
        );
        assert_eq!(
            opts["publicKey"]["authenticatorSelection"]["requireResidentKey"].as_bool(),
            Some(true)
        );
        let expected_salt_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(prf_salt);
        assert_eq!(
            opts["publicKey"]["extensions"]["prf"]["eval"]["first"].as_str(),
            Some(expected_salt_b64.as_str())
        );

        // The patched verification state carries the same challenge — this
        // is what `finish_registration` actually verifies against, not just
        // the outgoing JSON.
        let state_json = serde_json::to_value(&reg_state).unwrap();
        assert_eq!(
            state_json["rs"]["challenge"].as_str(),
            Some(expected_challenge_b64.as_str())
        );
    }

    #[test]
    fn start_registration_challenge_differs_per_wallet_and_challenge() {
        let prf_salt = [1u8; 32];
        let (opts_a, _) = start_registration_challenge("wallet-a", &prf_salt, &[1u8; 32]).unwrap();
        let (opts_b, _) = start_registration_challenge("wallet-b", &prf_salt, &[1u8; 32]).unwrap();
        // Different wallet -> different user.id (derived from the wallet name).
        assert_ne!(
            opts_a["publicKey"]["user"]["id"],
            opts_b["publicKey"]["user"]["id"]
        );

        let (opts_c, _) = start_registration_challenge("wallet-a", &prf_salt, &[2u8; 32]).unwrap();
        assert_ne!(
            opts_a["publicKey"]["challenge"],
            opts_c["publicKey"]["challenge"]
        );
    }

    #[test]
    fn patch_passkey_registration_challenge_overwrites_only_challenge_field() {
        let prf_salt = [3u8; 32];
        let (_, reg_state) =
            start_registration_challenge("wallet-a", &prf_salt, &[5u8; 32]).unwrap();
        let before = serde_json::to_value(&reg_state).unwrap();

        let repatched = patch_passkey_registration_challenge(reg_state, &[6u8; 32]).unwrap();
        let after = serde_json::to_value(&repatched).unwrap();

        assert_ne!(before["rs"]["challenge"], after["rs"]["challenge"]);
        assert_eq!(
            after["rs"]["challenge"].as_str(),
            Some(
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode([6u8; 32])
                    .as_str()
            )
        );
        // Everything else about the registration state is untouched.
        assert_eq!(before["rs"]["policy"], after["rs"]["policy"]);
        assert_eq!(
            before["rs"]["require_resident_key"],
            after["rs"]["require_resident_key"]
        );
    }

    #[test]
    fn finish_registration_rejects_garbage_credential() {
        let prf_salt = [4u8; 32];
        let (_, reg_state) =
            start_registration_challenge("wallet-a", &prf_salt, &[8u8; 32]).unwrap();
        let garbage: serde_json::Value = serde_json::json!({
            "id": "not-a-real-credential",
            "rawId": "AAAA",
            "type": "public-key",
            "response": {
                "attestationObject": "AAAA",
                "clientDataJSON": base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(br#"{"type":"webauthn.create","challenge":"AAAA","origin":"http://localhost:18734"}"#),
            },
        });
        let credential: RegisterPublicKeyCredential = serde_json::from_value(garbage).unwrap();
        assert!(finish_registration(&credential, &reg_state).is_err());
    }
}

#[cfg(test)]
mod finalize_tests {
    use super::*;

    fn make_prepared(tmp_dir: PathBuf) -> PreparedPasskeyWallet {
        std::fs::create_dir_all(&tmp_dir).unwrap();
        std::fs::write(tmp_dir.join("marker"), b"still here").unwrap();
        PreparedPasskeyWallet {
            tmp_dir,
            address: Address::ZERO,
            pubkey_hex: "deadbeef".into(),
            policy: Policy::default(),
            recovery_key: Zeroizing::new("recovery-key-plaintext".into()),
        }
    }

    #[test]
    fn finalize_moves_tmp_dir_to_final_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let prepared = make_prepared(tmp.path().join("staged"));
        let final_dir = tmp.path().join("final");

        // `FinalizedPasskeyWallet`/`PreparedPasskeyWallet` intentionally
        // don't derive `Debug` (they carry key material), so match instead
        // of `.unwrap()`/`.unwrap_err()`.
        let finalized = match finalize_passkey_wallet(prepared, &final_dir) {
            Ok(f) => f,
            Err(_) => panic!("expected finalize to succeed"),
        };

        assert!(final_dir.join("marker").exists());
        assert_eq!(finalized.pubkey_hex, "deadbeef");
    }

    /// The bug this guards: `finalize_passkey_wallet` used to take
    /// `PreparedPasskeyWallet` by value and drop it internally on any error
    /// path, and `Drop` unconditionally `remove_dir_all`s the temp dir —
    /// destroying a still-valid, not-yet-installed wallet (including the
    /// only copy of the recovery key) on nothing more than a transient
    /// rename failure. It must now hand `prepared` back intact so a caller
    /// can retry.
    #[test]
    fn finalize_hands_prepared_back_intact_on_rename_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let staged_dir = tmp.path().join("staged");
        let prepared = make_prepared(staged_dir.clone());
        // `final_dir`'s parent doesn't exist, so `std::fs::rename` fails.
        let final_dir = tmp.path().join("no-such-parent").join("final");

        let returned = match finalize_passkey_wallet(prepared, &final_dir) {
            Ok(_) => panic!("expected finalize to fail: parent dir does not exist"),
            Err((prepared, _e)) => prepared,
        };

        assert!(
            staged_dir.join("marker").exists(),
            "a failed rename must not have deleted the still-valid prepared wallet"
        );
        assert_eq!(returned.recovery_key.as_str(), "recovery-key-plaintext");

        // The caller can still choose to discard it — dropping the
        // returned value cleans up normally.
        drop(returned);
        assert!(
            !staged_dir.exists(),
            "dropping the returned PreparedPasskeyWallet should still clean up its temp dir"
        );
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

    #[test]
    fn approval_challenge_patch_updates_request_json() {
        let challenge = [7u8; 32];
        let challenge_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge);
        let patched = patch_request_challenge_json(
            r#"{"publicKey":{"challenge":"AAAA","timeout":60000}}"#,
            &challenge,
            false,
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&patched).unwrap();
        assert_eq!(
            v["publicKey"]["challenge"].as_str(),
            Some(challenge_b64.as_str())
        );
        assert!(v["publicKey"].get("userVerification").is_none());
    }

    #[test]
    fn approval_challenge_patch_requires_uv_for_hardened() {
        let challenge = [7u8; 32];
        let patched = patch_request_challenge_json(
            r#"{"publicKey":{"challenge":"AAAA","timeout":60000}}"#,
            &challenge,
            true,
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&patched).unwrap();
        assert_eq!(
            v["publicKey"]["userVerification"].as_str(),
            Some("required")
        );
    }

    #[test]
    fn hardened_assurance_requires_user_verified_flag() {
        assert!(require_user_verification_for_assurance(AssuranceLevel::Hardened, true).is_ok());
        assert!(require_user_verification_for_assurance(AssuranceLevel::Standard, false).is_ok());
        assert!(require_user_verification_for_assurance(AssuranceLevel::Standard, true).is_ok());
        let err =
            require_user_verification_for_assurance(AssuranceLevel::Hardened, false).unwrap_err();
        assert!(err.contains("user-verified"), "{err}");
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
        assert_eq!(v["editable_policy"].as_bool(), Some(false));
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
    async fn intent_json_marks_editable_policy_reviews() {
        let state = unreviewed_state();
        *state.editable_policy.lock() =
            Some("[approval]\nagent_autonomy = \"prompt_all\"\n".into());
        let (base, _h) = serve(state.clone()).await;
        let v: serde_json::Value = client()
            .get(format!("{base}/intent.json"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(v["editable_policy"].as_bool(), Some(true));
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

/// End-to-end UV enforcement tests using a software Ed25519 WebAuthn
/// credential registered *without* UV (`user_verified: false`, policy
/// `preferred`). They pin the invariant that a presence-only assertion never
/// authorizes an approval: today webauthn-rs's hardcoded Required policy
/// rejects it first, and `require_user_verification_for_assurance` keeps the
/// hardened guarantee even if that library default ever changes.
#[cfg(test)]
mod approval_uv_tests {
    use super::*;
    use bloom_auth_api::{APPROVAL_SCHEMA_V1, SignerTransport, petal_identity};
    use ed25519_dalek::Signer as _;
    use sha2::{Digest, Sha256};

    const UP: u8 = 0x01;
    const UV: u8 = 0x04;

    fn unsigned_approval(wallet: &str, assurance: AssuranceLevel) -> UnsignedApproval {
        UnsignedApproval {
            schema: APPROVAL_SCHEMA_V1.into(),
            action_id: "tx_1".into(),
            wallet: wallet.into(),
            surface: "outbox".into(),
            petal_id: petal_identity::PETAL_ID_EVM_WALLET.into(),
            petal_digest: petal_identity::PLACEHOLDER_DIGEST_EVM_WALLET.into(),
            intent_hash: "0".repeat(64),
            server_nonce: "nonce-1".into(),
            assurance,
            daemon_terms_digest: "1".repeat(64),
            petal_policy_digest: "2".repeat(64),
            policy_version: 0,
            expiry_ms: u64::MAX,
            signer_transport: SignerTransport::BrowserWebauthn,
            credential_id: Some("cred-uv-test".into()),
            review_session_id: None,
        }
    }

    fn wallet_with_software_credential(
        root: &std::path::Path,
        wallet: &str,
    ) -> ed25519_dalek::SigningKey {
        wallet_with_software_credential_counter(root, wallet, 0)
    }

    fn wallet_with_software_credential_counter(
        root: &std::path::Path,
        wallet: &str,
        counter: u32,
    ) -> ed25519_dalek::SigningKey {
        let dir = root.join(wallet);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("kind"), "passkey\n").unwrap();
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let cose = COSEKey {
            type_: COSEAlgorithm::EDDSA,
            key: COSEKeyType::EC_OKP(COSEOKPKey {
                curve: EDDSACurve::ED25519,
                x: signing.verifying_key().to_bytes().to_vec().into(),
            }),
        };
        let passkey_json = serde_json::json!({
            "cred": {
                "cred_id": Base64UrlSafeData::from(b"cred-uv-test".to_vec()),
                "cred": cose,
                "counter": counter,
                "transports": null,
                "user_verified": false,
                "backup_eligible": false,
                "backup_state": false,
                "registration_policy": "preferred",
                "extensions": {},
                "attestation": ParsedAttestation::default(),
                "attestation_format": AttestationFormat::None,
            }
        });
        std::fs::write(
            dir.join("passkey.json"),
            serde_json::to_vec(&passkey_json).unwrap(),
        )
        .unwrap();
        signing
    }

    fn assertion_with_flags(
        signing: &ed25519_dalek::SigningKey,
        unsigned: &UnsignedApproval,
        flags: u8,
    ) -> WebAuthnAssertionRecord {
        assertion_with_flags_and_counter(signing, unsigned, flags, 0)
    }

    fn assertion_with_flags_and_counter(
        signing: &ed25519_dalek::SigningKey,
        unsigned: &UnsignedApproval,
        flags: u8,
        counter: u32,
    ) -> WebAuthnAssertionRecord {
        let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let challenge = unsigned.challenge_hash().unwrap();
        let client_data = serde_json::json!({
            "type": "webauthn.get",
            "challenge": b64(&challenge),
            "origin": format!("http://localhost:{CEREMONY_PORT}"),
            "crossOrigin": false,
        });
        let client_data_bytes = serde_json::to_vec(&client_data).unwrap();
        let mut auth_data = Vec::with_capacity(37);
        auth_data.extend_from_slice(&Sha256::digest(RP_ID.as_bytes()));
        auth_data.push(flags);
        auth_data.extend_from_slice(&counter.to_be_bytes());
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data_bytes));
        let signature = signing.sign(&signed);
        WebAuthnAssertionRecord {
            credential_id: b64(b"cred-uv-test"),
            authenticator_data_b64: b64(&auth_data),
            client_data_json_b64: b64(&client_data_bytes),
            signature_b64: b64(&signature.to_bytes()),
            user_handle_b64: None,
        }
    }

    #[tokio::test]
    async fn hardened_verification_rejects_presence_only_assertion() {
        let td = tempfile::tempdir().unwrap();
        let ks = crate::Keystore::new(td.path()).unwrap();
        let signing = wallet_with_software_credential(td.path(), "uv-wallet");
        let unsigned = unsigned_approval("uv-wallet", AssuranceLevel::Hardened);
        let signature = assertion_with_flags(&signing, &unsigned, UP);
        let err = ks
            .verify_approval_signature_with_passkey(&unsigned, &signature)
            .await
            .unwrap_err();
        // Rejected by webauthn-rs's Required policy today; the assurance gate
        // gives the same answer if the library default ever changes.
        assert!(err.to_string().contains("verified"), "{err}");
    }

    #[tokio::test]
    async fn hardened_verification_accepts_user_verified_assertion() {
        let td = tempfile::tempdir().unwrap();
        let ks = crate::Keystore::new(td.path()).unwrap();
        let signing = wallet_with_software_credential(td.path(), "uv-wallet");
        let unsigned = unsigned_approval("uv-wallet", AssuranceLevel::Hardened);
        let signature = assertion_with_flags(&signing, &unsigned, UP | UV);
        ks.verify_approval_signature_with_passkey(&unsigned, &signature)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn standard_verification_currently_rejects_presence_only_assertion() {
        let td = tempfile::tempdir().unwrap();
        let ks = crate::Keystore::new(td.path()).unwrap();
        let signing = wallet_with_software_credential(td.path(), "uv-wallet");
        let unsigned = unsigned_approval("uv-wallet", AssuranceLevel::Standard);
        let signature = assertion_with_flags(&signing, &unsigned, UP);
        // Stricter than the spec floor (standard may accept presence-only):
        // the shared ceremony policy requires UV for every assertion. Relaxing
        // standard to UP-only is a deliberate future change; this test makes
        // sure it doesn't happen by accident.
        let err = ks
            .verify_approval_signature_with_passkey(&unsigned, &signature)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("verified"), "{err}");
    }

    #[tokio::test]
    async fn standard_verification_accepts_user_verified_assertion() {
        let td = tempfile::tempdir().unwrap();
        let ks = crate::Keystore::new(td.path()).unwrap();
        let signing = wallet_with_software_credential(td.path(), "uv-wallet");
        let unsigned = unsigned_approval("uv-wallet", AssuranceLevel::Standard);
        let signature = assertion_with_flags(&signing, &unsigned, UP | UV);
        ks.verify_approval_signature_with_passkey(&unsigned, &signature)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn verification_rejects_tampered_assertion_signature() {
        let td = tempfile::tempdir().unwrap();
        let ks = crate::Keystore::new(td.path()).unwrap();
        let signing = wallet_with_software_credential(td.path(), "uv-wallet");
        let unsigned = unsigned_approval("uv-wallet", AssuranceLevel::Standard);
        let other = unsigned_approval("uv-wallet", AssuranceLevel::Hardened);
        // Assertion minted for a different approval payload must not verify,
        // even though it is a valid signature from the right credential.
        let mut record = assertion_with_flags(&signing, &other, UP | UV);
        let challenge = unsigned.challenge_hash().unwrap();
        let client_data = serde_json::json!({
            "type": "webauthn.get",
            "challenge": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge),
            "origin": format!("http://localhost:{CEREMONY_PORT}"),
            "crossOrigin": false,
        });
        record.client_data_json_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&client_data).unwrap());
        let err = ks
            .verify_approval_signature_with_passkey(&unsigned, &record)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("finish_passkey_authentication"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn counter_incrementing_assertion_verifies_once_then_replay_rejected() {
        // Hardware-key path: the authenticator reports a real signature counter
        // (stored 5, assertion 6). The daemon verifier is the only place that
        // persists counter updates — `sign_approval_with_passkey` must not,
        // because the daemon re-verifies the same assertion and a pre-bumped
        // stored counter reads as a cloned authenticator, denying every
        // approval from counter-incrementing keys.
        let td = tempfile::tempdir().unwrap();
        let ks = crate::Keystore::new(td.path()).unwrap();
        let signing = wallet_with_software_credential_counter(td.path(), "hw-wallet", 5);
        let unsigned = unsigned_approval("hw-wallet", AssuranceLevel::Hardened);
        let signature = assertion_with_flags_and_counter(&signing, &unsigned, UP | UV, 6);
        ks.verify_approval_signature_with_passkey(&unsigned, &signature)
            .await
            .unwrap();

        // The daemon persisted the bump: replaying the identical assertion now
        // fails the clone check (counter 6 is no longer greater than stored 6).
        let stored = std::fs::read_to_string(td.path().join("hw-wallet/passkey.json")).unwrap();
        assert!(stored.contains("\"counter\":6"), "{stored}");
        let err = ks
            .verify_approval_signature_with_passkey(&unsigned, &signature)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("finish_passkey_authentication"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn cross_wallet_approval_reuse_rejected() {
        let td = tempfile::tempdir().unwrap();
        let ks = crate::Keystore::new(td.path()).unwrap();
        let signing_a = wallet_with_software_credential(td.path(), "wallet-a");
        let _signing_b = wallet_with_software_credential(td.path(), "wallet-b");

        // Sign an approval for wallet-a.
        let unsigned_a = unsigned_approval("wallet-a", AssuranceLevel::Hardened);
        let signature_a = assertion_with_flags(&signing_a, &unsigned_a, UP | UV);

        // Attempt to verify it against wallet-b — the challenge hash is derived
        // from the unsigned payload (which includes the wallet name), so the
        // assertion must not cross-verify.
        let unsigned_b = unsigned_approval("wallet-b", AssuranceLevel::Hardened);
        let err = ks
            .verify_approval_signature_with_passkey(&unsigned_b, &signature_a)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("challenge does not match")
                || err.to_string().contains("finish_passkey_authentication"),
            "{err}"
        );
    }

    // ── sealed_approval_ceremony: fail-closed logic paths ───────────────────
    //
    // The happy path (and the no-PRF / missing-UV cases) drives `auth_ceremony`,
    // which binds a real socket and launches a browser — not unit-testable
    // headlessly. Those cases live below as `#[ignore]` integration tests gated
    // on `BLOOM_TEST_BROWSER=1`. The three pure-logic tests that follow exercise
    // the validation gates that fire BEFORE the ceremony, so they need no
    // authenticator.

    #[tokio::test]
    async fn sealed_approval_ceremony_fails_when_wallet_not_found() {
        let td = tempfile::tempdir().unwrap();
        let ks = crate::Keystore::new(td.path()).unwrap();
        let unsigned = unsigned_approval("my-wallet", AssuranceLevel::Hardened);
        let err = ks
            .sealed_approval_ceremony("my-wallet", &unsigned)
            .await
            .unwrap_err();
        assert!(matches!(err, KeystoreError::NotFound(_)), "{err}");
    }

    #[tokio::test]
    async fn sealed_approval_ceremony_fails_when_wallet_is_not_passkey() {
        let td = tempfile::tempdir().unwrap();
        let ks = crate::Keystore::new(td.path()).unwrap();
        // Lay down a non-passkey wallet (kind = "local").
        let dir = td.path().join("my-wallet");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("kind"), b"local\n").unwrap();
        let unsigned = unsigned_approval("my-wallet", AssuranceLevel::Hardened);
        let err = ks
            .sealed_approval_ceremony("my-wallet", &unsigned)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("sealed ceremony requires a passkey wallet")
                && msg.contains("my-wallet")
                && msg.contains("local"),
            "{msg}"
        );
    }

    #[tokio::test]
    async fn sealed_approval_ceremony_fails_when_wallet_name_mismatch() {
        let td = tempfile::tempdir().unwrap();
        let ks = crate::Keystore::new(td.path()).unwrap();
        // Create a real passkey-shaped wallet named "wallet-a".
        let _ = wallet_with_software_credential(td.path(), "wallet-a");
        // But pass an unsigned approval whose wallet field is "wallet-b".
        let unsigned = unsigned_approval("wallet-b", AssuranceLevel::Hardened);
        let err = ks
            .sealed_approval_ceremony("wallet-a", &unsigned)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("does not match passkey wallet")
                && msg.contains("wallet-b")
                && msg.contains("wallet-a"),
            "{msg}"
        );
    }

    fn browser_tests_enabled() -> bool {
        std::env::var("BLOOM_TEST_BROWSER").as_deref() == Ok("1")
    }

    fn skip_browser_test_if_disabled(test_name: &str) -> bool {
        if browser_tests_enabled() {
            return false;
        }
        eprintln!(
            "skipping {test_name}: set BLOOM_TEST_BROWSER=1 and plant a real passkey wallet to run this manual ceremony test"
        );
        true
    }

    // ── sealed_approval_ceremony: browser-gated integration tests ───────────
    //
    // These need a real authenticator (the ceremony binds port 18734 and opens
    // a browser). Run with: `BLOOM_TEST_BROWSER=1 cargo test -p bloom-keystore
    // -- --ignored sealed_approval`. They are compiled but skipped by default.

    #[tokio::test]
    #[ignore = "requires a real authenticator; set BLOOM_TEST_BROWSER=1"]
    async fn sealed_approval_ceremony_returns_assertion_and_signer() {
        if skip_browser_test_if_disabled("sealed_approval_ceremony_returns_assertion_and_signer") {
            return;
        }
        let td = tempfile::tempdir().unwrap();
        let ks = crate::Keystore::new(td.path()).unwrap();
        // NOTE: this fixture does NOT create a wallet; a maintainer must first
        // run `bloom wallet new --kind passkey my-wallet` against this tempdir
        // (pointing BLOOM_KEYSTORE_DIR at td) to plant the passkey credential,
        // prf.salt, and encrypted.key before running this test. Kept here as a
        // runnable skeleton for manual end-to-end verification.
        let unsigned = unsigned_approval("my-wallet", AssuranceLevel::Hardened);
        let (assertion, signer) = ks
            .sealed_approval_ceremony("my-wallet", &unsigned)
            .await
            .expect("ceremony succeeds and returns both assertion and signer");
        // The returned assertion must verify against the same approval.
        ks.verify_approval_signature_with_passkey(&unsigned, &assertion)
            .await
            .expect("assertion verifies");
        // The signer must be a usable secp256k1 key.
        let _addr = signer.address();
    }

    #[tokio::test]
    #[ignore = "requires a real authenticator; set BLOOM_TEST_BROWSER=1"]
    async fn sealed_approval_ceremony_fails_when_no_prf_output() {
        if skip_browser_test_if_disabled("sealed_approval_ceremony_fails_when_no_prf_output") {
            return;
        }
        let td = tempfile::tempdir().unwrap();
        let ks = crate::Keystore::new(td.path()).unwrap();
        // Same plant-a-wallet caveat as above; this asserts that an
        // authenticator which does not return a PRF output fails with the
        // PRF_NOT_SUPPORTED_MSG contract rather than silently decrypting.
        let unsigned = unsigned_approval("my-wallet", AssuranceLevel::Hardened);
        let err = ks
            .sealed_approval_ceremony("my-wallet", &unsigned)
            .await
            .unwrap_err();
        assert!(err.to_string().contains(PRF_NOT_SUPPORTED_MSG), "{}", err);
    }

    #[tokio::test]
    #[ignore = "requires a real authenticator; set BLOOM_TEST_BROWSER=1"]
    async fn sealed_approval_ceremony_fails_when_uv_missing_for_hardened() {
        if skip_browser_test_if_disabled(
            "sealed_approval_ceremony_fails_when_uv_missing_for_hardened",
        ) {
            return;
        }
        let td = tempfile::tempdir().unwrap();
        let ks = crate::Keystore::new(td.path()).unwrap();
        // Same plant-a-wallet caveat. A hardened approval must require user
        // verification; an authenticator returning only UP (not UV) must be
        // rejected after the ceremony completes.
        let unsigned = unsigned_approval("my-wallet", AssuranceLevel::Hardened);
        let err = ks
            .sealed_approval_ceremony("my-wallet", &unsigned)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("verified"), "{}", err);
    }
}
