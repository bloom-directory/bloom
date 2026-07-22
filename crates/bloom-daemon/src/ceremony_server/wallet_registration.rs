//! `/wallet-registration/{token}/...` — asynchronous, VFS-exposed passkey
//! registration ceremony, served on the same daemon-owned loopback listener
//! as Sealed Approval (`ceremony_server::spawn`).
//!
//! `token` is an untrusted routing capability (see
//! `docs/plans/2026-07-21-async-vfs-passkey-registration.md`): every handler
//! here resolves it against the [`RegistrationCoordinator`](crate::registration::RegistrationCoordinator),
//! which is the sole place that verifies WebAuthn material before consuming
//! any adjacent PRF output. No handler in this file performs verification
//! itself.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use bloom_auth_api::{AuthApiError, WalletRegistrationCompleteBody};

use super::CeremonyState;
use crate::registration::now_ms;

const WALLET_REGISTRATION_HTML: &str = include_str!("../wallet_registration.html");
const FAVICON_LIGHT: &str = include_str!("../wallet_registration_assets/favicon_light.svg");
const FAVICON_DARK: &str = include_str!("../wallet_registration_assets/favicon_dark.svg");
const FONT_INSTRUMENT_NORMAL: &[u8] =
    include_bytes!("../wallet_registration_assets/fonts/instrument-serif-normal-latin.woff2");
const FONT_INSTRUMENT_ITALIC: &[u8] =
    include_bytes!("../wallet_registration_assets/fonts/instrument-serif-italic-latin.woff2");
const FONT_INTER_TIGHT: &[u8] =
    include_bytes!("../wallet_registration_assets/fonts/inter-tight-latin.woff2");
const FONT_JETBRAINS_MONO: &[u8] =
    include_bytes!("../wallet_registration_assets/fonts/jetbrains-mono-latin.woff2");

pub(super) fn router() -> Router<CeremonyState> {
    // Every route keyed by the URL token (the page itself and all of its
    // JSON endpoints, including `/complete`'s one-time response carrying
    // the plaintext recovery key) must never be cacheable by an
    // intermediary or the browser's disk cache — apply the same
    // `no-store` policy uniformly via a layer instead of repeating a
    // header on each handler, so a new token route can't accidentally be
    // added without it.
    let token_routes = Router::new()
        .route("/wallet-registration/{token}", get(page))
        .route(
            "/wallet-registration/{token}/session.json",
            get(session_json),
        )
        .route(
            "/wallet-registration/{token}/attempts",
            post(create_attempt),
        )
        .route(
            "/wallet-registration/{token}/attempts/{attempt}/fallback-options",
            post(fallback_options),
        )
        .route(
            "/wallet-registration/{token}/attempts/{attempt}/complete",
            post(complete),
        )
        .route(
            "/wallet-registration/{token}/attempts/{attempt}/recovery-ack",
            post(recovery_ack),
        )
        .route("/wallet-registration/{token}/cancel", post(cancel))
        .layer(axum::middleware::from_fn(no_store_cache_control));

    let asset_routes = Router::new()
        .route(
            "/wallet-registration-assets/favicon-light.svg",
            get(favicon_light),
        )
        .route(
            "/wallet-registration-assets/favicon-dark.svg",
            get(favicon_dark),
        )
        .route(
            "/wallet-registration-assets/fonts/instrument-serif-normal-latin.woff2",
            get(font_instrument_normal),
        )
        .route(
            "/wallet-registration-assets/fonts/instrument-serif-italic-latin.woff2",
            get(font_instrument_italic),
        )
        .route(
            "/wallet-registration-assets/fonts/inter-tight-latin.woff2",
            get(font_inter_tight),
        )
        .route(
            "/wallet-registration-assets/fonts/jetbrains-mono-latin.woff2",
            get(font_jetbrains_mono),
        );

    token_routes.merge(asset_routes)
}

async fn no_store_cache_control(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let mut response = next.run(req).await;
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    response
}

/// Never include `AuthApiError`'s message verbatim for variants that might
/// wrap store internals in a way that could leak secret-adjacent detail;
/// all current variants are safe (no PRF/key material ever flows through
/// `AuthApiError`), but keep the mapping explicit rather than falling back
/// to a blanket `Display`.
fn err_response(e: AuthApiError) -> Response {
    let (status, message) = match &e {
        AuthApiError::NotFound(message) => (StatusCode::NOT_FOUND, message.as_str()),
        AuthApiError::Denied(message) => (StatusCode::FORBIDDEN, message.as_str()),
        AuthApiError::InvalidSubject(message)
        | AuthApiError::InvalidAssuranceTransition(message) => {
            (StatusCode::BAD_REQUEST, message.as_str())
        }
        AuthApiError::Json(_) | AuthApiError::Store(_) => {
            tracing::warn!(error = %e, "wallet_registration.request_failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal registration error",
            )
        }
    };
    (
        status,
        Json(serde_json::json!({ "ok": false, "error": message })),
    )
        .into_response()
}

fn coordinator_or_404(
    state: &CeremonyState,
) -> Result<&std::sync::Arc<dyn bloom_auth_api::WalletRegistrationCoordinator>, StatusCode> {
    state
        .daemon
        .auth_services
        .registration_coordinator()
        .ok_or(StatusCode::NOT_FOUND)
}

async fn page(
    State(state): State<CeremonyState>,
    Path(token): Path<String>,
) -> Result<Response, Response> {
    coordinator_or_404(&state)
        .map_err(IntoResponse::into_response)?
        .session_view(&token, now_ms())
        .await
        .map(|_| Html(WALLET_REGISTRATION_HTML).into_response())
        .map_err(err_response)
}

async fn session_json(
    State(state): State<CeremonyState>,
    Path(token): Path<String>,
) -> Result<Response, Response> {
    coordinator_or_404(&state)
        .map_err(IntoResponse::into_response)?
        .session_view(&token, now_ms())
        .await
        .map(|view| Json(view).into_response())
        .map_err(err_response)
}

async fn create_attempt(
    State(state): State<CeremonyState>,
    Path(token): Path<String>,
    body: String,
) -> Result<Response, Response> {
    coordinator_or_404(&state)
        .map_err(IntoResponse::into_response)?
        .create_attempt(&token, body, now_ms())
        .await
        .map(|options| Json(options).into_response())
        .map_err(err_response)
}

async fn fallback_options(
    State(state): State<CeremonyState>,
    Path((token, attempt)): Path<(String, String)>,
    Json(credential): Json<serde_json::Value>,
) -> Result<Response, Response> {
    coordinator_or_404(&state)
        .map_err(IntoResponse::into_response)?
        .fallback_options(&token, &attempt, credential, now_ms())
        .await
        .map(|options| Json(options).into_response())
        .map_err(err_response)
}

async fn complete(
    State(state): State<CeremonyState>,
    Path((token, attempt)): Path<(String, String)>,
    Json(body): Json<WalletRegistrationCompleteBody>,
) -> Result<Response, Response> {
    coordinator_or_404(&state)
        .map_err(IntoResponse::into_response)?
        .complete(&token, &attempt, body, now_ms())
        .await
        .map(|outcome| {
            // The only place `recovery_key`/`receipt` are ever serialized —
            // never logged (this response body is not traced) and never
            // written to any persisted status/session record.
            Json(serde_json::json!({
                "ok": true,
                "address": outcome.address,
                "recovery_key": outcome.recovery_key.as_str(),
                "receipt": outcome.receipt.as_str(),
            }))
            .into_response()
        })
        .map_err(err_response)
}

#[derive(serde::Deserialize)]
struct RecoveryAckBody {
    receipt: String,
}

async fn recovery_ack(
    State(state): State<CeremonyState>,
    Path((token, _attempt)): Path<(String, String)>,
    Json(body): Json<RecoveryAckBody>,
) -> Result<Response, Response> {
    coordinator_or_404(&state)
        .map_err(IntoResponse::into_response)?
        .recovery_ack(&token, &body.receipt, now_ms())
        .await
        .map(|address| Json(serde_json::json!({ "ok": true, "address": address })).into_response())
        .map_err(err_response)
}

async fn cancel(
    State(state): State<CeremonyState>,
    Path(token): Path<String>,
) -> Result<Response, Response> {
    coordinator_or_404(&state)
        .map_err(IntoResponse::into_response)?
        .cancel_by_token(&token, now_ms())
        .await
        .map(|()| Json(serde_json::json!({ "ok": true })).into_response())
        .map_err(err_response)
}

async fn favicon_light() -> impl IntoResponse {
    (
        [
            (
                axum::http::header::CONTENT_TYPE,
                "image/svg+xml; charset=utf-8",
            ),
            (axum::http::header::CACHE_CONTROL, "no-cache"),
        ],
        FAVICON_LIGHT,
    )
}

async fn favicon_dark() -> impl IntoResponse {
    (
        [
            (
                axum::http::header::CONTENT_TYPE,
                "image/svg+xml; charset=utf-8",
            ),
            (axum::http::header::CACHE_CONTROL, "no-cache"),
        ],
        FAVICON_DARK,
    )
}

fn font_response(font: &'static [u8]) -> impl IntoResponse {
    (
        [
            (axum::http::header::CONTENT_TYPE, "font/woff2"),
            (axum::http::header::CACHE_CONTROL, "no-cache"),
        ],
        font,
    )
}

async fn font_instrument_normal() -> impl IntoResponse {
    font_response(FONT_INSTRUMENT_NORMAL)
}

async fn font_instrument_italic() -> impl IntoResponse {
    font_response(FONT_INSTRUMENT_ITALIC)
}

async fn font_inter_tight() -> impl IntoResponse {
    font_response(FONT_INTER_TIGHT)
}

async fn font_jetbrains_mono() -> impl IntoResponse {
    font_response(FONT_JETBRAINS_MONO)
}
