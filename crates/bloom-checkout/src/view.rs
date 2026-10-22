use crate::service::{CheckoutService, ViewAction};
use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use std::sync::Arc;

pub fn router(service: Arc<CheckoutService>) -> Router {
    Router::new().route("/private",get(claim)).route("/view",get(page))
        .route("/unlocked",get(||async {Html("<!doctype html><meta charset=utf-8><title>Bloom</title><p>Traveler details unlocked for this booking. You can close this page.</p>")}))
        .route("/view.js",get(||async {([(header::CONTENT_TYPE,"application/javascript")],include_str!("view.js"))}))
        .route("/state",get(state)).route("/frame",get(frame)).route("/action",post(action))
        .layer(axum::middleware::from_fn(|request:axum::extract::Request,next:axum::middleware::Next|async move {
            let mut response=next.run(request).await;
            response.headers_mut().insert(header::CACHE_CONTROL,"no-store".parse().unwrap());
            response.headers_mut().insert("referrer-policy","no-referrer".parse().unwrap());
            response.headers_mut().insert("content-security-policy","default-src 'none'; script-src 'self'; img-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'".parse().unwrap());
            response
        })).with_state(service)
}

fn token(
    headers: &HeaderMap,
    service: &CheckoutService,
    mutation: bool,
) -> Result<String, StatusCode> {
    let host = format!("localhost:{}", service.view_port);
    if headers.get(header::HOST).and_then(|v| v.to_str().ok()) != Some(host.as_str()) {
        return Err(StatusCode::FORBIDDEN);
    }
    let origin = format!("http://{host}");
    if mutation
        && headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) != Some(origin.as_str())
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let name = format!("bloom_checkout_{}=", service.view_port);
    headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies
                .split(';')
                .map(str::trim)
                .find_map(|c| c.strip_prefix(&name))
        })
        .map(str::to_owned)
        .ok_or(StatusCode::UNAUTHORIZED)
}

#[derive(Deserialize)]
struct Claim {
    token: String,
}
async fn claim(
    State(service): State<Arc<CheckoutService>>,
    headers: HeaderMap,
    Query(query): Query<Claim>,
) -> Response {
    let host = format!("localhost:{}", service.view_port);
    if headers.get(header::HOST).and_then(|v| v.to_str().ok()) != Some(host.as_str())
        || service.private_claim(&query.token).await.is_err()
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let cookie = format!(
        "bloom_checkout_{}={}; HttpOnly; SameSite=Strict; Path=/; Max-Age=1800",
        service.view_port, query.token
    );
    (
        StatusCode::SEE_OTHER,
        [
            (header::SET_COOKIE, cookie),
            (header::LOCATION, "/view".into()),
        ],
    )
        .into_response()
}
async fn page(State(service): State<Arc<CheckoutService>>, headers: HeaderMap) -> Response {
    let Ok(token) = token(&headers, &service, false) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if service.private_state(&token).await.is_err() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    Html(include_str!("view.html")).into_response()
}
async fn state(State(service): State<Arc<CheckoutService>>, headers: HeaderMap) -> Response {
    let Ok(token) = token(&headers, &service, false) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match service.private_state(&token).await {
        Ok(value) => Json(value).into_response(),
        Err(_) => StatusCode::GONE.into_response(),
    }
}
async fn frame(State(service): State<Arc<CheckoutService>>, headers: HeaderMap) -> Response {
    let Ok(token) = token(&headers, &service, false) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match service.private_screenshot(&token).await {
        Ok(bytes) => ([(header::CONTENT_TYPE, "image/png")], bytes).into_response(),
        Err(_) => StatusCode::GONE.into_response(),
    }
}
async fn action(
    State(service): State<Arc<CheckoutService>>,
    headers: HeaderMap,
    Json(action): Json<ViewAction>,
) -> Response {
    let Ok(token) = token(&headers, &service, true) else {
        return StatusCode::FORBIDDEN.into_response();
    };
    match service.private_action(&token, action).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => StatusCode::CONFLICT.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser::{BrowseRequest, Browser};
    use serde_json::json;

    #[tokio::test]
    async fn closed_private_page_hides_controls_and_preserves_outcome() {
        for state in [None, Some(json!({"state":"paid","closed":true}))] {
            let expected_message = if state.is_some() {
                "site confirmed the purchase"
            } else {
                "Return to Bloom for the recorded outcome"
            };
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
            let app = Router::new()
                .route("/", get(|| async { Html(include_str!("view.html")) }))
                .route(
                    "/view.js",
                    get(|| async {
                        (
                            [(header::CONTENT_TYPE, "application/javascript")],
                            include_str!("view.js"),
                        )
                    }),
                )
                .route(
                    "/state",
                    get(move || {
                        let state = state.clone();
                        async move {
                            match state {
                                Some(state) => Json(state).into_response(),
                                None => StatusCode::GONE.into_response(),
                            }
                        }
                    }),
                );
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let root = tempfile::tempdir().unwrap().keep();
            let browser = Browser::launch(
                &crate::test_chromium(),
                &root.join("profile"),
                &["--no-sandbox".into()],
            )
            .await
            .unwrap();
            browser.browse(BrowseRequest::Open { url }).await.unwrap();
            let tab = browser.handoff().await.unwrap();
            let result = tab.cdp.evaluate(&tab.session, r#"(async () => {
                for (let i = 0; i < 100; i++) {
                    if (!document.getElementById('status')?.textContent.includes('Waiting')) break;
                    await new Promise(resolve => setTimeout(resolve, 20));
                }
                return {
                    controlsHidden: document.getElementById('controls')?.hidden === true,
                    visibleButtons: [...document.querySelectorAll('button')].filter(b => b.getClientRects().length).length,
                    frameCleared: !document.getElementById('screen').hasAttribute('src'),
                    status: document.getElementById('status').textContent,
                    heading: document.getElementById('heading').textContent
                };
            })()"#.into()).await.unwrap();
            assert_eq!(result["controlsHidden"], true, "{result}");
            assert_eq!(result["visibleButtons"], 0, "{result}");
            assert_eq!(result["frameCleared"], true, "{result}");
            assert!(
                result["status"]
                    .as_str()
                    .unwrap()
                    .contains(expected_message),
                "{result}"
            );
            assert_eq!(result["heading"], "Private checkout closed");
            drop(tab);
            drop(browser);
            server.abort();
        }
    }
}
