use crate::service::{CheckoutService, ViewAction};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use std::sync::Arc;

pub fn router(service: Arc<CheckoutService>) -> Router {
    Router::new().route("/private",get(page)).route("/claim",post(claim)).route("/view",get(page))
        .route("/unlocked",get(||async {Html("<!doctype html><meta charset=utf-8><title>Bloom</title><p>Traveler details unlocked for this booking. You can close this page.</p>")}))
        .route("/view.js",get(||async {([(header::CONTENT_TYPE,"application/javascript")],include_str!("view.js"))}))
        .route("/state",get(state)).route("/frame",get(frame)).route("/action",post(action))
        .layer(axum::middleware::from_fn(|request:axum::extract::Request,next:axum::middleware::Next|async move {
            let mut response=next.run(request).await;
            response.headers_mut().insert(header::CACHE_CONTROL,"no-store".parse().unwrap());
            response.headers_mut().insert("referrer-policy","no-referrer".parse().unwrap());
            response.headers_mut().insert("content-security-policy","default-src 'none'; script-src 'self'; img-src 'self' blob:; connect-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'".parse().unwrap());
            response
        })).with_state(service)
}

fn check_origin(
    headers: &HeaderMap,
    service: &CheckoutService,
    mutation: bool,
) -> Result<(), StatusCode> {
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
    Ok(())
}

fn token(
    headers: &HeaderMap,
    service: &CheckoutService,
    mutation: bool,
) -> Result<String, StatusCode> {
    check_origin(headers, service, mutation)?;
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
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
    Json(query): Json<Claim>,
) -> Response {
    if let Err(status) = check_origin(&headers, &service, true) {
        return status.into_response();
    }
    let previous = token(&headers, &service, false).ok();
    let Ok(session) = service
        .private_claim(&query.token, previous.as_deref())
        .await
    else {
        return StatusCode::FORBIDDEN.into_response();
    };
    Json(serde_json::json!({"session":session})).into_response()
}
async fn page(State(service): State<Arc<CheckoutService>>, headers: HeaderMap) -> Response {
    if let Err(status) = check_origin(&headers, &service, false) {
        return status.into_response();
    }
    // Only a public shell. State, images and actions require the origin-bound
    // key that view.js keeps in localStorage, never an ambient localhost cookie.
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
        for (state, transient_failure) in [
            (None, false),
            (Some(json!({"state":"paid","closed":true})), false),
            (Some(json!({"state":"paid","closed":true})), true),
        ] {
            let expected_message = if state.is_some() {
                "site confirmed the purchase"
            } else {
                "Return to Bloom for the recorded outcome"
            };
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
            let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let server_reads = reads.clone();
            let app = Router::new()
                .route("/", get(|| async { Html(include_str!("view.html").replace("<script src=", "<script>localStorage.setItem('bloom.checkout.session','fixture-session')</script><script src=")) }))
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
                        let reads = server_reads.clone();
                        async move {
                            if reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 && transient_failure {
                                return StatusCode::SERVICE_UNAVAILABLE.into_response();
                            }
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
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    if let Ok(page) = browser.browse(BrowseRequest::Snapshot).await
                        && page["text"].as_str().is_some_and(|text| {
                            text.contains("Private checkout closed")
                                && text.contains(expected_message)
                        })
                    {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                }
            })
            .await
            .expect("closed checkout fixture did not finish loading");
            if transient_failure {
                assert!(reads.load(std::sync::atomic::Ordering::SeqCst) >= 2);
            }
            let tab = browser.handoff().await.unwrap();
            let result = tab.cdp.evaluate(&tab.session, r#"({
                    controlsHidden: document.getElementById('controls')?.hidden === true,
                    visibleButtons: [...document.querySelectorAll('button')].filter(b => b.getClientRects().length).length,
                    frameCleared: !document.getElementById('screen').hasAttribute('src'),
                    status: document.getElementById('status').textContent,
                    heading: document.getElementById('heading').textContent
                })"#.into()).await.unwrap();
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
