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
