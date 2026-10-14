//! Ephemeral, capability-addressed onboarding UI. Authority stays on the IPC edge.
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, State},
    http::{Request, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use bloom_daemon::ipc::{MachineCommand, MachineCommandOutput, MachineCustodyKind};
use bloom_proto::{HomeDir, persona::PersonaPreset};
use rand::RngCore as _;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::ResolvedEndpoint;

const MAX_BODY: usize = 16 * 1024;
const SESSION_LIFETIME: Duration = Duration::from_secs(30 * 60);
const IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SetupRequest {
    pub persona: PersonaPreset,
    #[serde(default)]
    pub per_action_usd: Option<String>,
    #[serde(default)]
    pub daily_usd: Option<String>,
    #[serde(default)]
    pub session_duration_secs: Option<u64>,
    pub petals: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionRequest {
    action: Action,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Action {
    WalletNew,
    WalletImport,
    Policy,
    Activate,
    Stop,
    Refresh,
}

struct AppState {
    home: HomeDir,
    endpoint: ResolvedEndpoint,
    authority: String,
    origin: String,
    mutations: Mutex<()>,
    started: Instant,
    last_request_secs: AtomicU64,
}

type App = Arc<AppState>;

/// Bind only loopback; the random path is a temporary capability and is never
/// persisted. Starting the server or loading its page grants no wallet authority.
pub(super) async fn run(home: HomeDir, endpoint: ResolvedEndpoint, no_open: bool) -> Result<()> {
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let authority = listener.local_addr()?.to_string();
    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);
    let base = format!("/onboarding/{}/", hex::encode(secret));
    let state = app_state(home, endpoint, authority);
    let url = format!("{}{}", state.origin, base);
    println!(
        "Bloom onboarding: {url}\nThis local page closes after 30 minutes. Press Ctrl-C to close it sooner."
    );
    if !no_open && let Err(error) = open_browser(&url) {
        eprintln!("Could not open the browser: {error}. Open the local URL above.");
    }
    let shutdown_state = state.clone();
    axum::serve(listener, router(state, &base))
        .with_graceful_shutdown(async move {
            loop {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => break,
                    _ = tokio::time::sleep(Duration::from_secs(10)) => {
                        let elapsed = shutdown_state.started.elapsed();
                        let last = shutdown_state.last_request_secs.load(Ordering::Relaxed);
                        if elapsed >= SESSION_LIFETIME || elapsed.as_secs().saturating_sub(last) >= IDLE_TIMEOUT.as_secs() { break; }
                    }
                }
            }
        }).await.context("serve local onboarding page")
}

fn app_state(home: HomeDir, endpoint: ResolvedEndpoint, authority: String) -> App {
    Arc::new(AppState {
        home,
        endpoint,
        origin: format!("http://{authority}"),
        authority,
        mutations: Mutex::new(()),
        started: Instant::now(),
        last_request_secs: AtomicU64::new(0),
    })
}

fn router(state: App, base: &str) -> Router {
    Router::new()
        .route(base, get(index))
        .route(&format!("{base}app.js"), get(script))
        .route(&format!("{base}style.css"), get(styles))
        .route(&format!("{base}api/state"), get(read_state))
        .route(&format!("{base}api/setup"), post(setup))
        .route(&format!("{base}api/action"), post(action))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(middleware::from_fn_with_state(state.clone(), security))
        .with_state(state)
}

async fn security(State(state): State<App>, request: Request<Body>, next: Next) -> Response {
    let host_ok = request
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        == Some(state.authority.as_str());
    let origin = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok());
    let is_post = request.method() == axum::http::Method::POST;
    let origin_ok = origin.is_none_or(|v| v == state.origin)
        && (!is_post || origin == Some(state.origin.as_str()));
    let mut response = if !host_ok || !origin_ok {
        api_error(
            StatusCode::FORBIDDEN,
            "This page only accepts requests from its local browser origin",
        )
    } else if is_post
        && !request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.split(';')
                    .next()
                    .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
            })
    {
        api_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Expected application/json",
        )
    } else {
        state
            .last_request_secs
            .store(state.started.elapsed().as_secs(), Ordering::Relaxed);
        next.run(request).await
    };
    for (name, value) in [
        (header::CACHE_CONTROL, "no-store, max-age=0"),
        (header::REFERRER_POLICY, "no-referrer"),
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        ),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
    ] {
        response
            .headers_mut()
            .insert(name, value.parse().expect("static header"));
    }
    response
}

async fn index() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        include_str!("onboarding_assets/index.html"),
    )
}
async fn script() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("onboarding_assets/app.js"),
    )
}
async fn styles() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("onboarding_assets/style.css"),
    )
}

async fn read_state(State(state): State<App>) -> Response {
    match state_snapshot(&state).await {
        Ok(value) => Json(value).into_response(),
        Err(error) => api_error(StatusCode::INTERNAL_SERVER_ERROR, &format!("{error:#}")),
    }
}

async fn state_snapshot(state: &AppState) -> Result<Value> {
    // Never initialize a home, write config, or advance a policy from a GET.
    let exists = state.home.config_path().exists();
    let config = if exists {
        Some(bloom_proto::Config::load(&state.home.config_path())?)
    } else {
        None
    };
    let persona_limits = config.as_ref().and_then(|c| c.persona.as_ref()).map(|p| {
        let decimal = |n: u64| format!("{}.{:06}", n / 1_000_000, n % 1_000_000);
        json!({"per_action_usd":decimal(p.per_action_usd_micros),"daily_usd":decimal(p.daily_usd_micros),"session_duration_secs":p.session_duration_secs.to_string()})
    });
    let config = json!({"exists":exists, "persona_limits":persona_limits, "setup_complete":config.as_ref().is_some_and(|c| c.petals.setup_complete), "persona":config.as_ref().and_then(|c| c.persona.as_ref()), "petals":config.as_ref().map(|c| c.petals.setup.keys().cloned().collect::<Vec<_>>()).unwrap_or_default()});
    let wallets = observe(state, MachineCommand::WalletList).await;
    let available = wallets["available"].as_bool().unwrap_or(false);
    // Read the public projection including freshness, not the mutation-capable
    // WalletDefaultPolicy command, which can prepare a new owner ceremony.
    let mut policy = if available {
        observe(
            state,
            MachineCommand::WalletProjection {
                name: "main".into(),
            },
        )
        .await
    } else {
        unavailable("Machine is unavailable")
    };
    if let Some(projection) = policy.get_mut("data") {
        *projection = json!({"policy":projection.get("policy"), "freshness":projection.get("freshness"), "observed_at_ms":projection.get("observed_at_ms"), "verification":projection.get("verification")});
    }
    let sessions = if available {
        observe(
            state,
            MachineCommand::PersonaSessions {
                wallet: "main".into(),
            },
        )
        .await
    } else {
        unavailable("Machine is unavailable")
    };
    let ceremony_url = sessions.get("data").and_then(find_ceremony_url);
    let catalog = crate::default_policy::menu_petals()
        .into_iter()
        .map(|id| json!({"label":crate::default_policy::petal_label(&id),"id":id}))
        .collect::<Vec<_>>();
    Ok(
        json!({"config":config, "machine":{"available":available,"error":wallets.get("error")}, "wallets":wallets, "policy":policy, "sessions":sessions, "catalog":catalog, "ceremony_url":ceremony_url}),
    )
}

async fn observe(state: &AppState, command: MachineCommand) -> Value {
    match execute(state, command).await {
        Ok(output) if output.exit_code == 0 => {
            let mut value = command_result(output);
            value["available"] = json!(true);
            value
        }
        Ok(output) => {
            let mut value = command_result(output);
            value["available"] = json!(false);
            value["error"] = value["stderr"].clone();
            value
        }
        Err(error) => unavailable(&format!("{error:#}")),
    }
}
fn unavailable(error: &str) -> Value {
    json!({"available":false,"error":error})
}

async fn execute(state: &AppState, command: MachineCommand) -> Result<MachineCommandOutput> {
    tokio::time::timeout(
        COMMAND_TIMEOUT,
        crate::machine_command(&state.endpoint, command),
    )
    .await
    .context("Machine command timed out; refresh actual state before retrying")?
}

async fn setup(State(state): State<App>, Json(request): Json<SetupRequest>) -> Response {
    let _guard = state.mutations.lock().await;
    match crate::configure_browser_setup(&state.home, &state.endpoint, request).await {
        Ok(value) => Json(value).into_response(),
        Err(error) => api_error(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    }
}

async fn action(State(state): State<App>, Json(request): Json<ActionRequest>) -> Response {
    if matches!(request.action, Action::Refresh) {
        return read_state(State(state)).await;
    }
    let _guard = state.mutations.lock().await;
    let command = match request.action {
        Action::WalletNew => MachineCommand::WalletCustody {
            name: "main".into(),
            kind: MachineCustodyKind::New,
        },
        Action::WalletImport => MachineCommand::WalletCustody {
            name: "main".into(),
            kind: MachineCustodyKind::Import,
        },
        Action::Policy => MachineCommand::WalletDefaultPolicy {
            name: "main".into(),
        },
        Action::Activate => MachineCommand::PersonaSessionActivateConfigured {
            wallet: "main".into(),
            account: 0,
        },
        Action::Stop => MachineCommand::PersonaSessionsStop {
            wallet: "main".into(),
            reason: "owner stopped sessions from onboarding".into(),
        },
        Action::Refresh => unreachable!("handled read above"),
    };
    match execute(&state, command).await {
        Ok(output) => Json(command_result(output)).into_response(),
        Err(error) => api_error(StatusCode::BAD_GATEWAY, &format!("{error:#}")),
    }
}

fn command_result(output: MachineCommandOutput) -> Value {
    let data = serde_json::from_str::<Value>(output.stdout.trim()).ok();
    let ceremony_url = data.as_ref().and_then(find_ceremony_url).or_else(|| {
        // Custody commands use an authenticated, explicitly named output field.
        output.stdout.lines().find_map(|line| {
            line.strip_prefix("ceremony_url: ")
                .and_then(valid_ceremony_url)
        })
    });
    json!({"stdout":output.stdout,"stderr":output.stderr,"exit_code":output.exit_code,"data":data,"ceremony_url":ceremony_url})
}

fn find_ceremony_url(value: &Value) -> Option<String> {
    match value {
        Value::Object(map) => map
            .get("ceremony_url")
            .and_then(Value::as_str)
            .and_then(valid_ceremony_url)
            .or_else(|| map.values().find_map(find_ceremony_url)),
        Value::Array(values) => values.iter().find_map(find_ceremony_url),
        _ => None,
    }
}
fn expected_ceremony_port() -> u16 {
    #[cfg(feature = "triad-dev-harness")]
    if std::env::var_os("BLOOM_TRIAD_DEVELOPER_ROOT")
        .is_some_and(|root| !root.is_empty() && std::path::Path::new(&root).is_absolute())
        && let Ok(port) = std::env::var("BLOOM_TRIAD_DEV_CEREMONY_PORT")
        && let Ok(port) = port.parse::<u16>()
        && port != 0
    {
        return port;
    }
    18734
}

fn valid_ceremony_url(value: &str) -> Option<String> {
    let url = url::Url::parse(value).ok()?;
    let token = url.path().strip_prefix("/ceremony/")?;
    (url.scheme() == "http"
        && matches!(url.host_str(), Some("127.0.0.1" | "localhost"))
        && url.port() == Some(expected_ceremony_port())
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && !token.is_empty()
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
    .then(|| url.to_string())
}
fn api_error(status: StatusCode, error: &str) -> Response {
    (status, Json(json!({"error":error}))).into_response()
}

fn open_browser(url: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    let mut command = std::process::Command::new("open");
    #[cfg(target_os = "linux")]
    let mut command = std::process::Command::new("xdg-open");
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut c = std::process::Command::new("rundll32.exe");
        c.arg("url.dll,FileProtocolHandler");
        c
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    anyhow::bail!("open the local URL in a browser");
    command
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("launch browser")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    struct TestServer {
        address: String,
        home: tempfile::TempDir,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for TestServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    async fn server() -> TestServer {
        let home = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let state = app_state(
            HomeDir::at(home.path()),
            ResolvedEndpoint::explicit_socket(home.path().join("absent.sock")),
            address.clone(),
        );
        let app = router(state, "/onboarding/test-secret/");
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        TestServer {
            address,
            home,
            task,
        }
    }
    async fn request(
        server: &TestServer,
        method: &str,
        path: &str,
        headers: &str,
        body: &str,
    ) -> String {
        let mut stream = tokio::net::TcpStream::connect(&server.address)
            .await
            .unwrap();
        let bytes = format!(
            "{method} {path} HTTP/1.1\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(bytes.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }
    #[tokio::test]
    async fn host_origin_and_content_type_are_required_before_mutations() {
        let server = server().await;
        let path = "/onboarding/test-secret/api/action";
        let wrong_host = request(
            &server,
            "POST",
            path,
            "Host: attacker.example\r\nContent-Type: application/json\r\n",
            r#"{"action":"wallet_new"}"#,
        )
        .await;
        assert!(wrong_host.starts_with("HTTP/1.1 403"));
        let missing_origin = request(
            &server,
            "POST",
            path,
            &format!(
                "Host: {}\r\nContent-Type: application/json\r\n",
                server.address
            ),
            r#"{"action":"wallet_new"}"#,
        )
        .await;
        assert!(missing_origin.starts_with("HTTP/1.1 403"));
        let wrong_origin=request(&server,"POST",path,&format!("Host: {}\r\nOrigin: https://attacker.example\r\nContent-Type: application/json\r\n",server.address),r#"{"action":"wallet_new"}"#).await;
        assert!(wrong_origin.starts_with("HTTP/1.1 403"));
        let wrong_type = request(
            &server,
            "POST",
            path,
            &format!(
                "Host: {}\r\nOrigin: http://{}\r\nContent-Type: text/plain\r\n",
                server.address, server.address
            ),
            r#"{"action":"wallet_new"}"#,
        )
        .await;
        assert!(wrong_type.starts_with("HTTP/1.1 415"));
        for response in [wrong_host, missing_origin, wrong_origin, wrong_type] {
            assert!(response.contains("cache-control: no-store"));
            assert!(response.contains("referrer-policy: no-referrer"));
            assert!(response.contains("frame-ancestors 'none'"));
            assert!(!response.contains("access-control-allow-origin"));
        }
        assert!(!server.home.path().join("config.toml").exists());
    }
    #[tokio::test]
    async fn capability_path_and_typed_json_cannot_select_arbitrary_commands() {
        let server = server().await;
        let headers = format!(
            "Host: {}\r\nOrigin: http://{}\r\nContent-Type: application/json\r\n",
            server.address, server.address
        );
        let unknown = request(&server, "GET", "/onboarding/other/api/state", &headers, "").await;
        assert!(unknown.starts_with("HTTP/1.1 404"));
        let extra = request(
            &server,
            "POST",
            "/onboarding/test-secret/api/action",
            &headers,
            r#"{"action":"wallet_new","wallet":"other"}"#,
        )
        .await;
        assert!(extra.starts_with("HTTP/1.1 422"));
        let command = request(
            &server,
            "POST",
            "/onboarding/test-secret/api/action",
            &headers,
            r#"{"action":"deployment_rpc"}"#,
        )
        .await;
        assert!(command.starts_with("HTTP/1.1 422"));
        assert!(!server.home.path().join("config.toml").exists());
    }
    #[tokio::test]
    async fn get_state_reports_unavailable_without_initializing_or_inventing_authority() {
        let server = server().await;
        let result = request(
            &server,
            "GET",
            "/onboarding/test-secret/api/state",
            &format!("Host: {}\r\n", server.address),
            "",
        )
        .await;
        assert!(result.starts_with("HTTP/1.1 200"));
        let state: Value = serde_json::from_str(result.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(state["config"]["exists"], false);
        assert_eq!(state["config"]["setup_complete"], false);
        assert_eq!(state["machine"]["available"], false);
        assert_eq!(state["sessions"]["available"], false);
        assert!(!server.home.path().join("config.toml").exists());
        assert!(
            find_ceremony_url(&json!({"link":"http://127.0.0.1:18734/ceremony/token"})).is_none()
        );
        assert!(
            find_ceremony_url(&json!({"ceremony_url":"https://attacker.example/ceremony/token"}))
                .is_none()
        );
        assert_eq!(
            find_ceremony_url(
                &json!({"nested":[{"ceremony_url":"http://127.0.0.1:18734/ceremony/token"}]})
            )
            .as_deref(),
            Some("http://127.0.0.1:18734/ceremony/token")
        );
    }
}
