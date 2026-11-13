use anyhow::Result;
use bloom_checkout::{
    browser::Browser,
    service::{CheckoutService, serve_api},
    view,
};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(version)]
struct Args {
    #[arg(long)]
    chromium: PathBuf,
    #[arg(long)]
    profile: PathBuf,
    #[arg(long)]
    state: PathBuf,
    #[arg(long)]
    socket: PathBuf,
    #[arg(long)]
    broker_socket: PathBuf,
    #[arg(long)]
    broker_uid: u32,
    #[arg(long)]
    machine_uid: u32,
    #[arg(long, default_value_t = 0)]
    view_port: u16,
    /// Run Chromium as the normal browser on a private Xvfb display started
    /// from this path, instead of headless. Linux only. Some shops refuse
    /// headless browsers.
    #[arg(long)]
    xvfb: Option<PathBuf>,
    /// Exit cleanly when the session-bound Broker disappears (launchd lifecycle).
    #[arg(long)]
    follow_broker_lifecycle: bool,
    #[cfg(feature = "triad-dev-harness")]
    #[arg(long)]
    fixture_allow_insecure_tls: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Checkout and its Chromium children must not write card-bearing core dumps.
    let core_limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &core_limit) } != 0 {
        anyhow::bail!("Cannot disable checkout core dumps");
    }
    let args = Args::parse();
    let lifecycle_socket = args.broker_socket.clone();
    let lifecycle_uid = args.broker_uid;
    let follow_broker = args.follow_broker_lifecycle;
    CheckoutService::reconcile_before_browser(&args.state, &args.broker_socket, args.broker_uid)
        .await?;
    #[cfg(feature = "triad-dev-harness")]
    let flags = if args.fixture_allow_insecure_tls {
        vec!["--ignore-certificate-errors".into()]
    } else {
        Vec::new()
    };
    #[cfg(not(feature = "triad-dev-harness"))]
    let flags = Vec::new();
    // The display lives until Checkout exits; Chromium exits with it.
    #[cfg(target_os = "linux")]
    let display = match &args.xvfb {
        Some(xvfb) => {
            use anyhow::Context;
            let dir = args.state.parent().context("State path has no directory")?;
            // Without a private display, run headless; never fall back to a host display.
            bloom_checkout::display::Display::start(xvfb, dir)
                .inspect_err(|error| eprintln!("Running headless: {error:#}"))
                .ok()
        }
        None => None,
    };
    #[cfg(target_os = "linux")]
    let display_environment = display
        .as_ref()
        .map(|display| display.environment().to_vec())
        .unwrap_or_default();
    #[cfg(not(target_os = "linux"))]
    let display_environment = match &args.xvfb {
        Some(_) => anyhow::bail!("--xvfb is supported only on Linux"),
        None => Vec::new(),
    };
    let browser =
        Browser::launch_on(&args.chromium, &args.profile, &flags, &display_environment).await?;
    let view_listener =
        tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, args.view_port)).await?;
    let view_port = view_listener.local_addr()?.port();
    let service = CheckoutService::new(
        browser.clone(),
        &args.state,
        args.broker_socket,
        args.broker_uid,
        view_port,
    )?;
    let api = serve_api(service.clone(), &args.socket, args.machine_uid);
    let viewer = axum::serve(view_listener, view::router(service));
    let lifecycle = async {
        if !follow_broker {
            std::future::pending::<()>().await;
        }
        loop {
            let peer = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                tokio::net::UnixStream::connect(&lifecycle_socket),
            )
            .await;
            if !matches!(peer, Ok(Ok(ref stream)) if stream.peer_cred().is_ok_and(|credentials| credentials.uid() == lifecycle_uid))
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    };
    let browser_lifecycle = async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            if browser.needs_restart() {
                anyhow::bail!("Checkout browser cannot continue; restarting checkout is required");
            }
        }
    };
    // The service manager restarts failures. Keeping a dead browser behind a
    // healthy checkout socket would leave every shopper permanently blocked.
    tokio::select! {result=api=>result?,result=viewer=>result?,_=tokio::signal::ctrl_c()=>{},_=lifecycle=>{},result=browser_lifecycle=>result?}
    Ok(())
}
