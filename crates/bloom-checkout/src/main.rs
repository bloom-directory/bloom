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
    #[arg(long)]
    view_port: u16,
    /// Socket for the Bloom browser extension's native messaging host.
    #[arg(long)]
    extension_socket: Option<PathBuf>,
    /// Exit cleanly when the session-bound Broker disappears (launchd lifecycle).
    #[arg(long)]
    follow_broker_lifecycle: bool,
    #[cfg(feature = "triad-dev-harness")]
    #[arg(long)]
    fixture_allow_insecure_tls: bool,
    /// Synthetic development rehearsal only; not available in release builds.
    #[cfg(feature = "triad-dev-harness")]
    #[arg(long, requires = "extension_socket")]
    development_extension_private: bool,
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
    #[cfg(feature = "triad-dev-harness")]
    let flags = if args.fixture_allow_insecure_tls {
        vec!["--ignore-certificate-errors".into()]
    } else {
        Vec::new()
    };
    #[cfg(not(feature = "triad-dev-harness"))]
    let flags = Vec::new();
    let browser = Browser::launch(&args.chromium, &args.profile, &flags).await?;
    #[cfg(feature = "triad-dev-harness")]
    if args.development_extension_private {
        browser.allow_development_extension_private();
    }
    if let Some(path) = args.extension_socket.clone() {
        let browser = browser.clone();
        tokio::spawn(async move {
            if let Err(error) = bloom_checkout::extension::serve_extension(&path, browser).await {
                eprintln!("extension socket stopped: {error}");
            }
        });
    }
    let service = CheckoutService::new(
        browser,
        &args.state,
        args.broker_socket,
        args.broker_uid,
        args.view_port,
    )?;
    let view_listener =
        tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, args.view_port)).await?;
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
    tokio::select! {result=api=>result?,result=viewer=>result?,_=tokio::signal::ctrl_c()=>{},_=lifecycle=>{}}
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn private_extension_opt_in_exists_only_in_development_builds() {
        let command = Args::command();
        let present = command
            .get_arguments()
            .any(|arg| arg.get_id() == "development_extension_private");
        assert_eq!(present, cfg!(feature = "triad-dev-harness"));
    }
}
