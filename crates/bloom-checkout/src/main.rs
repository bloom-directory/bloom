use anyhow::Result;
use bloom_checkout::{
    browser::Browser,
    service::{CheckoutService, serve_api},
    view,
};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let browser = Browser::launch(&args.chromium, &args.profile, &[]).await?;
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
    tokio::select! {result=api=>result?,result=viewer=>result?,_=tokio::signal::ctrl_c()=>{}}
    Ok(())
}
