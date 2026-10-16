//! Native messaging host for the Bloom browser extension.
//!
//! `bloom-extension-host install <extension-dir> <checkout-extension-socket>`
//! writes the extension and registers this host with Chromium and Chrome.
//! Chrome then runs `<extension-dir>/host.sh`, which relays to checkout.
use anyhow::{Context, Result, bail};
use bloom_checkout::extension;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("relay") => extension::relay(Path::new(args.get(2).context("relay needs a socket")?)),
        Some("install") => install(
            Path::new(
                args.get(2)
                    .context("install needs an extension directory")?,
            ),
            Path::new(
                args.get(3)
                    .context("install needs checkout's extension socket")?,
            ),
        ),
        _ => bail!("usage: bloom-extension-host install <extension-dir> <socket> | relay <socket>"),
    }
}

fn install(dir: &Path, socket: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    for (name, content) in extension::bundle() {
        std::fs::write(dir.join(name), content)?;
    }
    let host = dir.join("host.sh");
    let me = std::env::current_exe()?.canonicalize()?;
    std::fs::write(
        &host,
        format!(
            "#!/bin/sh\nexec '{}' relay '{}'\n",
            me.display(),
            socket.display()
        ),
    )?;
    std::fs::set_permissions(&host, std::fs::Permissions::from_mode(0o700))?;
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .context("No home directory")?;
    for browser in ["chromium", "google-chrome"] {
        let hosts = config.join(browser).join("NativeMessagingHosts");
        std::fs::create_dir_all(&hosts)?;
        std::fs::write(
            hosts.join(format!("{}.json", extension::HOST_NAME)),
            serde_json::to_vec_pretty(&extension::host_manifest(&host))?,
        )?;
    }
    println!(
        "Load {} once as an unpacked extension (chrome://extensions, Developer mode).",
        dir.display()
    );
    Ok(())
}
