//! Native messaging host for the Bloom browser extension.
//!
//! `bloom-extension-host install <extension-dir> <checkout-extension-socket>`
//! writes the extension and registers this host with Chromium and Chrome.
//! Chrome then runs `<extension-dir>/host.sh`, which relays to checkout.
use anyhow::{Context, Result, bail};
use bloom_checkout::extension;
use clap::{Parser, Subcommand};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    version,
    about = "Install or run Bloom's browser native-messaging host"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Install {
        extension_dir: PathBuf,
        socket: PathBuf,
    },
    Relay {
        socket: PathBuf,
    },
}

fn main() -> Result<()> {
    match Args::parse().command {
        Command::Relay { socket } => extension::relay(&socket),
        Command::Install {
            extension_dir,
            socket,
        } => install(&extension_dir, &socket),
    }
}

fn install(dir: &Path, socket: &Path) -> Result<()> {
    if !socket.is_absolute() {
        bail!("Checkout socket must be an absolute path");
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("No home directory")?;
    let config = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
    let registrations = host_directories(std::env::consts::OS, &home, config.as_deref())?;
    std::fs::create_dir_all(dir)?;
    let dir = dir.canonicalize()?;
    for (name, content) in extension::bundle() {
        std::fs::write(dir.join(name), content)?;
    }
    let host = dir.join("host.sh");
    let me = std::env::current_exe()?.canonicalize()?;
    std::fs::write(&host, wrapper(&me, socket)?)?;
    std::fs::set_permissions(&host, std::fs::Permissions::from_mode(0o700))?;
    for hosts in registrations {
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

fn wrapper(executable: &Path, socket: &Path) -> Result<String> {
    fn quote(path: &Path) -> Result<String> {
        let value = path.to_str().context("Native host paths must be UTF-8")?;
        Ok(format!("'{}'", value.replace('\'', "'\\''")))
    }
    Ok(format!(
        "#!/bin/sh\nexec {} relay {}\n",
        quote(executable)?,
        quote(socket)?
    ))
}

fn host_directories(os: &str, home: &Path, config: Option<&Path>) -> Result<Vec<PathBuf>> {
    if !home.is_absolute() || config.is_some_and(|path| !path.is_absolute()) {
        bail!("Native messaging registration requires absolute home/config paths");
    }
    let directories = match os {
        "linux" => {
            let root = config
                .map(Path::to_path_buf)
                .unwrap_or_else(|| home.join(".config"));
            ["chromium", "google-chrome"]
                .map(|browser| root.join(browser))
                .to_vec()
        }
        "macos" => ["Google/Chrome", "Chromium"]
            .map(|browser| home.join("Library/Application Support").join(browser))
            .to_vec(),
        _ => bail!("Native messaging installation is supported only on Linux and macOS"),
    };
    Ok(directories
        .into_iter()
        .map(|path| path.join("NativeMessagingHosts"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_paths_match_each_platform() {
        let home = Path::new("/users/person");
        assert_eq!(
            host_directories("linux", home, None).unwrap()[0],
            home.join(".config/chromium/NativeMessagingHosts")
        );
        assert_eq!(
            host_directories("linux", home, Some(Path::new("/config"))).unwrap()[1],
            Path::new("/config/google-chrome/NativeMessagingHosts")
        );
        assert_eq!(
            host_directories("macos", home, Some(Path::new("/ignored"))).unwrap()[0],
            home.join("Library/Application Support/Google/Chrome/NativeMessagingHosts")
        );
        assert!(host_directories("windows", home, None).is_err());
        assert!(host_directories("linux", Path::new("relative"), None).is_err());
    }

    #[test]
    fn wrapper_treats_quotes_and_shell_characters_as_path_bytes() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let executable = root.path().join("host ' $(false)");
        symlink("/bin/echo", &executable).unwrap();
        let socket = root.path().join("socket ' $(false)");
        let output = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(wrapper(&executable, &socket).unwrap())
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!("relay {}\n", socket.display())
        );
    }
}
