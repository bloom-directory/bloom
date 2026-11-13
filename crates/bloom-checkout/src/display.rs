//! A private virtual display, so Chromium runs as the normal browser rather
//! than in headless mode. Some shops refuse any browser that reports itself
//! as headless. Nothing about the browser is disguised: it is ordinary Chrome.
//!
//! Only holders of the random cookie can connect, and the server listens on
//! neither TCP nor the abstract socket namespace, so other local accounts
//! cannot read the screen while a card is entered.
//!
//! Xvfb runs in its own user and mount namespace whose `/tmp` is a private
//! directory, so its socket and lock file never touch the host's
//! `/tmp/.X11-unix` or `/tmp/.X<n>-lock`. A desktop's display cannot be
//! taken over, even when a sandbox hides the desktop's lock file.
//! Chromium connects by the socket's full path.

use crate::cdp::{child_fd, pipe};
use anyhow::{Context, Result, bail};
use std::{
    ffi::{CStr, CString},
    fs::File,
    io::{Read, Write},
    os::fd::AsRawFd,
    os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, OpenOptionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

pub struct Display {
    child: Child,
    socket: PathBuf,
    authority: PathBuf,
}

impl Display {
    /// Starts Xvfb with an authority file and its own `/tmp` in `dir`, which
    /// must be private.
    pub fn start(xvfb: &Path, dir: &Path) -> Result<Self> {
        let authority = dir.join("Xauthority");
        write_authority(&authority)?;
        let tmp = dir.join("display-tmp");
        // Xvfb clears a stopped earlier display's stale lock and socket itself.
        if !tmp.is_dir() {
            std::fs::DirBuilder::new().mode(0o700).create(&tmp)?;
        }
        let sockets = tmp.join(".X11-unix");
        // Leave room for "/X<number>" inside sockaddr_un's 108 bytes.
        if sockets.as_os_str().len() > 96 {
            bail!("The display directory path is too long: {}", tmp.display());
        }
        let tmp_c = CString::new(tmp.as_os_str().as_bytes())?;
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let uid_map = format!("{uid} {uid} 1");
        let gid_map = format!("{gid} {gid} 1");
        let (read, write) = pipe()?;
        let child_write = child_fd(&write)?;
        let output = child_write.as_raw_fd();
        let mut command = Command::new(xvfb);
        command
            .args(["-displayfd", "3", "-nolisten", "tcp", "-nolisten", "local"])
            .arg("-auth")
            .arg(&authority)
            .args(["-screen", "0", "1280x900x24"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // The child executes only async-signal-safe calls before exec.
        unsafe {
            command.pre_exec(move || {
                // The display ends with Checkout, even if Checkout is killed.
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                    || libc::dup2(output, 3) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                isolate(&tmp_c, &uid_map, &gid_map)
            });
        }
        let mut child = command
            .spawn()
            .context("Cannot start the virtual display")?;
        drop(child_write);
        drop(write);
        // Xvfb writes its display number once it accepts connections, or
        // closes the pipe by exiting.
        let mut number = String::new();
        let mut reader = File::from(read);
        let mut byte = [0; 1];
        while reader.read(&mut byte)? == 1 && byte[0] != b'\n' && number.len() < 8 {
            number.push(byte[0] as char);
        }
        let Ok(number) = number.parse::<u32>() else {
            let _ = child.kill();
            let _ = child.wait();
            bail!("The virtual display did not start");
        };
        Ok(Self {
            child,
            socket: sockets.join(format!("X{number}")),
            authority,
        })
    }

    pub fn environment(&self) -> [(&'static str, std::ffi::OsString); 2] {
        let mut display = std::ffi::OsString::from("unix:");
        display.push(&self.socket);
        [
            ("DISPLAY", display),
            ("XAUTHORITY", self.authority.clone().into_os_string()),
        ]
    }
}

/// Runs in the forked Xvfb child before exec, so it uses only raw system
/// calls: enter a new user and mount namespace and bind `tmp` over `/tmp`.
fn isolate(tmp: &CStr, uid_map: &str, gid_map: &str) -> std::io::Result<()> {
    let fail = || Err(std::io::Error::last_os_error());
    unsafe {
        if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) != 0 {
            return fail();
        }
        for (path, text) in [
            (c"/proc/self/setgroups", "deny"),
            (c"/proc/self/uid_map", uid_map),
            (c"/proc/self/gid_map", gid_map),
        ] {
            let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
            if fd < 0 {
                return fail();
            }
            let written = libc::write(fd, text.as_ptr().cast(), text.len());
            libc::close(fd);
            if written != text.len() as isize {
                return fail();
            }
        }
        if libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        ) != 0
            || libc::mount(
                tmp.as_ptr(),
                c"/tmp".as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            ) != 0
        {
            return fail();
        }
    }
    Ok(())
}

impl Drop for Display {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One MIT-MAGIC-COOKIE-1 entry that matches any address and display.
fn write_authority(path: &Path) -> Result<()> {
    use rand::RngCore;
    let mut cookie = [0; 16];
    rand::thread_rng().fill_bytes(&mut cookie);
    let mut entry = 0xffffu16.to_be_bytes().to_vec();
    for field in [&b""[..], b"", b"MIT-MAGIC-COOKIE-1", &cookie] {
        entry.extend_from_slice(&(field.len() as u16).to_be_bytes());
        entry.extend_from_slice(field);
    }
    let _ = std::fs::remove_file(path);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?
        .write_all(&entry)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn xvfb() -> Option<PathBuf> {
        let found = std::env::var_os("PATH")
            .into_iter()
            .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
            .map(|dir| dir.join("Xvfb"))
            .find(|path| path.is_file());
        if found.is_none() {
            eprintln!("Xvfb is not installed; skipping the headed browser test");
        }
        found
    }

    /// The X11 connection setup reply: 0 refused, 1 accepted.
    fn handshake(socket: &str, cookie: Option<&[u8]>) -> u8 {
        let mut stream = std::os::unix::net::UnixStream::connect(socket).unwrap();
        let name: &[u8] = if cookie.is_some() {
            b"MIT-MAGIC-COOKIE-1"
        } else {
            b""
        };
        let data = cookie.unwrap_or(b"");
        let mut setup = vec![b'l', 0, 11, 0, 0, 0];
        setup.extend_from_slice(&(name.len() as u16).to_le_bytes());
        setup.extend_from_slice(&(data.len() as u16).to_le_bytes());
        setup.extend_from_slice(&[0, 0]);
        for field in [name, data] {
            setup.extend_from_slice(field);
            setup.resize(setup.len().next_multiple_of(4), 0);
        }
        stream.write_all(&setup).unwrap();
        let mut reply = [0];
        stream.read_exact(&mut reply).unwrap();
        reply[0]
    }

    #[tokio::test]
    async fn headed_browser_runs_on_a_display_only_its_cookie_opens() {
        let Some(xvfb) = xvfb() else { return };
        let dir = tempfile::tempdir().unwrap();
        let host_x11 = || std::fs::read_dir("/tmp/.X11-unix").map(|e| e.count()).ok();
        let host_before = host_x11();
        let display = Display::start(&xvfb, dir.path()).unwrap();
        let environment = display.environment();
        let socket = environment[0]
            .1
            .to_str()
            .unwrap()
            .strip_prefix("unix:")
            .unwrap()
            .to_owned();
        // The socket lives in Checkout's directory, never in the host's.
        assert!(socket.starts_with(dir.path().to_str().unwrap()), "{socket}");
        assert_eq!(host_x11(), host_before, "the host's X11 sockets changed");
        let number = socket.rsplit_once("/X").unwrap().1.to_owned();
        let authority = std::fs::read(&environment[1].1).unwrap();
        assert_eq!(
            std::fs::metadata(&environment[1].1)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            handshake(&socket, None),
            0,
            "a client without the cookie connected"
        );
        assert_eq!(
            handshake(&socket, Some(&authority[authority.len() - 16..])),
            1
        );
        // No listener in the abstract namespace, which ignores file permissions.
        let sockets = std::fs::read_to_string("/proc/net/unix").unwrap();
        assert!(!sockets.contains(&format!("@/tmp/.X11-unix/X{number}")));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let page = || async { axum::response::Html("<h1>Headed fixture</h1>") };
            axum::serve(
                listener,
                axum::Router::new().route("/", axum::routing::get(page)),
            )
            .await
            .unwrap();
        });
        let browser = crate::browser::Browser::launch_on(
            &crate::test_chromium(),
            &dir.path().join("profile"),
            &["--no-sandbox".into()],
            &environment,
        )
        .await
        .unwrap();
        browser
            .browse(crate::browser::BrowseRequest::Open { url })
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let snapshot = browser
            .browse(crate::browser::BrowseRequest::Snapshot)
            .await
            .unwrap();
        assert!(
            snapshot["text"]
                .as_str()
                .unwrap()
                .contains("Headed fixture")
        );
        let tab = browser.handoff().await.unwrap();
        let agent = tab
            .cdp
            .evaluate(&tab.session, "navigator.userAgent".into())
            .await
            .unwrap();
        assert!(!agent.as_str().unwrap().contains("Headless"), "{agent}");
        // The private view streams screenshots of this browser.
        let shot = tab
            .cdp
            .call(
                Some(&tab.session),
                "Page.captureScreenshot",
                serde_json::json!({}),
            )
            .await
            .unwrap();
        assert!(shot["data"].as_str().is_some_and(|data| data.len() > 100));
        // A headed browser quits when its last window closes; both handbacks
        // close every private page and must leave a usable browser.
        drop(tab);
        browser.return_control_signed_in().await.unwrap();
        browser.handoff().await.unwrap();
        browser.return_control().await.unwrap();
        assert!(!browser.needs_restart());
        assert_eq!(
            browser
                .browse(crate::browser::BrowseRequest::Snapshot)
                .await
                .unwrap()["url"],
            "about:blank"
        );
        server.abort();
    }
}
