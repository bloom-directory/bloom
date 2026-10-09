//! Checkout owns its browser. Machine receives only a narrow, revocable view.
pub mod browser;
mod cdp;
mod discovery;
mod hpke;
pub mod service;
pub mod view;

#[cfg(test)]
fn test_chromium() -> std::path::PathBuf {
    if let Some(path) = std::env::var_os("BLOOM_CHECKOUT_TEST_CHROMIUM") {
        return path.into();
    }
    [
        "/usr/lib/chromium/chromium",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    ]
    .into_iter()
    .map(std::path::PathBuf::from)
    .find(|p| p.is_file())
    .expect("Checkout fixtures require Chromium; set BLOOM_CHECKOUT_TEST_CHROMIUM")
}
mod crash_protection;
