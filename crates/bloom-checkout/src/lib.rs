//! Checkout owns its browser. Machine receives only a narrow, revocable view.
pub mod browser;
mod cdp;
mod discovery;
mod hpke;
pub mod service;
pub mod view;
