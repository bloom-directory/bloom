//! 4-byte BLAKE3 method selectors for all DEX petal entry points.
//!
//! Selectors are computed at build time (see `build.rs`) and included here
//! as `pub const [u8; 4]` items. The build script reads from DEX spec §4.1.

include!(concat!(env!("OUT_DIR"), "/selectors_generated.rs"));
