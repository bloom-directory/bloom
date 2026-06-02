//! `PetalManifestV0` — the canonical manifest schema for Bloom-native
//! petals (spec §8, §11.1) — plus its canonical codec, wasm
//! custom-section extractor, and the projector that produces the
//! validator-facing [`bloom_script::PetalManifestStub`].
//!
//! ## Why this is its own crate
//!
//! `bloom-resource-macros` is `proc-macro = true`, so it cannot export
//! non-macro public items. The chain node needs the manifest schema
//! and codec at runtime (to decode the `bloom_petal_manifest_v0`
//! custom section from a freshly-deployed wasm and project it down
//! to the validator's stub). Splitting the schema into this library
//! crate lets both the proc-macros (compile-time encode) and the
//! chain node (runtime decode + project) share one source of truth.
//!
//! ## Public surface
//!
//! - [`types`] — the `PetalManifestV0` AST + variants.
//! - [`codec`] — canonical encoder / decoder.
//! - [`extract`] — wasm custom-section walker that returns the
//!   decoded `PetalManifestV0` from a `&[u8]` wasm binary.
//! - [`stub`] — projection from the full manifest to the lean
//!   `bloom_script::PetalManifestStub` the PTB validator consumes.

#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::too_many_lines)]

pub mod codec;
pub mod extract;
pub mod resolver;
pub mod stub;
pub mod types;

pub use codec::{decode, decode_from, encode, encode_into};
pub use extract::{extract_petal_manifest_v0, extract_petal_manifest_v0_bytes};
pub use resolver::{ManifestResolver, validate_reserved_type_names};
pub use stub::to_petal_manifest_stub;
pub use types::{MANIFEST_CUSTOM_SECTION, PetalManifestV0, SCHEMA_VERSION};
