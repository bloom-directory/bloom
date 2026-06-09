//! `PetalManifest` — the canonical manifest schema for Bloom-native
//! petals (spec §8, §11.1) — plus its canonical codec, wasm
//! custom-section extractor, and the projector that produces the
//! validator-facing [`bloom_script::PetalManifestStub`].
//!
//! ## Why this is its own crate
//!
//! `bloom-resource-macros` is `proc-macro = true`, so it cannot export
//! non-macro public items. The chain node needs the manifest schema
//! and codec at runtime (to decode the `bloom_petal_manifest`
//! custom section from a freshly-deployed wasm and project it down
//! to the validator's stub). Splitting the schema into this library
//! crate lets both the proc-macros (compile-time encode) and the
//! chain node (runtime decode + project) share one source of truth.
//!
//! ## Public surface
//!
//! - [`types`] — the `PetalManifest` AST + variants.
//! - [`codec`] — canonical encoder / decoder.
//! - [`extract`] — wasm custom-section walker that returns the
//!   decoded `PetalManifest` from a `&[u8]` wasm binary.
//! - [`stub`] — projection from the full manifest to the lean
//!   `bloom_script::PetalManifestStub` the PTB validator consumes.

#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::too_many_lines)]

pub mod boundary;
pub mod codec;
pub mod extract;
pub mod interpret;
pub mod resolver;
pub mod stub;
pub mod types;

pub use boundary::{BoundaryConfig, BoundaryReport, boundary_check};
pub use codec::{decode, decode_from, encode, encode_into};
pub use extract::{extract_petal_manifest, extract_petal_manifest_bytes};
pub use interpret::{
    EvalOutcome, MAX_INVARIANT_PREDICATE_FUEL, Triviality, collect_field_refs, interpret_predicate,
    predicate_is_enforceable, predicate_max_fuel, predicate_triviality, predicate_uses_subtraction,
    predicate_uses_unsupported_arithmetic_shape, render_predicate_english,
};
pub use resolver::{ManifestResolver, validate_reserved_type_names};
pub use stub::to_petal_manifest_stub;
pub use types::{MANIFEST_CUSTOM_SECTION, PetalManifest, SCHEMA_VERSION};
