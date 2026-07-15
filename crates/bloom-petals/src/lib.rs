//! Content-addressed wasm petals for bloom.
//!
//! Petals are content-addressed wasm artifacts with metadata under
//! `~/.bloom/petals`. Local plugin packages are Petals mounted through
//! the `petals/` VFS router. Raw single-WASM local petal installation and
//! execution is intentionally unsupported.

#![forbid(unsafe_code)]

pub mod abi;
pub mod error;
pub mod host;
pub mod meta;
pub mod package;
pub mod policy;
pub mod private_store;
pub mod registry;
pub mod router;
pub mod runner;
pub mod store;
pub mod vm;

pub use abi::{
    ApprovalRequired, DispatchEntry, DispatchEntryKind, DispatchOp, DispatchRequest,
    DispatchResponse, EvmOutboxInspection, EvmOutboxOutcome, EvmTransactionRequest, HttpRequest,
    HttpResponse, SignBatchOutcome, SignBatchRequest, SignOutcome, SignRequest,
    decode_dispatch_request, decode_dispatch_response, decode_http_request, decode_http_response,
    decode_sign_request, decode_string_list, encode_dispatch_request, encode_dispatch_response,
    encode_http_request, encode_http_response, encode_sign_request, encode_string_list,
};
pub use error::PetalError;
pub use host::{DenyHost, HostError, HostVfsEntry, HostVfsEntryKind, PetalHost};
pub use meta::{Capability, PetalMeta, PetalMode};
pub use package::{PetalPackage, RouteMatch, RouteRecord, RouteSpecificity};
pub use policy::NetPolicy;
pub use private_store::PrivateStore;
pub use registry::{NameRegistry, validate_name};
pub use router::PetalRouter;
pub use runner::{LateVfsHost, PetalRunner, VfsHost};
pub use store::{InstallResult, PetalStore};
pub use vm::{PetalVm, RunOptions, RunOutput};
