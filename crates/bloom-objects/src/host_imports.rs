//! Host-import declaration table for the new Bloom-native VM surface
//! (spec §16.2).
//!
//! This module is pure data: it lists every host import the runtime
//! installs into wasmtime, with each import's parameter and result wasm
//! value types. The wasmtime runtime crate (later) reads this table to
//! drive linking; the petal-build pipeline reads it to validate that a
//! new-framework petal only imports symbols from this list.

/// Wasm core value type (subset used by the bloom host surface).
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum WasmValType {
    /// 32-bit signed integer.
    I32,
    /// 64-bit signed integer.
    I64,
}

/// A single host-import declaration: module + name + function signature.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct HostImport {
    /// Wasm module name (e.g. `"object"`, `"cap"`, `"signer"`, `"ptb"`, `"log"`).
    pub module: &'static str,
    /// Wasm function name within the module.
    pub name: &'static str,
    /// Parameter types in declaration order.
    pub params: &'static [WasmValType],
    /// Result types in declaration order.
    pub results: &'static [WasmValType],
}

// --- shared signature tuples (kept small and shared via slice-of-slice) ---

const SIG_I32: &[WasmValType] = &[WasmValType::I32];
const SIG_I32_I32: &[WasmValType] = &[WasmValType::I32, WasmValType::I32];
const SIG_I32_I32_I32: &[WasmValType] = &[WasmValType::I32, WasmValType::I32, WasmValType::I32];
const SIG_I32X4: &[WasmValType] = &[
    WasmValType::I32,
    WasmValType::I32,
    WasmValType::I32,
    WasmValType::I32,
];
const SIG_EMPTY: &[WasmValType] = &[];

/// All host imports defined in spec §16.2, in declaration order.
///
/// Encoding contract (spec §16.2): pointers are `i32` byte offsets
/// into the petal's wasm linear memory; lengths are `i32` byte counts;
/// `handle` is an opaque `i32` index into the runtime's borrow table
/// (never the raw `ObjectId`).
pub const NEW_HOST_IMPORTS: &[HostImport] = &[
    // -------- chain.* --------
    HostImport {
        module: "chain",
        name: "msg.calldata.read",
        // (dst_ptr i32, offset i32, len i32) -> len i32
        params: SIG_I32_I32_I32,
        results: SIG_I32,
    },
    HostImport {
        module: "chain",
        name: "petal.return",
        // (data_ptr i32, data_len i32) -> trap/()
        params: SIG_I32_I32,
        results: SIG_EMPTY,
    },
    HostImport {
        module: "chain",
        name: "petal.revert",
        // (reason_ptr i32, reason_len i32) -> trap/()
        params: SIG_I32_I32,
        results: SIG_EMPTY,
    },
    // -------- object.* --------
    HostImport {
        module: "object",
        name: "borrow",
        // (id_ptr i32, mode i32) -> handle i32
        params: SIG_I32_I32,
        results: SIG_I32,
    },
    HostImport {
        module: "object",
        name: "read",
        // (handle i32, dst_ptr i32, dst_cap i32) -> len i32
        params: SIG_I32_I32_I32,
        results: SIG_I32,
    },
    HostImport {
        module: "object",
        name: "mutate",
        // (handle i32, src_ptr i32, src_len i32) -> i32
        params: SIG_I32_I32_I32,
        results: SIG_I32,
    },
    HostImport {
        module: "object",
        name: "create",
        // (type_tag_ptr i32, type_tag_len i32, payload_ptr i32, payload_len i32) -> handle i32
        params: SIG_I32X4,
        results: SIG_I32,
    },
    HostImport {
        module: "object",
        name: "transfer",
        // (handle i32, owner_kind i32, owner_payload_ptr i32, owner_payload_len i32) -> i32
        params: SIG_I32X4,
        results: SIG_I32,
    },
    HostImport {
        module: "object",
        name: "share",
        // (handle i32) -> i32
        params: SIG_I32,
        results: SIG_I32,
    },
    HostImport {
        module: "object",
        name: "freeze",
        // (handle i32) -> i32
        params: SIG_I32,
        results: SIG_I32,
    },
    HostImport {
        module: "object",
        name: "delete",
        // (handle i32) -> i32
        params: SIG_I32,
        results: SIG_I32,
    },
    HostImport {
        module: "object",
        name: "id",
        // (handle i32, out_ptr i32) -> i32
        params: SIG_I32_I32,
        results: SIG_I32,
    },
    // -------- cap.* --------
    HostImport {
        module: "cap",
        name: "check",
        // (cap_handle i32, type_tag_ptr i32, type_tag_len i32) -> i32
        params: SIG_I32_I32_I32,
        results: SIG_I32,
    },
    // -------- signer.* --------
    HostImport {
        module: "signer",
        name: "index",
        // () -> i32
        params: SIG_EMPTY,
        results: SIG_I32,
    },
    HostImport {
        module: "signer",
        name: "address",
        // (idx i32, out_ptr i32) -> i32
        params: SIG_I32_I32,
        results: SIG_I32,
    },
    // -------- ptb.* --------
    HostImport {
        module: "ptb",
        name: "command_output",
        // (cmd_idx i32, ret_idx i32, out_ptr i32, out_cap i32) -> len i32
        params: SIG_I32X4,
        results: SIG_I32,
    },
    // -------- log.* --------
    HostImport {
        module: "log",
        name: "emit",
        // (topic_ptr i32, topic_len i32, data_ptr i32, data_len i32) -> i32
        params: SIG_I32X4,
        results: SIG_I32,
    },
];

/// Look up a host import by `(module, name)`.
pub fn find(module: &str, name: &str) -> Option<&'static HostImport> {
    NEW_HOST_IMPORTS
        .iter()
        .find(|h| h.module == module && h.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The complete spec §16.2 list as `(module, name, n_params, n_results)`.
    /// Updating this fixture deliberately requires re-reading the spec.
    const EXPECTED: &[(&str, &str, usize, usize)] = &[
        ("chain", "msg.calldata.read", 3, 1),
        ("chain", "petal.return", 2, 0),
        ("chain", "petal.revert", 2, 0),
        ("object", "borrow", 2, 1),
        ("object", "read", 3, 1),
        ("object", "mutate", 3, 1),
        ("object", "create", 4, 1),
        ("object", "transfer", 4, 1),
        ("object", "share", 1, 1),
        ("object", "freeze", 1, 1),
        ("object", "delete", 1, 1),
        ("object", "id", 2, 1),
        ("cap", "check", 3, 1),
        ("signer", "index", 0, 1),
        ("signer", "address", 2, 1),
        ("ptb", "command_output", 4, 1),
        ("log", "emit", 4, 1),
    ];

    #[test]
    fn host_imports_match_spec_order() {
        assert_eq!(NEW_HOST_IMPORTS.len(), EXPECTED.len());
        for (got, want) in NEW_HOST_IMPORTS.iter().zip(EXPECTED.iter()) {
            assert_eq!(got.module, want.0);
            assert_eq!(got.name, want.1);
            assert_eq!(
                got.params.len(),
                want.2,
                "params for {}.{}",
                got.module,
                got.name
            );
            assert_eq!(
                got.results.len(),
                want.3,
                "results for {}.{}",
                got.module,
                got.name
            );
            for ty in got.params.iter().chain(got.results.iter()) {
                assert_eq!(*ty, WasmValType::I32);
            }
        }
    }

    #[test]
    fn find_known() {
        let h = find("object", "create").unwrap();
        assert_eq!(h.params.len(), 4);
        assert_eq!(h.results, SIG_I32);
    }

    #[test]
    fn find_unknown() {
        assert!(find("object", "no_such").is_none());
        assert!(find("other", "create").is_none());
    }

    #[test]
    fn signer_index_is_nullary() {
        let h = find("signer", "index").unwrap();
        assert!(h.params.is_empty());
        assert_eq!(h.results, SIG_I32);
    }
}
