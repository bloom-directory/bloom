//! Raw unsafe host import declarations for all chain-mode host imports.
//!
//! Signatures verified against the host implementation in
//! `bloom-petals/src/chain_vm.rs` (`link_chain_imports`). The wasm import
//! module is `"chain"` throughout; each function name uses the dotted form
//! matching the host linker (e.g. `"state.read"`, `"petal.call"`, etc.).
//!
//! On wasm32: `unsafe extern "C"` declarations linked against the chain runtime.
//! On non-wasm32: stub functions that panic (for compile-only host builds).
//!
//! All public wrappers live in the sibling modules (`state`, `petal`, `block`,
//! `msg`, `log`, `crypto`, `host`). Callers should use those, not the raw
//! imports here.

// ---------------------------------------------------------------------------
// wasm32 target — real host imports
// ---------------------------------------------------------------------------

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "chain")]
unsafe extern "C" {
    // ---- state ----

    /// Read 32-byte value at `key[0..key_len]` into `out_ptr[0..32]`.
    /// Returns 32 on hit, negative error code on miss/error.
    #[link_name = "state.read"]
    pub fn state_read(key_ptr: i32, key_len: i32, out_ptr: i32) -> i64;

    /// Write `val[0..val_len]` (≤ 32 bytes, left-padded) at `key[0..key_len]`.
    /// Returns 0 on success, negative error code on failure.
    #[link_name = "state.write"]
    pub fn state_write(key_ptr: i32, key_len: i32, val_ptr: i32, val_len: i32) -> i32;

    /// Clear `key[0..key_len]`. Returns 0 on success, negative on error.
    #[link_name = "state.delete"]
    pub fn state_delete(key_ptr: i32, key_len: i32) -> i32;

    // ---- petal ----

    /// Synchronous nested call to `target[0..target_len]` with `calldata`.
    /// `value_lo` and `value_hi` are the low/high 64 bits of the u128 LOOM value.
    /// Return data (up to `retdata_max` bytes) is written to `retdata_ptr`.
    /// Returns retdata length on success, negative error code on failure/revert.
    #[link_name = "petal.call"]
    pub fn petal_call(
        target_ptr: i32,
        target_len: i32,
        cd_ptr: i32,
        cd_len: i32,
        value_lo: i64,
        value_hi: i64,
        retdata_ptr: i32,
        retdata_max: i32,
    ) -> i64;

    /// Store return data and exit successfully. Does not return.
    #[link_name = "petal.return"]
    pub fn petal_return(data_ptr: i32, data_len: i32) -> !;

    /// Discard write set and exit with revert. Does not return.
    #[link_name = "petal.revert"]
    pub fn petal_revert(msg_ptr: i32, msg_len: i32) -> !;

    // ---- block ----

    /// Current block number.
    #[link_name = "block.number"]
    pub fn block_number() -> i64;

    /// Block timestamp in milliseconds.
    #[link_name = "block.timestamp"]
    pub fn block_timestamp() -> i64;

    /// Write 32-byte previous block hash to `out_ptr`.
    #[link_name = "block.prevhash"]
    pub fn block_prevhash(out_ptr: i32);

    // ---- msg ----

    /// Write 32-byte caller address to `out_ptr`.
    #[link_name = "msg.sender"]
    pub fn msg_sender(out_ptr: i32);

    /// Write native LOOM attached to this call as a 16-byte little-endian u128
    /// into the buffer at `out_ptr`.
    #[link_name = "msg.value"]
    pub fn msg_value(out_ptr: i32);

    /// Return the calldata length in bytes.
    #[link_name = "msg.calldata.len"]
    pub fn msg_calldata_len() -> i32;

    /// Copy `len` bytes of calldata starting at `offset` into `dst_ptr`.
    /// Returns the number of bytes actually copied.
    #[link_name = "msg.calldata.read"]
    pub fn msg_calldata_read(dst_ptr: i32, offset: i32, len: i32) -> i32;

    // ---- log ----

    /// Emit a log entry. `topic_ptr` points to `topic_count * 32` bytes of
    /// topic data (each topic is 32 bytes). Returns 0 on success.
    #[link_name = "log.emit"]
    pub fn log_emit(topic_ptr: i32, topic_count: i32, data_ptr: i32, data_len: i32) -> i32;

    // ---- crypto ----

    /// Compute BLAKE3(input) and write 32 bytes to `out_ptr`.
    /// Returns 32 on success, negative on error.
    #[link_name = "crypto.blake3"]
    pub fn crypto_blake3(in_ptr: i32, in_len: i32, out_ptr: i32) -> i32;

    // ---- host.deploy ----

    /// Petal-initiated deploy. `hash_ptr[0..hash_len]` is the 32-byte petal
    /// BLAKE3 hash already in the code_root. `salt_ptr[0..salt_len]` is 32
    /// bytes. `init_ptr[0..init_len]` is passed to the deployed petal's `init`.
    /// On success, writes 32-byte instance address to `out_addr_ptr` and
    /// returns 0. On error, returns a negative error code.
    #[link_name = "host.deploy"]
    pub fn host_deploy(
        hash_ptr: i32,
        hash_len: i32,
        salt_ptr: i32,
        salt_len: i32,
        init_ptr: i32,
        init_len: i32,
        out_addr_ptr: i32,
    ) -> i64;
}

// ---------------------------------------------------------------------------
// Non-wasm32 stubs — panic at runtime; allow host-side cargo check to succeed
// ---------------------------------------------------------------------------

#[cfg(not(target_arch = "wasm32"))]
#[allow(unused_variables)]
pub mod stubs {
    #[inline(never)]
    pub unsafe fn state_read(key_ptr: i32, key_len: i32, out_ptr: i32) -> i64 {
        panic!("state_read: not available outside wasm32")
    }
    #[inline(never)]
    pub unsafe fn state_write(key_ptr: i32, key_len: i32, val_ptr: i32, val_len: i32) -> i32 {
        panic!("state_write: not available outside wasm32")
    }
    #[inline(never)]
    pub unsafe fn state_delete(key_ptr: i32, key_len: i32) -> i32 {
        panic!("state_delete: not available outside wasm32")
    }
    #[inline(never)]
    pub unsafe fn petal_call(
        target_ptr: i32, target_len: i32, cd_ptr: i32, cd_len: i32,
        value_lo: i64, value_hi: i64, retdata_ptr: i32, retdata_max: i32,
    ) -> i64 {
        panic!("petal_call: not available outside wasm32")
    }
    #[inline(never)]
    pub unsafe fn petal_return(data_ptr: i32, data_len: i32) -> ! {
        panic!("petal_return: not available outside wasm32")
    }
    #[inline(never)]
    pub unsafe fn petal_revert(msg_ptr: i32, msg_len: i32) -> ! {
        panic!("petal_revert: not available outside wasm32")
    }
    #[inline(never)]
    pub unsafe fn block_number() -> i64 {
        panic!("block_number: not available outside wasm32")
    }
    #[inline(never)]
    pub unsafe fn block_timestamp() -> i64 {
        panic!("block_timestamp: not available outside wasm32")
    }
    #[inline(never)]
    pub unsafe fn block_prevhash(out_ptr: i32) {
        panic!("block_prevhash: not available outside wasm32")
    }
    #[inline(never)]
    pub unsafe fn msg_sender(out_ptr: i32) {
        panic!("msg_sender: not available outside wasm32")
    }
    #[inline(never)]
    pub unsafe fn msg_value(out_ptr: i32) {
        let _ = out_ptr;
        panic!("msg_value: not available outside wasm32")
    }
    #[inline(never)]
    pub unsafe fn msg_calldata_len() -> i32 {
        panic!("msg_calldata_len: not available outside wasm32")
    }
    #[inline(never)]
    pub unsafe fn msg_calldata_read(dst_ptr: i32, offset: i32, len: i32) -> i32 {
        panic!("msg_calldata_read: not available outside wasm32")
    }
    #[inline(never)]
    pub unsafe fn log_emit(topic_ptr: i32, topic_count: i32, data_ptr: i32, data_len: i32) -> i32 {
        panic!("log_emit: not available outside wasm32")
    }
    #[inline(never)]
    pub unsafe fn crypto_blake3(in_ptr: i32, in_len: i32, out_ptr: i32) -> i32 {
        panic!("crypto_blake3: not available outside wasm32")
    }
    #[inline(never)]
    pub unsafe fn host_deploy(
        hash_ptr: i32, hash_len: i32, salt_ptr: i32, salt_len: i32,
        init_ptr: i32, init_len: i32, out_addr_ptr: i32,
    ) -> i64 {
        panic!("host_deploy: not available outside wasm32")
    }
}

// Re-export stubs at the top level on non-wasm32 so sibling modules can use
// the same call sites regardless of target.
#[cfg(not(target_arch = "wasm32"))]
pub use stubs::*;
