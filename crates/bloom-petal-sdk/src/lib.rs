//! bloom-petal-sdk — guest SDK for wasm32 petals running on bloom-chain.
//!
//! Provides safe wrappers around the chain-mode host imports defined in
//! bloom-chain spec §7.6. Compiles on wasm32-unknown-unknown with `no_std`
//! and dlmalloc as the global allocator. On non-wasm32 targets the host
//! imports are replaced by stubs that panic at runtime (for host-build
//! compile checks only — do not call them outside wasm32).

#![cfg_attr(target_arch = "wasm32", no_std)]

extern crate alloc;

pub mod block;
pub mod code;
pub mod crypto;
pub mod host;
pub mod imports;
pub mod log;
pub mod msg;
pub mod petal;
pub mod state;
pub mod value;

pub use value::{LoomValue, LoomValueError};

// ---------------------------------------------------------------------------
// wasm32-only runtime support
// ---------------------------------------------------------------------------

/// Global allocator (wasm32 only).
#[cfg(target_arch = "wasm32")]
#[global_allocator]
static A: dlmalloc::GlobalDlmalloc = dlmalloc::GlobalDlmalloc;

/// Panic handler (wasm32 only) — calls `petal.revert` with reason "panic".
#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic_handler(_info: &core::panic::PanicInfo) -> ! {
    petal::revert("panic")
}

// ---------------------------------------------------------------------------
// petal! macro — synthesises the wasm entry-point shim
// ---------------------------------------------------------------------------

/// Generates the `#[unsafe(no_mangle)]` wasm entry points `init` and `call`
/// (edition 2024 syntax — bare `#[no_mangle]` is rejected as unsafe).
///
/// Usage:
/// ```ignore
/// bloom_petal_sdk::petal! {
///     init => my_init,
///     call => my_call,
/// }
/// fn my_init(calldata: alloc::vec::Vec<u8>) { ... }
/// fn my_call(calldata: alloc::vec::Vec<u8>) -> i32 { ... }
/// ```
///
/// Both entry points read calldata via `msg::calldata()` internally, so
/// the `calldata_ptr` / `calldata_len` arguments from the chain runtime
/// are accepted but not used directly (the SDK reads via the host import
/// instead, matching the chain spec §7.8 contract).
#[macro_export]
macro_rules! petal {
    (init => $init_fn:expr, call => $call_fn:expr $(,)?) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn init(calldata_ptr: i32, calldata_len: i32) -> i32 {
            let _ = (calldata_ptr, calldata_len);
            let cd = $crate::msg::calldata();
            ($init_fn)(cd);
            0
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn call(calldata_ptr: i32, calldata_len: i32) -> i32 {
            let _ = (calldata_ptr, calldata_len);
            let cd = $crate::msg::calldata();
            ($call_fn)(cd)
        }
    };
}
