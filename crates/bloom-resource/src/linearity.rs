//! Client-side linearity tracker (spec §4.4).
//!
//! The chain is authoritative — at tx-end it enforces the
//! transient/persistent invariants (every transient row must have been
//! consumed/transferred/shared/frozen/deleted; otherwise
//! `LinearityViolation`). This module gives petals a **best-effort
//! guardrail** that catches the same bug earlier: at the close of a
//! `PetalScope`, in debug builds, any handles that were `record_create`d
//! but not `record_consume`d cause a panic so the violation surfaces in
//! tests instead of waiting for the chain's revert.
//!
//! Release-mode behavior: `ScopeGuard` drop is a no-op. The chain's
//! tx-end check is the source of truth.
//!
//! Macro emission contract:
//! - Macro-emitted `__petal_<fn>` wrappers call [`PetalScope::enter`]
//!   at the top of the function body and let the returned guard drop
//!   at scope exit.
//! - Calls into `host::object_create` record via
//!   [`PetalScope::record_create`].
//! - Calls that consume a handle (`object.transfer`, `share`, `freeze`,
//!   `delete`, returning a value to a `Use(...)`) record via
//!   [`PetalScope::record_consume`].
//! - `object.borrow(_, Consume)` rows record via
//!   [`PetalScope::record_borrow`] (informational only — these are
//!   tracked but not asserted; the chain owns Consume-row checks).

use std::cell::RefCell;
use std::collections::BTreeMap;

use crate::handle::RuntimeHandle;

thread_local! {
    /// Per-thread scope stack. Most petals only use one scope at a
    /// time; the stack supports nested instrumentation in invariants.
    static SCOPE_STACK: RefCell<Vec<ScopeState>> = const { RefCell::new(Vec::new()) };
}

#[derive(Debug, Default, Clone)]
struct ScopeState {
    /// Handles produced by `object.create` within this scope, with a
    /// reference count so a `Coin::clone`-style copy doesn't trip the
    /// linearity guardrail.
    created: BTreeMap<RuntimeHandle, u32>,
    /// Handles consumed by `object.transfer`/`share`/`freeze`/`delete`
    /// (or by being passed to a downstream fn). Used to discount
    /// `created` at scope-end.
    consumed: BTreeMap<RuntimeHandle, u32>,
    /// Handles borrowed at `Consume` mode — informational only.
    borrowed_consume: Vec<RuntimeHandle>,
}

/// Per-call scope state. Construct via [`PetalScope::enter`]; the
/// returned [`ScopeGuard`] runs the at-scope-exit check.
#[derive(Debug)]
pub struct PetalScope;

impl PetalScope {
    /// Push a fresh scope onto the per-thread stack. The returned
    /// guard pops (and audits, in debug builds) on drop.
    #[must_use = "drop the guard at scope exit to run the linearity check"]
    pub fn enter() -> ScopeGuard {
        SCOPE_STACK.with(|s| s.borrow_mut().push(ScopeState::default()));
        ScopeGuard { _private: () }
    }

    /// Record that this scope created a new transient row.
    pub fn record_create(h: RuntimeHandle) {
        Self::with_top(|state| {
            *state.created.entry(h).or_insert(0) += 1;
        });
    }

    /// Record that a previously-created row was consumed
    /// (transferred / shared / frozen / deleted / passed downstream).
    pub fn record_consume(h: RuntimeHandle) {
        Self::with_top(|state| {
            *state.consumed.entry(h).or_insert(0) += 1;
        });
    }

    /// Record that this scope took a `Consume`-mode borrow on `h`.
    /// Tracked for diagnostics only; the chain enforces consume-row
    /// semantics at tx-end.
    pub fn record_borrow(h: RuntimeHandle) {
        Self::with_top(|state| {
            state.borrowed_consume.push(h);
        });
    }

    /// Snapshot of handles that were created but not (yet) consumed.
    ///
    /// Returns an empty `Vec` if there is no active scope.
    pub fn outstanding() -> Vec<RuntimeHandle> {
        SCOPE_STACK.with(|s| {
            let stack = s.borrow();
            let Some(state) = stack.last() else {
                return Vec::new();
            };
            let mut out = Vec::new();
            for (h, created) in state.created.iter() {
                let consumed = state.consumed.get(h).copied().unwrap_or(0);
                if created.saturating_sub(consumed) > 0 {
                    out.push(*h);
                }
            }
            out
        })
    }

    /// Snapshot of handles borrowed at `Consume` mode in the active
    /// scope. Diagnostic-only.
    pub fn consume_borrows() -> Vec<RuntimeHandle> {
        SCOPE_STACK.with(|s| {
            let stack = s.borrow();
            stack
                .last()
                .map(|state| state.borrowed_consume.clone())
                .unwrap_or_default()
        })
    }

    /// Depth of the scope stack. `0` if no scope is active.
    pub fn depth() -> usize {
        SCOPE_STACK.with(|s| s.borrow().len())
    }

    fn with_top<F: FnOnce(&mut ScopeState)>(f: F) {
        SCOPE_STACK.with(|s| {
            let mut stack = s.borrow_mut();
            if let Some(top) = stack.last_mut() {
                f(top);
            }
        });
    }

    /// Pop the current scope off the stack without auditing. Exposed
    /// for the `ScopeGuard` `Drop`; petals should not call directly.
    fn pop_unchecked() -> Option<ScopeState> {
        SCOPE_STACK.with(|s| s.borrow_mut().pop())
    }
}

/// RAII guard returned by [`PetalScope::enter`]. Auditing on drop is
/// gated on `debug_assertions`: in release builds the chain's tx-end
/// linearity check is authoritative and a panicking guardrail would
/// just turn a runtime revert into an abort.
pub struct ScopeGuard {
    _private: (),
}

impl Drop for ScopeGuard {
    fn drop(&mut self) {
        let state = match PetalScope::pop_unchecked() {
            Some(s) => s,
            None => return,
        };

        // Compute net-outstanding handles (created minus consumed).
        let mut outstanding = Vec::new();
        for (h, created) in state.created.iter() {
            let consumed = state.consumed.get(h).copied().unwrap_or(0);
            if created.saturating_sub(consumed) > 0 {
                outstanding.push(*h);
            }
        }

        // Avoid panicking during another panic (would abort).
        if std::thread::panicking() {
            return;
        }

        if cfg!(debug_assertions) && !outstanding.is_empty() {
            panic!(
                "bloom-resource: linearity violation — scope ended with \
                 {} outstanding transient handle(s): {:?}",
                outstanding.len(),
                outstanding
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(i: i32) -> RuntimeHandle {
        RuntimeHandle::from_raw(i)
    }

    #[test]
    fn empty_scope_is_clean() {
        let g = PetalScope::enter();
        assert!(PetalScope::outstanding().is_empty());
        assert_eq!(PetalScope::depth(), 1);
        drop(g);
        assert_eq!(PetalScope::depth(), 0);
    }

    #[test]
    fn balanced_create_consume_clean() {
        let g = PetalScope::enter();
        PetalScope::record_create(h(1));
        PetalScope::record_consume(h(1));
        assert!(PetalScope::outstanding().is_empty());
        drop(g);
    }

    #[test]
    fn outstanding_lists_unconsumed() {
        let g = PetalScope::enter();
        PetalScope::record_create(h(1));
        PetalScope::record_create(h(2));
        PetalScope::record_consume(h(1));
        let out = PetalScope::outstanding();
        assert_eq!(out, vec![h(2)]);
        // Consume the rest before drop so the audit doesn't fire.
        PetalScope::record_consume(h(2));
        drop(g);
    }

    #[test]
    fn nested_scopes_isolate() {
        let outer = PetalScope::enter();
        PetalScope::record_create(h(10));
        {
            let inner = PetalScope::enter();
            // Inner has its own state.
            assert!(PetalScope::outstanding().is_empty());
            PetalScope::record_create(h(11));
            PetalScope::record_consume(h(11));
            drop(inner);
        }
        // Back in outer: original create is still outstanding.
        let out = PetalScope::outstanding();
        assert_eq!(out, vec![h(10)]);
        PetalScope::record_consume(h(10));
        drop(outer);
    }

    #[test]
    fn record_borrow_is_diagnostic_only() {
        let g = PetalScope::enter();
        PetalScope::record_borrow(h(5));
        PetalScope::record_borrow(h(6));
        let borrows = PetalScope::consume_borrows();
        assert_eq!(borrows, vec![h(5), h(6)]);
        // Borrows do not count against outstanding.
        assert!(PetalScope::outstanding().is_empty());
        drop(g);
    }

    #[test]
    fn outside_scope_is_safe() {
        // No active scope; recording is a no-op and outstanding is empty.
        PetalScope::record_create(h(1));
        PetalScope::record_consume(h(1));
        PetalScope::record_borrow(h(2));
        assert!(PetalScope::outstanding().is_empty());
        assert!(PetalScope::consume_borrows().is_empty());
        assert_eq!(PetalScope::depth(), 0);
    }

    #[test]
    fn multiple_creates_then_consumes_balance() {
        let g = PetalScope::enter();
        PetalScope::record_create(h(7));
        PetalScope::record_create(h(7));
        PetalScope::record_consume(h(7));
        // One still outstanding.
        assert_eq!(PetalScope::outstanding(), vec![h(7)]);
        PetalScope::record_consume(h(7));
        assert!(PetalScope::outstanding().is_empty());
        drop(g);
    }

    /// In debug builds, a leaked transient handle panics on guard drop.
    #[test]
    #[cfg_attr(not(debug_assertions), ignore)]
    #[should_panic(expected = "linearity violation")]
    fn debug_drop_panics_on_leaked_handle() {
        let g = PetalScope::enter();
        PetalScope::record_create(h(42));
        drop(g);
    }
}
