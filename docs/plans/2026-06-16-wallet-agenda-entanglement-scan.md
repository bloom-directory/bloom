# Wallet Agenda + Entanglement Scan

**Status:** Design. Phase 0 scoped; not yet built. Updated after removal of
top-level `bloom onboard`: the agenda is now VFS-first, with CLI rendering only
as a convenience.
**Date:** 2026-06-16.

## 1. Motivation

bloom is an agent-guided wallet: the user opens their agent, the agent drives
bloom. For that loop to be useful the agent needs **situational awareness** at
session start — *what do I hold, what am I entangled with, what's at risk, what's
time-sensitive, what did I recently do* — not just a balance readout.

Today the only "what needs attention" surface is `bloom polymarket obligations`
(Polymarket-only, CLI-only). There is no cross-protocol view, and no
lending/staking/LP awareness anywhere in the VFS (audited: only Polymarket's
`redeemable` flag exists).

The agenda must not become a new setup dashboard. It is an agent-readable VFS
summary of live wallet context, with an optional CLI renderer for humans.

## 2. Approaches considered

- **Per-protocol adapters** (a hand-written Aave reader, Lido reader, …):
  endless and brittle; does not scale to the long tail of protocols. Rejected as
  the primary mechanism.
- **Persistent trace store with time-series snapshots + a learned-interpretation
  cache:** rejected after red-teaming. It is a cache of derived state over a
  source of truth (the chain), and is sync-fragile in ways that are dangerous for
  a wallet:
  - a stored risk number (e.g. health factor) is stale the instant it is
    written; acting on it is the catastrophic case;
  - `abi_hash`-keyed interpretation breaks on proxy upgrades (proxy ABI stable,
    implementation changed underneath);
  - a wrong persisted interpretation looks authoritative and compounds silently;
  - incremental discovery cursors break on reorgs / indexer lag;
  - multi-writer (daemon + one-shot CLI) coherence, and a third local ledger
    (after the audit log and Polymarket receipts) that can disagree with both.
  The most elaborate parts of that design were also the most fragile — a smell.

- **Chosen — live-first, nearly stateless.** bloom is the always-live
  grounding/verification layer; the **agent** is the memory/interpretation layer,
  and its guesses are always re-verified against bloom's live reads. This deletes
  the "agenda said safe, chain said liquidated" bug class, is far less code, and
  ships on primitives bloom already has.

## 3. Design principles

1. **Live-first where it matters.** The agenda is computed on demand per read.
   Risk-bearing facts such as balances, pending outbox state, and current
   Polymarket position state are read live. Historical provenance may come from
   bounded/cached indexer feeds, but the output must label that coverage
   honestly.
2. **bloom grounds, the agent interprets.** bloom surfaces decoded history,
   entangled contracts (with ABI when verified), and live view-reads. Semantic
   risk ("this is an Aave loan, HF 1.05, near liquidation") is the agent's job.
   bloom computes **no** per-protocol risk in Phase 0.
3. **Honest coverage is non-negotiable.** Every agenda declares what it scanned
   and what it cannot see. A false "nothing urgent" is the one outcome worse than
   silence.
4. **Persist nothing in Phase 0.** No trace store, no snapshots, no learned
   interpretations. Interpretation/labels live in the agent's own cross-session
   memory, re-verified against live reads each session.
5. **Degrade, never hang or lie.** Each network-touching section is time-boxed
   and degrades to an explicit `unavailable` note surfaced in `coverage`, never
   silently dropped.

## 4. Architecture

One read triggers three on-demand steps:

### 4.1 Entanglement scan
For `(wallet_address, chain)`, pull bounded recent account history and reduce it
to the distinct set of counterparties the wallet has recently interacted with:
- contracts the wallet has called (`txlist`, `txlistinternal`);
- tokens held / transferred (`tokentx`, `tokennfttx`).

Reduction rules:
- normalize addresses to lowercase; dedup; drop the wallet's own address.
- classify each as `token` (appears in token-transfer feeds) / `contract`
  (called, has code / verified ABI) / `eoa` (called, no code).
- carry `first_seen_block`, `last_seen_block`, `interaction_count`, and a few
  representative `tx_refs` as provenance.
- bound the scan (configurable lookback window / max records) so it stays cheap
  and RPC-resilient; record the bound in `coverage`.

This is a **recently observed entanglement scan**, not proof of all open
positions. Long-lived lending/staking/LP exposure can be missed if the opening
transaction is outside the scan window. The agenda must say that plainly.

Reuse the chains handler's existing `AddressHistorySource` (Etherscan-backed,
cached) rather than calling Etherscan directly — consistent caching + one code
path.

### 4.2 Grounding
For each entanglement: set `abi_available` from `contracts/<addr>/abi`. Optionally
perform **cheap, generic** live view-reads where the read is standard and safe
(e.g. ERC-20 `balanceOf(wallet)`) via `contracts/<addr>/methods/<name>.read`.
Protocol-specific view-reads (e.g. `getUserAccountData`) are **not** auto-called
in Phase 0 — the agent requests them once it has interpreted the contract.

### 4.3 Aggregation
Combine:
- **"What I did"** — tail of the hash-chained audit log + Polymarket receipts.
- **"What I hold"** — live native balance facts from the canonical native
  balance VFS paths (`balance.json`; legacy balance paths only as a temporary
  fallback).
- **"What I recently touched"** — the observed entanglement set + grounding.
- **The one interpreted protocol** — Polymarket obligations (reuse existing
  data once refactored out of the current CLI renderer: open positions,
  `redeemable`, next exit action).
Rank by severity, attach provenance + next-action, emit the coverage block.

## 5. Surface

- **VFS (primary, machine-readable):** `wallets/<w>/agenda.json`.
- **CLI (human + agent convenience):** `bloom wallet agenda <name>`, mirroring
  the VFS JSON without becoming a separate source of truth.

No top-level `onboard` integration. First-run wallet setup remains explicit
wallet/VFS workflow; agenda is session awareness after a wallet exists.

## 6. Data model (`agenda.json`)

```json
{
  "wallet": "main",
  "address": "0x..",
  "generated_at_ms": 0,
  "chains_scanned": ["polygon"],
  "balances": [
    { "chain": "polygon", "asset": "native", "symbol": "POL",
      "decimals": 18, "raw": "95084027568306020633",
      "formatted": "95.084027568306020633",
      "display": "95.084027568306020633 POL",
      "source": "wallets/main/chains/polygon/balance.json" }
  ],
  "did": [
    { "ts_ms": 0, "kind": "tx.broadcast", "summary": "…", "ref": "audit:…" }
  ],
  "entanglements": [
    { "address": "0x..", "chain": "polygon", "kind": "contract",
      "symbol": null, "first_seen_block": 0, "last_seen_block": 0,
      "interaction_count": 3, "tx_refs": ["0x.."],
      "abi_available": true, "interpreted": false }
  ],
  "items": [
    { "id": "outbox:…", "severity": "high", "kind": "pending_tx",
      "summary": "1 staged tx awaiting confirm",
      "condition": null, "evidence": ["outbox:…"],
      "next_action": {
        "kind": "confirm_staged_tx",
        "surface": "vfs",
        "review_path": "wallets/main/chains/polygon/outbox/pending/<id>/plan.md",
        "write_path": "wallets/main/chains/polygon/outbox/pending/<id>/confirm",
        "requires_unlock": true
      },
      "coverage_note": null }
  ],
  "coverage": {
    "sources": ["audit", "etherscan-history", "polymarket"],
    "chains_scanned": ["polygon"],
    "scan_window": "last 5000 blocks / 100 records",
    "uninterpreted": ["0x.. (no adapter; agent should interpret)"],
    "unavailable": ["etherscan-history@arbitrum: timed out"],
    "not_covered": [
      "lending/staking/LP risk interpretation = agent's job",
      "unverified contracts (no ABI)",
      "positions opened by third parties may be missed",
      "old positions may be missed when the opening interaction is outside the scan window"
    ]
  }
}
```

Severity model (Phase 0, no interpretation required):
- `high` — pending/staged outbox tx awaiting confirm; a Polymarket position the
  existing logic flags as redeemable/needs-exit.
- `medium` — open Polymarket positions with no immediate action.
- `info` — one item per **uninterpreted observed entanglement**, inviting the
  agent to study it (`"summary": "you recently interacted with 0x… on polygon; I
  have not interpreted it"`).

bloom never fabricates a risk item (e.g. "near liquidation") in Phase 0 — that
requires interpretation it does not have. Such items appear only after the agent
interprets and acts.

## 7. Reuse map (do not rebuild)

| Need | Existing primitive |
|---|---|
| account history | `bloom-etherscan` `txlist`/`txlistinternal`/`tokentx`/`tokennfttx` + on-disk TTL cache; chains handler `AddressHistorySource` |
| ABI availability / decode | chains handler `contracts/<addr>/abi`, `AbiCache` |
| live view-reads | chains handler `contracts/<addr>/methods/<name>.read` |
| live native balances | `wallets/<w>/chains/<c>/balance.json`; current balance paths as fallback |
| "what I did" | `bloom-proto::AuditLog::tail` + Polymarket receipts |
| interpreted protocol slice | refactored data-returning Polymarket obligations helper + `OnboardStore` |
| human rendering | `bloom wallet agenda <name>` CLI renderer over `agenda.json` |

## 8. Non-goals / deferred (named, not buried)

- Persistent trace store, time-series snapshots, learned-interpretation cache.
- Per-protocol risk math (health factors, APRs, LP valuations).
- An incremental **entanglement index** with a saved block cursor — a *future*
  optimization that must **fail safe** (stale list → re-read live). Earns its
  place only when scan cost proves it.
- MCP transport for the agenda (separate, larger piece; the path to robust
  agent consumption, but out of scope here).
- Global portfolio rollup (`wallets/<w>/balances.json`) beyond the native
  balance facts needed for agenda context.

## 9. Phase-0 implementation outline (separate go-ahead)

1. Refactor Polymarket obligations into a data-returning helper. The current
   CLI function prints human text; agenda must consume structured position and
   next-action facts, not parse stdout.
2. `crates/bloom-vfs/src/handlers/agenda.rs` — entanglement scan + aggregation,
   sibling to the existing `chains_history` module; pure async functions taking
   the history source + audit log + native balance reader + polymarket data;
   time-boxed per section.
3. Wire `wallets/<w>/agenda.json` into `crates/bloom-vfs/src/handlers/wallets.rs`
   (read-only; likely `is_read_side_effecting = true` since the scan hits
   Etherscan).
4. `bloom wallet agenda <name>` subcommand in `crates/bloom/src/main.rs`,
   rendering the VFS JSON for humans.

## 10. Verification (when built)

- `cargo test -p bloom-vfs` + `cargo test -p bloom`.
- Unit (offline, deterministic via `bloom-test-util::mocks` mock
  `AddressHistorySource`):
  - empty wallet → honest coverage, zero fabricated items, exit 0;
  - mock history of N contracts → N deduped entanglements, each with
    `abi_available` set; an uninterpreted entanglement yields exactly one `info`
    item, never a risk item.
  - bounded history output says "recently observed" and includes scan window /
    missed-old-position caveat in coverage.
  - native Polygon balance facts use the chain's native symbol, not ETH.
  - `next_action` is structured VFS/action metadata, not a CLI command string.
- CLI smoke (assert_cmd, hermetic `BLOOM_HOME`, pattern from
  `crates/bloom/tests/cli.rs`): `bloom wallet agenda main` prints the coverage
  block and invents no risk.
- Manual: `bloom wallet agenda <w>` against a funded testnet wallet → real
  entanglements + honest coverage.

## 11. Future phases

- **P1 — entanglement index + cursor** (fail-safe optimization) if scan cost
  hurts.
- **P2 — global portfolio rollup:** add `wallets/<w>/balances.json` only after
  native balance JSON is stable and there is a clear need for multi-chain
  portfolio sizing.
- **P3 — agent-memory interpretation loop:** the agent labels a contract once
  (in its own memory), bloom re-verifies the label against live reads each
  session; bloom never stores the label as authoritative.
- **P4 — MCP transport** so agents consume the agenda as a typed resource/tool
  rather than scraping the CLI.
