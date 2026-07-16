# Native Bloom Functionality as Petals: Feasibility Review

**Date:** 10 July 2026  
**Status:** Code-backed architecture assessment  
**Scope:** Native Bloom VFS surfaces and supporting crates compared with the current local Petals v1 ABI.

## Executive conclusion

Not all native Bloom functionality can be replaced by Petals with the current ABI.

A large amount of venue-specific business logic can already move into Petals:

- REST API integrations
- parsing and formatting
- route construction
- market and account views
- local workflow state
- EIP-712 and protocol-specific hashing
- generic hash-signing requests
- ordinary EVM transaction staging
- receipt inspection
- static VFS route trees

Several native implementations also contain parts of Bloom's security and runtime kernel:

- wallet and passkey custody
- semantic Sealed Approval subjects
- policy and budget enforcement
- encrypted delegated keys
- durable background monitors
- WebSocket subscriptions
- system-wide status and service registration
- multi-transaction dependency handling
- arbitrary-user-destination network authorization
- simulation and debug RPC
- shared stable state across package upgrades

Those cannot be reproduced inside an untrusted route component with equivalent guarantees today.

A Petal can technically wrap most existing native surfaces through `bloom:vfs/readwrite`, but that is delegation to native code, not replacement. This assessment excludes that escape hatch.

## Current Petal host surface

| Interface | Current functionality |
| --- | --- |
| HTTP | Buffered HTTPS request/response with static host, method, and path allowlists |
| Store | Per-package-hash private/secret KV |
| Signing | Sign one 32-byte hash for a declared intent, with structured approval-required result |
| Transactions | Stage, confirm, and inspect one ordinary EVM transaction |
| Chain | `eth_chainId`, latest `eth_getBalance`, and latest `eth_call` |
| VFS | Broad lookup/list/read/write of native VFS, except `/petals` |
| Environment | Time and bounded random bytes |

## Summary matrix

| Native functionality | Petal today? | Equivalent native guarantees? |
| --- | --- | --- |
| Polymarket | Mostly | Not completely |
| Hyperliquid public reads | Yes | Largely |
| Hyperliquid direct actions | Partly | No |
| Hyperliquid agent sessions | No | No |
| Free/static-host HTTP | Yes | Mostly |
| General paid HTTP/x402 | Partly | No |
| Tempo MPP charge | Partly | No |
| Durable MPP sessions | No | No; native support is also incomplete |
| Enso/DeFi intent compilation | Mostly | Not fully |
| Ordinary EVM transaction execution | Yes | Yes, through the host outbox |
| Multi-transaction workflows | Partly | No |
| ENS | Yes | Largely |
| Price views | Yes | As an app, not as a system oracle |
| Pure tools/docs | Yes | Yes |
| Chain explorer views | Partly | No |
| Simulation/tracing | Partly | No |
| Watches/subscriptions | No | No |
| Mempool monitoring | No | No |
| Wallet management/passkeys | No | Should remain native |
| Address book | Partly | Not as a system service |
| Central outbox | Partly | Only the Petal's own transactions |
| Daemon status | Partly | Only by delegating to native VFS |
| IPC/NFS mount/ceremony server | No | Host infrastructure |

## Polymarket

Polymarket is the closest native venue to being fully Petalized. The current ABI was clearly shaped to make this possible.

### Implementable now

A Polymarket Petal can implement:

- Gamma, Data, and CLOB REST reads
- market search, books, positions, activity, account views, and order status
- quote and order construction
- EIP-712 and POLY_1271 digest calculation
- host-mediated owner signatures
- CLOB credential minting and authenticated requests
- order posting and cancellation
- drafts, locks, credentials, and receipts using private KV
- Polygon balance and allowance probes using `eth_call`
- ordinary funding transactions through `tx.outbox`
- relayer calls over HTTP
- receipt inspection and workflow reconciliation

The separation of POLY_1271 wrapping from key-backed signing is particularly useful: the Petal calculates the digest, Bloom signs it, and the Petal performs deterministic wrapping.

### Missing equivalent guarantees

The native implementation embeds Polymarket-specific authority semantics:

- onboarding creates one Hardened Sealed Action covering up to three signatures
- order approvals bind an order subject, chain, maker, side, market, signing hash, and policy snapshot
- policy checks include market rules, daily spend, order limits, holdings, stale-draft checks, and receipt audits
- redeem, withdraw, approval revocation, and onboarding use distinct action schemas and assurance levels
- builder and CLOB credentials have specific lifecycle and redaction rules
- jurisdiction checks are enforced as hard gates

Generic Petal signing binds package, route, path, wallet, intent, and hash. It does not host-validate that the hash represents the claimed Polymarket order, amount, or market.

Native onboarding supports a multi-signature grant. Generic local-app signing creates one-signature actions. A Petal could request the signatures separately, but that changes UX and authority semantics.

Onboarding also uses contract-code probes. `eth_getCode` is not in the current chain ABI.

### Verdict

Polymarket can be implemented functionally as a Petal today. It cannot yet reproduce all first-party policy, semantic approval, and multi-signature behavior without additional host support.

## Hyperliquid

### Public reads

The market and account read surface primarily consists of `POST /info` requests for:

- mids
- perp and spot metadata
- books
- candles
- recent trades
- funding history
- clearinghouse state
- open orders
- fills
- portfolio and rate-limit views

These fit the current HTTP interface when the Hyperliquid hosts are statically allowlisted.

### Direct signed actions

A Petal can calculate Hyperliquid action hashes and request generic signatures for `approveAgent`, `usdSend`, and similar owner actions. It can sign ordinary exchange actions itself if it owns an approved agent key.

It cannot reproduce the native semantic approval structure. Native code freezes policy and binds protocol facts for `approveAgent` and `usdSend`; it does not ask the owner to approve only an opaque hash.

### Agent sessions

Native agent sessions require:

- generation of an ephemeral agent key
- sealed persistence of that key
- a frozen Hyperliquid policy
- asset, notional, leverage, position, loss, and duration enforcement
- a ten-second background monitor
- repeated risk snapshots
- automatic cancellation and reduce-only close on expiry or breach
- session audit logs
- restart/orphan detection and recovery

A route component only runs in response to a VFS operation. `write_async` is a best-effort task, not a durable scheduler.

A Petal could generate a key with `random-bytes` and put it in a secret namespace, but this is not equivalent to native sealed-key handling. The key remains visible to guest code, at-rest protection is largely filesystem mode, and package updates change the storage partition.

### Verdict

Hyperliquid reads and request construction are good Petal workloads. Secure delegated sessions, monitoring, and recovery require durable jobs and non-exportable key handles.

## Paid HTTP, x402, and MPP

The native request handler:

1. Accepts a user-provided arbitrary URL.
2. Sends an unpaid probe.
3. Normalizes a 402 challenge.
4. Selects a supported payment requirement.
5. Reads wallet payment policy.
6. Calculates spend over the previous 24 hours.
7. Evaluates request, daily, host, asset, and session limits.
8. Seals the exact request and challenge.
9. Mints a signature-bound credential.
10. Retries with sensitive-header controls.
11. Redacts credential material.
12. Persists a receipt and session projection.

### Fixed-host requests

A protocol-specific Petal for a known merchant can issue the request, parse a 402 response, calculate an x402 or MPP signing digest, request a host signature, and retry.

### General `/requests` replacement

The current network policy is static and exact-host. A general paid HTTP client accepts arbitrary user URLs that cannot be known in the package manifest. A safe replacement therefore requires a per-request egress authorization rather than a wildcard manifest rule.

### x402 signing

Generic `sign-hash` is cryptographically sufficient for x402 EIP-712 credentials. It is not semantically equivalent to the native paid-HTTP approval, which binds and policy-checks payee, asset, amount, network, merchant host, request body, and accumulated spend.

### MPP

A one-off Tempo MPP charge is computationally possible if the Petal can reach the required RPC and tolerate one approval per signature. Durable sessions require channel state, recovery, top-up/close lifecycle, multiple signatures, and scheduled maintenance.

The native implementation itself currently describes durable MPP reuse, top-up, and close as incomplete.

### Verdict

Fixed-merchant x402/MPP Petals are possible. A safe general-purpose paid HTTP client requires dynamic egress grants and host-enforced payment policy.

## DeFi and Enso

The native handler performs:

- natural-language or JSON intent parsing
- wallet and token resolution
- Enso route fetching
- allowance inspection
- approval and route transaction synthesis
- simulation
- receiver classification
- wallet DeFi policy evaluation
- ordered transaction staging
- cross-chain settlement waiting

### Implementable now

A Petal can implement intent parsing, token tables, Enso requests, balance/allowance reads, route review, persistent sessions, simple `eth_call` simulation, individual EVM transaction staging, receipt inspection, and request-driven settlement checks.

### Missing parity

The transaction ABI cannot express:

- a transaction batch
- dependency edges
- ordered confirmation
- workflow-level identity
- semantic token metadata
- expected balance deltas
- cross-chain dependencies
- private-orderflow preference

Native policy also depends on wallet policy, address-book classification, Polymarket deposit state, Hyperliquid bridge configuration, and current system configuration. There is no narrow host interface for these values.

Enso API keys also lack declarative host secret binding. A Petal can store the key itself, but guest code then handles it directly.

### Verdict

A basic Enso Petal is possible. Full safety and workflow parity need transaction batches/dependencies, system-policy reads, receiver classification, and secret bindings.

## Chain explorer and contract tooling

Native chain functionality includes:

- blocks and heads
- transactions and receipts
- logs
- code and storage
- gas data
- ERC-20 and NFT metadata
- Etherscan history
- verified ABI/source
- ABI method encoding
- event decoding
- proxy detection
- ENS reverse lookup
- live event tails
- mempool integration
- revert decoding

The Petal chain interface permits only `eth_chainId`, latest `eth_getBalance`, and latest `eth_call`.

Contract-specific reads, ABI encoding, token calls, and some ENS/proxy calls can be implemented today. Code, storage, blocks, receipts, logs, historical state, gas estimation, fee history, debug tracing, subscriptions, pending transactions, and host-managed RPC credentials are missing.

## Simulation

Native simulation uses:

- `eth_estimateGas`
- `eth_call` with state overrides
- `debug_traceCall`
- address-book resolution
- several transaction intent shapes

A Petal can implement only a basic latest-state `eth_call` simulation today. Debug tracing and state overrides should be separate high-risk capabilities rather than additions to the ordinary chain-read capability.

## Watches and mempool monitoring

These cannot be replaced with request-driven Petals.

Native watchers own a persistent registry, supervisor tasks, WebSocket subscriptions, polling fallback, cursors, resume behavior, history rotation, shutdown handling, and restart recovery. Mempool support similarly owns long-running subscriptions and a bounded in-memory index.

The Petal runtime lacks startup hooks, durable alarms, repeating timers, event delivery, WebSockets, streaming, checkpoints, and restart lifecycle.

## Wallets, passkeys, and policy

Wallet creation, import, passkey ceremonies, policy signing, grant minting, and key custody should remain native.

The ABI deliberately exposes hash signing rather than private keys, arbitrary grant creation, or raw unlock primitives. A Petal can build a wallet-facing application but should not replace the keystore or approval verifier.

## Smaller surfaces

### ENS

ENS is mostly namehash computation plus contract view calls. Forward, reverse, text, and content-hash resolution can be implemented in a Petal, with private KV caching.

### Prices

A Petal can fetch and expose prices. It cannot register itself as the price oracle consumed by `TxEngine` policy.

### Tools and docs

Pure transformations, hashes, amount parsing, formatting, and static documentation are ideal Petal workloads.

### Address book

A Petal can maintain an app-local address book. It cannot become the resolver used by `TxEngine` and native receiver classification.

### Central outbox

The transaction WIT deliberately limits a route to its own execution-origin-bound transactions. It does not expose global listing, cancellation, approval artifacts, other apps' entries, or non-EVM actions.

### Status

A Petal cannot directly inspect endpoint health, audit head, caches, backend configuration, mempool state, private-RPC health, or system-wide capabilities. Reading native `/status` would be a facade rather than replacement.

### IPC, mount, ceremony server, and daemon lifecycle

These are host infrastructure, not application functionality, and should remain native.

## Recommended architectural boundary

### Native Bloom kernel

Keep native:

- keystore and passkeys
- Sealed Approval and grants
- policy and budget enforcement
- transaction engine and broadcast
- audit log
- chain transport and endpoint credentials
- durable scheduler/subscription runtime
- credential/key vault
- IPC, VFS mount, and daemon lifecycle

### Petals

Move into Petals:

- venue and protocol adapters
- HTTP API schemas
- market/account presentation
- quote and order construction
- transaction calldata generation
- protocol-specific receipt parsing
- local workflow UI/state
- pure tools and documentation
- policy-neutral business logic

## Required platform extensions

In priority order:

1. Semantic action and multi-signature approval API.
2. Durable jobs, timers, and event delivery.
3. Non-exportable credential and delegated-key handles.
4. Stable app storage with explicit migrations.
5. Expanded typed chain and simulation APIs.
6. Transaction batches and dependency edges.
7. Per-request dynamic network authorization.
8. Narrow wallet, policy, address-book, chain-registry, and system-information APIs.
9. Controlled service-provider registration for system-level replacements.

The current ABI is a strong foundation for request-driven protocol adapters. The next step should add durable execution, semantic authorization, secure credential handles, richer typed host services, and stable upgradeable state—not simply more raw power.
