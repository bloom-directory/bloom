# Triad implementability review

> ## ⚠️ SUPERSEDED — historical record only
>
> **Marked 2026-07-29.** This document reviewed the **2026-07-23 draft** of
> `2026-07-23-triad-process-architecture.md`. That spec has since been
> consolidated (2026-07-29) and then corrected (2026-07-29). This review was
> **not** updated and must not be read as sign-off on the current spec.
>
> **Its verdict does not carry.** "Implementable now" was reached against a
> different document.
>
> **Every structural cross-reference in this document is dangling:**
>
> | This document says | Current spec |
> |---|---|
> | "the normative contract is in spec section 38" (and §38.2–§38.12) | The spec has sections 1–29. There is no section 38. |
> | daemon / signing / keystore | Machine / Broker / Signer. Spec §1 supersedes the old terminology. |
> | D-004 – D-039 | Spec §28 ratifies D-040 – D-064 and applies earlier decisions only where consistent. |
> | AC-01 – AC-15 | Spec §27 defines AC-01 – AC-35 with different content; §26 maps them to work packages. |
> | W0 – W8, with the dependency graph in §7 | Spec §26 defines W0 – W9 with different scopes (W3 is the Signer seam, not custody; W7 is Machine integration, not extraction) and its own dependency graph. |
>
> **One substantive reversal, called out because it inverts this review's
> security argument.** §6 (Q-SEC-05 / D-034) states that standing authority
> "continues to require a registered adapter that emits conservative value
> debits under D-016." **That requirement was removed.** Spec D-051 makes
> reusable approval available to any installed Petal with no registered schema
> and no Broker adapter, and spec §1.1 and D-062 state the consequence
> plainly: at the baseline `machine_asserted` assurance, declared-value limits
> are asserted by the Petal, are not verified against the payload, and do not
> contain a compromised Machine. Reading this review as current would leave you
> believing v1 standing budgets are adapter-backed spend caps. They are not.
>
> **What is still useful here:** §2 (phase-1 claim verification, K-01 – K-14),
> §3 (the E-10 signing-intent inventory), and §4.1 (VFS wallet-surface
> routing). Those are citations into the codebase as it stood on 2026-07-24 and
> remain the best available record of what exists today, subject to normal
> drift. The option analyses in §6 also remain useful as the reasoning behind
> decisions the current spec inherited (D-033 atomic batch, D-034 exact
> preimage, D-035 independent revocation, D-038 browser loopback, D-039 no
> public lock), even though their decision IDs have been renumbered or
> restated.
>
> Everything below this banner is unedited as of 2026-07-24.

Date: 2026-07-24  
Reviewed specification:
`docs/specs/2026-07-23-triad-process-architecture.md`
(the 2026-07-23 draft — **not** the current consolidated revision)

## 1. Executive result

The architecture is implementation-ready after a second, field-level review
found and resolved contradictions in revocation routing, signature result
delivery, ceremony-origin specification, and batch size arithmetic.
The first, second, and fourth are corrected in section 38 and recorded as
D-035/D-037 or direct contract fixes. D-038 selects the current
browser-loopback ceremony model with an explicit browser/extension TCB and
hardened origin contract. D-039 removes the mistakenly promoted public
`wallet.lock` RPC; no product question remains open.

D-034 corrected an earlier overreach: arbitrary calldata
cannot be universally mapped to trustworthy real-world meaning, and simulation
cannot prove future execution. Arbitrary one-shot transactions therefore use
live approval bound to exact final bytes/hashes. Registered semantic adapters
are optional trusted interpretation for one-shot requests and mandatory only
where standing budgets require conservative value extraction. D-033 selects
atomic, queryable batch publication. E-05 remains a production go/no-go, not a
waivable packaging checkbox.

## 2. Phase-1 claim verification

| Claim | Result | Evidence and correction |
|---|---|---|
| K-01 daemon is the composition root and holds all roles | Verified | `crates/bloom-daemon/src/lib.rs:1697` owns keystore, transaction engine, auth, signer cache, VFS, and Petal runtime; construction at `:1986` wires the in-memory grant store, signer cache, keystore Petal host, and registration coordinator. |
| K-02 ceremony PRF reaches daemon | Verified | `crates/bloom-daemon/src/ceremony_server.rs:304` includes PRF data in `CompleteBody`; `:431` decodes it and calls keystore decryption before caching the signer. |
| K-03 one-shot grants and decrypted signers are memory-only | Verified | `crates/bloom-auth/src/grant_store.rs:25` defines `InMemoryGrantStore`; `crates/bloom-keystore/src/petal_host.rs:41` defines an in-memory `SignerCache` holding `PrivateKeySigner`. |
| K-04 registration secret session is daemon memory | Verified | `crates/bloom-daemon/src/registration.rs:56` stores signer, PRF salt, WebAuthn state, and recovery receipt in secret session variants; `:220` creates the signer and salt. |
| K-05 policy ownership is currently collapsed | Verified | `crates/bloom-keystore/src/lib.rs:816` writes policy; `crates/bloom-vfs/src/handlers/wallets.rs:647` through `:827` parses, signs, and writes policy/update artifacts directly. |
| K-06 Petal signing ABI is hash-only | Verified | `../petal/wit/route/deps/sign-v0.1/sign.wit:15` through `:30` carries wallet, `hash32`, purpose/intent, and batch calls, but no preimage or semantic schema. |
| K-07 daemon builds Petal authorization context | Verified | `crates/bloom-daemon/src/lib.rs:968` through `:1074` handles the guest signing request and constructs attestation/action context before host signing. |
| K-08 current daemon IPC is minimally hardened | Verified, with stronger wording | `crates/bloom-daemon/src/ipc.rs:187` creates a UDS and blindly removes an existing path; `:243` reads unbounded newline-delimited JSON and has no peer authentication. Stale-socket cleanup is therefore unsafe, not a property to preserve unchanged. |
| K-09 same UID defeats filesystem-mode isolation | Verified architectural inference | POSIX same-principal access and process inspection make mode bits insufficient against a compromised daemon under the same UID. This is not a Rust-code fact; E-05 must demonstrate the packaged alternative per platform. |
| K-10 guests can choose an arbitrary signed hash within a grant | Verified | `sign.wit:26` supplies the hash; `crates/bloom-keystore/src/petal_host.rs:434` validates grant/attestation bindings but `:532` signs the supplied hash without reconstructing its semantics. |
| K-11 key use precedes one-shot consumption | Verified | `crates/bloom-keystore/src/petal_host.rs:532` signs, then consumes and audits at `:550` through `:577`. A crash can therefore leave an ambiguous key use. |
| K-12 batch is partial-prefix today | Verified | `crates/bloom-keystore/src/petal_host.rs:580` through `:636` loops over single signing; earlier children can succeed before a later failure. |
| K-13 registration has partial restart reconciliation | Verified | `crates/bloom-daemon/src/registration.rs:93` hashes registration requests; `:275` performs restart reconciliation and later replay logic, but secret pre-commit state remains memory-resident. |
| K-14 Bloom exposes three interaction modes | Verified | `docs/architecture/Interaction Modes.md` documents one-shot in-process, daemon UDS, and mounted NFS modes. D-008 intentionally removes the production in-process promise. |

Additional drift:

- Durable standing-session tables and reserve/commit/release methods now exist
  in `crates/bloom-auth/src/lib.rs:302` and around `:1957`. They are useful
  implementation material but do not yet implement the D-012 custody wrap or
  independent keystore backstops.
- VFS advertises `sign/message`, `sign/hash`, and `sign/typed_data`, but writes
  are explicitly rejected in `crates/bloom-vfs/src/handlers/wallets.rs:2200`.
  The triad should not accidentally restore those opaque legacy surfaces.
- Current `/wallets/new` supports local/raw import flows through daemon/VFS.
  That path is incompatible with D-005 and is replaced by trusted keystore UI
  preparation/status operations in section 38.3.

## 3. E-10 signing-intent coverage

The complete current first-party/installed inventory is:

| Intent | Preimage location today | Fixed versus controlled-variable fields | Parseability / standing |
|---|---|---|---|
| `evm.tx.sign` | transaction engine retains the unsigned envelope before the hash-only host call (`crates/bloom-tx/src/tx_engine.rs:3271`–`:3398`); auth subject contains envelope/hash facts (`crates/bloom-auth-api/src/lib.rs:1805`–`:1976`) | fixed chain/account/recipient/calldata/action/value; nonce and fee envelope may vary only inside approved bounds | standard transaction schema; standing when all value and maximum-fee debits have budget lines |
| `wallet_policy.sign` | exact proposed bytes are read and signed in `crates/bloom-vfs/src/handlers/wallets.rs:756`–`:824` | full proposed policy and baseline fixed | canonical TOML; one-shot only because it changes authority |
| `x402.sign` | x402 constructs typed payment material then invokes a digest callback (`crates/bloom-paid-x402/src/lib.rs:64`–`:129`); daemon host receives digest/facts at `crates/bloom-vfs/src/handlers/requests.rs:926`–`:966` | fixed asset/amount/payee/chain; bounded validity and nonce variable | registered typed-payment schema; standing after preimage callback plumbing |
| `paid-http.mpp.sign` | MPP constructs charge/session/open/voucher variants before its digest callback (`crates/bloom-paid-mpp/src/lib.rs:81`–`:320`) | fixed currency/payee/approved amount or deposit; channel, nonce, validity and explicit fee fields variable | parseable per registered variant; standing only where conservative debit/fee extraction exists |
| `hyperliquid.approve_agent` | handler builds the action/hash at `crates/bloom-vfs/src/handlers/hyperliquid.rs:674`–`:710`; builder at `crates/bloom-hyperliquid/src/lib.rs:275`–`:315` | fixed agent, wallet, chain and expiry envelope | EIP-712 parseable; one-shot authority change |
| `hyperliquid.usd_send` | handler builds action/hash at `crates/bloom-vfs/src/handlers/hyperliquid.rs:1652`–`:1712`; current host reduction is at `:2053`–`:2096` | fixed destination/amount/chain; time/nonce controlled | EIP-712 parseable and value-bearing |
| `polymarket.onboard` | CLOB-auth preimage at `../bloom-petal-polymarket/route/src/onboarding/mod.rs:94`–`:126`; onboarding also calls relayer batch signing near `:192` | wallet/chain/action fixed; timestamp/nonce/deadline controlled; relayer calls ordered and fixed by approved onboarding variant | two registered schemas under one intent; one-shot credential/authority setup |
| `polymarket.order.poly1271` | full order preimage at `../bloom-petal-polymarket/route/src/trade_flow_parts/posting.rs:145`–`:194` | market/token/side/price/maker/taker amounts fixed; salt/nonce/expiry controlled | typed order parseable; value-bearing maker exposure |
| `polymarket.relayer_batch` | ordered call preimage at `../bloom-petal-polymarket/route/src/relayer_actions.rs:142`–`:183` | wallet/chain/targets/values/calldata fixed; nonce/deadline controlled | parseable only for registered decoded call forms |

The registry constants and default registrations are at
`crates/bloom-auth-api/src/lib.rs:47`–`:58` and `:2295`–`:2386`.
Polymarket declares its three intents in
`../bloom-petal-polymarket/petal.toml:76`–`:81`; its internal
`PreparedSigning` retains preimage data
(`route/src/approval.rs:9`–`:32`) but `sign_prepared` transmits only
wallet/hash/intent (`:54`–`:72`, `:185`–`:195`).

The last item exposes a real protocol gap. Bloom's current Petal ABI never
receives those bytes. Consequently, D-002 (“keep v0.1 signing ABI unchanged”)
cannot support D-034's exact-preimage approval for installed Polymarket
routes. Section 38.9 now requires a parallel or v0.2 payload-bearing signing
interface and fail-closed behavior for v0.1 hash-only signing calls.
Non-signing v0.1 routes can remain compatible.

NEAR currently declares no signing capability. Registry names
`hyperliquid.order`, `hyperliquid.cancel`, and `defi.route.sign` have no live
host key-use path, so they are dormant registry entries rather than E-10
coverage (`../bloom-petal-near/petal.toml:15`–`:16`;
`crates/bloom-auth-api/src/lib.rs:2333`–`:2342`).

## 4. End-to-end completeness audit

| Flow | Authoritative owner(s) | Durable state / restart rule | Spec coverage |
|---|---|---|---|
| One-shot sign | signing grant/journal; keystore key-use result; daemon execution | at-most-once accepted effect, stable replay, ambiguous quarantine | 38.3–38.5 |
| Standing sign | signing policy/ledger; keystore capability/backstops | sliding reservations survive; keystore result reconciled first | 38.4–38.6 |
| Approval ceremony | signing review manifest; keystore challenge/capability | challenge boot-bound; activation receipt precedes grant | 38.7 |
| Registration | keystore | pre-commit secret loss fails; post-commit resumes from receipt | 38.7 |
| Recovery | keystore trusted UI | generic custody operation journal | 38.3, 38.7 |
| Raw-key import | keystore trusted UI | daemon receives status only | 38.3, 38.7 |
| Encrypted export | keystore trusted UI | encrypted artifact plus public receipt only | 38.7 |
| Credential add/revoke/replace | keystore trusted UI | replacement commits new before revoking old | 38.3, 38.7 |
| Wallet delete | keystore, after signing revocation | revoke, drain/quarantine accepted uses, tombstone/audit | 38.7 |
| Policy update | daemon projection; signing validation; keystore CAS | version+digest CAS; signing rereads/verifies commit | 38.8 |
| Revoke one/all/panic | independent signing and keystore control endpoints | either monotonic tombstone blocks its layer; signed union reconciles | D-035, 38.2–38.3 |
| Internal signer-cache eviction | keystore only; no public protocol or authority effect | process-local and restart-scoped | D-039, 38.7 |
| Standing renewal | signing ceremony plus keystore atomic replacement | new ID; no authorization before activate+old revoke receipts | 38.5 |
| Batch signing | signing and keystore | atomic parent commit; parent/derived children queryable; complete replay | D-033, 38.3–38.5 |
| Restart/reconciliation | each service owns journal; signed receipts bridge | keystore, signing, daemon reconciliation order | 38.5 |
| Audit | per-service | effect and audit append atomically; mutations fail closed | 38.11 |
| Version skew | both edges | exact major, conditional current/previous minor | 38.12 |

No required flow lacks an owner, API entry point, state machine, failure rule,
or acceptance-test shape.

### 4.1 VFS wallet-surface routing

The current handler's complete public categories route as follows:

| Current VFS surface | Triad route |
|---|---|
| `/wallets/new` and registration `status.json`, `ceremony_url`, `cancel` | daemon projection over keystore `wallet.registration_*`; local/raw secret fields are removed from VFS |
| wallet `address`, QR, `addresses.json`, `public_key`, `kind` | daemon read projection from `wallet.get_public`; no key material |
| `policy.json` and `policy-updates/{pending,confirmed,failed}` | daemon workflow projection → signing validate/review → keystore policy CAS |
| `unlock-passkey` | daemon returns keystore trusted UI from `wallet.unlock_prepare`; PRF never returns through VFS |
| `sign/{message,hash,typed_data}` | remains rejected; it is not restored as an opaque signing bypass |
| `policy-session/new`, `active.json`, `<id>/use`, `<id>/revoke` | standing `prepare/list/status/budget_state/revoke`; `use` becomes an ordinary semantic sign operation under the authority |
| `capabilities/active.json` and `.md` | daemon projection from signing authority status plus keystore capability receipts |
| chain `balance*`, `nonce`, `pending_external.jsonl`, `nonce_conflicts.json` | daemon-owned read-only network/outbox projections |
| `outbox/new.tx`, state files, `confirm`, `confirm.override`, `replace`, `cancel` | daemon stages and owns execution state; confirmation creates a separate signing operation and later idempotent execution per D-024 |

Evidence for the surface is
`crates/bloom-vfs/src/handlers/wallets.rs:1208` through `:1234`,
`:1967` through `:2078`, `:2197` through `:2267`, `:2337` through
`:2425`, and `:2447` through `:2974`.

The non-VFS CLI currently calls keystore directly for local creation/import,
lock, rebind, and deletion
(`crates/bloom/src/main.rs:1616`, `:1753`, `:2022`, `:2075`, `:2087`).
Section 38.3 now gives those paths explicit trusted-UI/status or lock methods;
the CLI becomes a daemon client and never constructs the keystore object.

Flows specified for completeness but not currently implemented as full product
surfaces are encrypted export and independently addressable credential
add/revoke/replace. Current rebind replaces a passkey and emits a raw recovery
key (`crates/bloom-keystore/src/passkey.rs:2088` through `:2201`), while
passkey registration/recovery acknowledgement is partially implemented.
These are forward features, not claims about existing code. Their inclusion is
necessary because the triad boundary must not be reopened later with an
unspecified secret channel.

## 5. Engineering decisions resolved

The formerly open `[agent]` questions are struck through in section 33 and
resolved as Proposed decisions D-017 through D-032. The second review adds
D-035 through D-037 for independent revocation, honest compromise claims, and
packaging go/no-go semantics:

- policy ownership, CAS, and independent signature verification;
- dual OS/application peer identity and signed canonical frames;
- independently verified package provenance;
- exact key-use ticket;
- at-most-once replay, expiry/revocation linearization, and boot leases;
- review-plan authenticity and removal of combined grant/execute;
- exact standing-ledger windows, CAIP-19 assets, gas accounting, and wrap
  construction;
- compiled semantic adapter registry;
- per-service signed audit chains and failure behavior;
- supervision, compatibility, and repository-split gates.

Engineering decisions D-017 through D-032 do not silently weaken D-004
through D-016. Product decision D-034 explicitly amends D-007's universal
semantic-validation claim while preserving exact-hash binding and D-016's
standing-adapter restriction. E-05 remains a mandatory conformance experiment
because application code cannot prove platform packaging isolation by itself.

Second-review corrections:

| Finding | Resolution |
|---|---|
| Revocation had no independent transport | D-035 adds revocation-only signing and keystore control sockets. CLI fans out without daemon; either monotonic tombstone stops its layer and later reconciles. |
| Daemon never received signature bytes | Daemon edge now exposes `signing.sign`/`sign_batch` returning complete `SigningResult`; status replays the complete result. Ticket stays internal to signing→keystore. |
| Ceremony origin/RP ID/CSRF was not specified | D-038 selects `http://localhost:18734`, RP ID `localhost`, keystore ownership, and the exact Host/Origin/token/CSP/body/rate contract in 38.7 while accepting same-RP/browser residuals. |
| Batch maxima exceeded frame maximum | Single decoded preimage is 256 KiB; batch child is 64 KiB, decoded aggregate 512 KiB, and complete encoded frame still has a 1 MiB limit. |
| Same-RP-ID PRF phishing and browser extensions were absent from threat model | Added explicitly to section 10; D-038 amends D-005 for transient browser PRF and accepts these as ceremony-TCB residuals. |
| “Parser-free small keystore” rationale ignored ceremony parsers | Section 11 now distinguishes excluded high-churn transaction/Petal parsers from the unavoidable chosen ceremony stack. |
| Keystore backstops were framed as economic containment | D-036 states that one signature may drain a standing-granted wallet; counts bound volume/duration only. |
| Signing compromise could misdescribe one-shot hashes | D-036 and section 10 state this explicitly. |
| Opaque one-shot level-3 claim overstated informed approval | Section 10.2 now says exact binding prevents substitution, not deception or social engineering. |
| Browser was an implicit TCB member | Explicit threat-matrix row and D-038 now accept/document it. |
| `wallet.lock` silently left standing authority active | D-039 removes the public RPC; the current helper remains internal cache eviction and explicit panic-revoke stops agents. |
| Same-UID systemd user-unit wording contradicted E-05 | D-037 and section 38.10 use system-owned per-login prototypes; E-05 failure blocks production rather than permitting a level-2 waiver. |

### 5.1 Platform conformance gate

- **Platform containment:** D-004 requires containment of a fully compromised
  daemon, while K-09 means ordinary same-UID filesystem/socket modes are not
  enough. D-008 names launchd/systemd user-service delivery, whose exact
  principal, sandbox, ptrace/process-visibility, key-store, and upgrade
  properties are not established in this repository. This is not yet a proven
  contradiction because mandatory sandbox identities or system-owned
  per-login instances may supply the boundary. E-05 is the explicit
  feasibility gate. Spec section 38.10 provides provisional candidates and
  refuses the level-3 claim on a platform whose negative tests fail.
There are no other known security-relevant choices left implicit in the local
v1 contract. Remote topology and wallet-kind expansion remain P2 product scope,
not hidden dependencies of the first local triad.

## 6. Product decision briefs

### Q-SEC-05 — Unknown/opaque one-shot payloads — resolved

The initial recommendation to require a semantic adapter for every one-shot
request was rejected because it would exclude arbitrary calldata, multicalls,
new contracts, and protocols unknown to Bloom. Executing or simulating a
transaction cannot prove that later mainnet behavior will match.

Decision D-034:

- arbitrary one-shot signing is allowed only through a live ceremony bound to
  the exact final preimage and ordered hash set;
- signing makes no universal claim about calldata, simulation, proxy, contract,
  or off-chain effects;
- Petal plans and simulations are digest-bound but visibly attributed
  advisory material;
- registered adapters may add trusted, locally decidable interpretation;
- standing authority continues to require a registered adapter that emits
  conservative value debits under D-016;
- there is no reusable opaque `N`-by-`T` one-shot grant.

Protocol/work consequences: W1 carries preimage, hash/algorithm, and optional
schema metadata; W3 stores exact one-shot hashes in the activated keystore
capability; W4 implements exact binding plus the standing adapter registry; W5
renders exact low-level commitments separately from attributed advice; W6
adds the payload-bearing Petal WIT; AC-07 tests byte-for-byte substitution and
the separation between advice and trusted claims.

### Q-CONS-05 — Batch signing contract — resolved

Context: current host batching is partial-prefix. Polymarket onboarding uses a
batch helper, so removing batch breaks a live installed flow. Returning an
unqueryable partial prefix is unsafe across IPC failure.

Options:

1. Preserve partial-prefix results and make every child independently
   queryable. Lowest implementation change, highest caller/recovery burden.
2. Keep a batch request but expose only an **atomic, queryable publication
   contract**: validate and reserve all children, compute signatures in
   memory, durably commit all results/counters in one local transaction, then
   return all; before commit none escape. Each child still has a derived child
   operation ID for status/audit.
3. Remove batch temporarily and rewrite callers as explicit single operations.
   Simpler protocol, but breaks Polymarket onboarding semantics and cannot make
   several signatures appear as one approved/key-use unit.

| Option | Protocol consequence | Work-breakdown consequence |
|---|---|---|
| 1 partial/queryable | response is ordered child results plus first failure; each child has an operation ID and independent key-use status | W2/W3/W4 implement child journals and prefix reconciliation; W6 rewrites all callers to handle partial outcomes |
| 2 atomic/queryable | one parent ticket/result binds ordered children; no child signature is published before parent commit; parent and derived child status are queryable | W2 adds parent/child journal support; W3/W4 add transactional batch reserve/result; W6 keeps Polymarket's logical batch |
| 3 remove | batch methods and ticket fields are deleted from v1 | W1/W3/W4 shrink, but W6 must redesign Polymarket onboarding and its approval model before integration can complete |

Decision: **option 2 (D-033)**, with a maximum of 32 children and one wallet,
key, authority, policy snapshot, algorithm, and semantic provenance domain per
batch. “Atomic” means no signature result is published before the durable
batch commit; it does not claim that cryptographic CPU work is reversible.
Crash before commit recomputes under the same operation ID; crash after commit
replays the whole stable result.

Consequences of option 2:

- signing reserves budgets and one-shot count for the ordered set in one
  transaction;
- the ticket binds all ordered hashes and `signature_count`;
- keystore checks/reserves backstops, computes all signatures, and commits the
  entire result/counters atomically;
- any validation/signing failure before commit releases all reservations;
- ambiguous post-dispatch state is resolved by querying the batch operation,
  never by submitting a new batch ID.

No further decision is needed.

### Q-CER-04 — Trusted ceremony surface — resolved

Context: a normal browser cannot use UDS peer authentication. On localhost,
WebAuthn RP ID is port-blind, so a compromised daemon can serve a different
port under the same RP ID and solicit an assertion/PRF. Browser JavaScript and
extensions also observe PRF and rendered approval content. This contradicts a
literal D-005 claim that only keystore holds PRF and means D-023 plan signing
does not by itself authenticate the UI surface.

Options:

1. **Native keystore-bound UI.** Keystore uses platform passkey APIs and
   renders the ceremony in its native security boundary. No localhost HTTP
   origin or browser extension sees PRF. This preserves D-005 but requires
   platform-specific UI/passkey work and feasibility testing on macOS/Linux.
2. **Per-install authenticated HTTPS origin.** Provision a unique RP ID,
   keystore-only TLS private key, trusted certificate path, fixed origin,
   Host/Origin/CSRF/CSP rules, and capability-scoped sessions. This prevents
   another local port from impersonating the HTTPS origin but explicitly adds
   the browser/extensions to the TCB and requires amending D-005.
3. **Platform-specific hybrid.** Use native UI where viable and authenticated
   HTTPS elsewhere. Each platform advertises a different ceremony trust tier
   and passes a separate suite; no generic “level 3 ceremony” claim is made.
4. **Current browser-loopback model with explicit residual acceptance.**
   Keystore serves fixed HTTP localhost origin/RP ID, with hardened
   Host/Origin/token/CSP rules. Browser extensions and same-RP-ID other-port
   phishing remain in/against the accepted ceremony TCB.

| Option | Protocol consequence | Work consequence |
|---|---|---|
| 1 native | `TrustedLaunch.kind=native`; OS activation token binds manifest/challenge; no RP ID/HTTP DTO | W0/W5 add native passkey/UI probes and platform implementations; strongest AC-02 |
| 2 HTTPS | `TrustedLaunch.kind=https`; normative origin, RP ID, TLS enrollment/rotation, cookies/tokens, CSRF/CSP and body/rate limits required | W0 gains certificate/RP provisioning; W5 gains hardened server/browser app and phishing/extension tests; D-005 must be amended |
| 3 hybrid | both launch variants and trust-tier advertisement are mandatory | largest W0/W5/release matrix; platform documentation and AC-10 split |
| 4 loopback HTTP | `TrustedLaunch.kind=browser_loopback`; fixed port/origin/RP ID and explicit browser PRF exception | smallest UX change; W5 hardens current server and AC-10 records rather than “passes” inherent same-RP/extension residuals |

Decision: retain the current browser-loopback model (D-038). Keystore binds
`127.0.0.1:18734`, serves canonical origin `http://localhost:18734`, and uses
RP ID `localhost`. Section 38.7 specifies exact Host/Origin, token, Fetch
Metadata, CSP, cache, body, concurrency, and PRF-handling rules. D-005 is
amended only to permit transient PRF in the browser ceremony context.
Same-RP-ID other-port phishing and compromised browser/extensions are accepted
and documented ceremony-TCB residuals; these HTTP controls do not claim to
prevent them.

### Q-LOCK-01 — Wallet lock and standing authority — resolved

Current-code fact: there is no public `bloom wallet lock` command in
`WalletCmd` (`crates/bloom/src/main.rs:547`–`:692`).
`Keystore::lock` only removes the wallet from the process-local unlocked signer
map (`crates/bloom-keystore/src/lib.rs:847`–`:849`) and is used internally
before passkey policy review (`crates/bloom/src/main.rs:2022`,
`crates/bloom-daemon/src/ipc.rs:486`). It does not revoke grants or the
separate signer cache. The open question exists because the draft promoted
this internal primitive into a public triad RPC.

Options:

1. **Do not expose public lock.** Keep cache eviction internal and use explicit
   revoke/panic-revoke for authority.
2. **Lock revokes all standing capabilities permanently.** It fans out through
   D-035; agents require a fresh ceremony afterward.
3. **Lock leaves standing capabilities active.** Rename/display the operation
   as “lock interactive access” and require a prominent list of still-active
   agents in its result.
4. **Add durable pause/resume.** Both signing and keystore need monotonic pause
   tombstones and authenticated resume semantics; resume without a fresh
   ceremony materially weakens the meaning of lock.

Decision D-039: **option 1**. No public lock variant ships in v1. The existing
helper remains internal signer-cache eviction with no authority semantics.
Explicit revoke/revoke-all/panic-revoke is the only public way to stop standing
agents. A future lock/pause product requires a separate decision.

## 7. Implementation handoff

The normative contract is in spec section 38. Work packages W0 through W8
include dependencies and completion evidence; acceptance tests AC-01 through
AC-15 cover process boundaries, secret confinement, protocol authentication,
fault recovery, exact-payload binding, optional semantic validation, budgets,
lifecycle, audit, and version skew.

The product contract is complete. W0, W1, W2, and W5 can begin within their
dependency constraints.

Dependency graph:

```text
W0 packaging ───────────────────────────────────────────────┐
                                                           v
W1 role contracts -> W2 journals -> W3 custody seam -> W4 signing seam
       |                  |              |             |
       |                  |              +-> W5 ceremony
       |                  |                            |
       +------------------+----------------------------+-> W6 daemon integration
                                                              |
                                                              v
                                                       W7 process extraction
                                                              |
                                                              v
                                                          W8 release
```

| Package | Deliverable / contracts | Test obligations | Independently mergeable? |
|---|---|---|---|
| W0 | installer-owned edge manifest; system-owned per-login prototypes; principals, roots, revocation control sockets, key-provider and ceremony-surface probes | AC-01, AC-14 and platform portion of AC-02/03/04 | yes, as go/no-go conformance spike and packaging fixtures |
| W1 | in-process `DaemonSigning` and `SigningKeystore` traits; all 38.3 DTOs, complete signing results, frame/JCS codec, hello/errors, size vectors | AC-04, AC-13, AC-15 | yes; D-038 fixes `TrustedLaunch` as browser loopback |
| W2 | reusable operation journal, state transitions, idempotency, service audit chain, fault-injection hooks | AC-05, AC-06, AC-12 | yes; uses W1 IDs/digests but no domain service |
| W3 | keystore implementation of public reads, ticket checks, key result replay, policy CAS, capability/lifecycle APIs | AC-02, AC-09, custody parts of AC-11 | yes with fake signing peer; no daemon dependency |
| W4 | signing grant state, exact-payload binding, standing semantic-adapter registry, policy evaluator, ledger, provenance verification, ticket issuer | AC-06–AC-09 | yes with fake daemon and W3 fake/real peer |
| W5 | D-038 browser-loopback ceremony; registration and custody workflows; review-manifest verification | AC-02, AC-10, lifecycle portions of AC-11 | yes after W3; accepted same-RP/browser residuals are documented test expectations |
| W6 | daemon clients/projections, VFS remap, execution separation, payload-bearing Petal WIT, removal of direct keystore/key types | AC-03, AC-07, full AC-11 | yes after W3–W5 interfaces; integration-heavy but feature-sliced commits should remain reviewable |
| W7 | signing and keystore binaries, real transport clients/servers, service activation integration, negative connectors | AC-01–AC-06 and restart matrix | no by nature; verified against completed seams and W0 fixtures rather than unfinished product logic |
| W8 | adjacent-version matrix, signed reproducible installer bundle, operational docs, repository-split gate | AC-13 plus rerun AC-01–AC-15 on bundle | yes as release/package work after W7 |

The only intentionally non-independent package is W7: extraction cannot prove
a real boundary without at least two endpoints. Its risk is reduced by keeping
all domain logic already mergeable and tested behind the W1 traits. W6 should
be split by surface (base wallet/policy, transaction/outbox, paid HTTP,
Hyperliquid, Polymarket) so no single integration change spans all handlers.

## 8. Verdict

**Verdict: implementable now.**
