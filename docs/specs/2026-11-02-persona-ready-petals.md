# Persona-ready Petals: verified effect profiles and a minimal Petal surface

**Status:** proposal, not implemented
**Date:** 2026-11-02
**Revised:** 2026-11-03 — narrow delivery scope and clarify trust guarantees
**Builds on:** Machine #377, Broker #112, Signer #81, SDK #52, Polymarket #26 (all open drafts)
**Relationship to existing decisions:** retains the decision to defer a generic
verifier framework. Typed verified results may replace duplicate `Spend`
declarations for individual supported operations; the declared-effects path
remains supported. The prepared-action API does not need a wholesale rewrite.

## Goal and first delivery

An owner picks a persona at onboarding. Covered Trader or Degen actions use
recurring token allowances without per-action approval. Valid actions outside
coverage use exact review. Institutional continues to require individual
approval; it has no automatic spending tier.

First make the existing Polymarket BUY and Degen ERC20 paths work from the
release catalog through a fresh installation. Then add one further Petal and
extract only the integration helpers that both actually need. Supporting every
default Petal is a staged goal, not the first release gate.

Keep custody, Sealed Approvals, reservations, rearm, revocation and process
boundaries unchanged. Keep the existing protocol verifiers. No new rule engine,
on-chain allowance tracker, linked-address registry or wallet-wide accounting
layer is required for the first delivery.

The eventual goal is a small Petal surface and catalog-driven eligibility.
New operations within an existing supported format/verifier should need only
Petal and reviewed catalog changes. New protocol semantics may require a small
Broker verifier; do not promise arbitrary protocols with no Broker changes.

## Current-state observations from the original proposal

These observations span several draft revisions. Recheck them against the exact
release candidates before turning them into tasks; this revision is not a fresh
audit of every listed PR or SDK dependency.

What avoids approvals today:

- Polymarket BUY.
- Degen native-wallet ERC20 transfers to any recipient on Ethereum and Polygon.

Even Polymarket BUY does not activate in a release build. Every pinned catalog
route in `crates/bloom/src/github_source.rs` has `economic_effects_schema: None`,
so onboarding discovers nothing, and Trader fails with "no supported reusable
scope was selected".

Gates that a new Petal hits, all hardcoded:

| Layer | Gate |
|---|---|
| Machine `bloom-daemon/src/prepared_signing.rs` | Only two review formats are accepted (`polymarket.prepared-record` v1, `bloom.message.review` v1). Everything else returns `Unsupported`. |
| Machine `bloom-daemon/src/lib.rs` | Persona discovery is forced off on the message-review route. Only the Polymarket batch route can use an allowance. |
| Broker `bloom-broker-api/src/reusable_profile.rs` | `reusable_signing_profiles()` has one entry. The verifier is a closed enum, and the profile is chosen per package rather than per operation class. |
| Broker `validate_generic_session_profile` | Hyperliquid, gasless and venice classes are refused allowances outright. |
| Machine onboarding | `DEFAULT_PETALS`, `petal_label`, `petal_destinations::for_petal`, the Polymarket setup template, and the `[1, 137]` Degen chain list (repeated in four places) are compiled in. |

Paths that the prepared-action API does not cover:

- near, pendle and privacy-pools never sign. They stage transactions through
  the Machine outbox (`tx_stage`/`tx_confirm`), and `native_session_projection`
  only covers plain transfers from the EVM wallet itself.
- gasless and venice-x402 pin SDK `b9fc22d` and call `sign_hash`, which SDK
  master has removed.
- Hyperliquid hand-rolls its own claim builder, nonce state, withdraw records
  and receipt reservations (about 1,400 lines in `workflow.rs`).

How the Polymarket spend shape falls short:

- **One order is described three times.** The typed order becomes the signing
  bytes, a JSON witness of decimal strings, and a `Spend` declaration. Broker
  rebuilds the bytes from the witness, then checks that the declared debit
  equals the witness maker amount. On the verified path the declaration only
  adds a way to fail.
- **Broker reads economics by display label.** `validate_order_debit` finds
  fields by strings such as `"Maker amount (raw protocol units)"`.
- **The legacy envelope survives.** `PreparedOrder` → `PreparedSigning` → JSON
  array → `ReviewArtifact`.
- **Petal plumbing outweighs domain logic.** Of the roughly 710 production
  lines #26 still touches, about 190 are Polymarket-specific. The rest is
  generic plumbing or workarounds: attempt records, status projections,
  operation keys, outcome mapping and compatibility shims.

## Decisions

| ID | Decision | Direction |
|---|---|---|
| P1 | How effects are established | **Protocol-verified:** an existing Broker verifier binds structured input to signing bytes and derives effects under explicitly reviewed protocol assumptions. **App-reported:** Broker accounts over the pinned Petal's declarations. Neither label promises arbitrary-contract maximum-exposure verification. |
| P2 | Persona eligibility | Trader and Degen may use either tier when the owner explicitly approves the profile and its assurance level. Do not introduce a Degen-only restriction implicitly. Institutional has no automatic spending. |
| P3 | Generic verifier framework | Defer. Return typed effects from existing verifiers, then integrate one further Petal before deciding whether a bounded evaluator saves complexity. |
| P4 | ERC20 approvals and consumer calls | Defer automatic approve/consumer accounting. Use existing exact review. Do not infer that a consumer call has zero debit because an earlier approval was charged. |
| P5 | Authentication | Consider a narrowly checked, explicitly opted-in auth profile when the next Petal requires it. Zero token debit alone never proves harmlessness. |
| P6 | Allowance semantics | Limits govern signing per rolling window, not outstanding exposure. Cancels do not refund signed orders; no exposure model is added. |
| P7 | Polymarket SELL | Keep exact review. |
| P8 | Ceremony count | Retain existing separate approvals, driven clearly through the browser, including rearm. No ceremony-composition project. |
| P9 | Venue assets | Defer until a concrete integration requires them. Hyperliquid agent permissions must be described separately from token budgets. |
| P10 | Wallet-wide ceilings | Optional future product decision. Retain per-Petal/account budgets, show their additive capacity clearly, and preserve usage through retries/rearm. Shared ceilings must not silently replace independent budgets. |

Malformed payloads, invalid provenance and mismatches between structured input
and signing bytes are rejected outright. Exact-review fallback is for valid
requests outside supported automatic coverage, not a way to approve invalid
requests.

## Workstream 0: land the current stack

Exit criterion: a release-shaped build onboards Trader and Degen, and
Polymarket BUY signs with zero ceremonies after setup.

1. Retarget Signer #81 to master and rebase it. Its base,
   `signer-quarantine-reports-ambiguous`, was squash-merged as `4fe7f61`.
2. Merge SDK #52. Re-pin it in Machine and Polymarket.
3. Pin a new Polymarket artifact whose routes carry `economic_effects_schema = 1`.
4. Add a test that the pinned release catalog yields at least one discoverable
   reusable profile. Make Trader onboarding fail with a clear message, not a
   compile error, when nothing is discoverable.
5. Fix stale operator text:
   - `bloom-vfs/src/docs/agent-guidance.md` still says "shared dollar pool"
     and "approved prices".
   - The Broker README contradicts `docs/generic-sessions.md` on native
     sessions and protocol 1.6.
   - The wording at `approval.rs:262` mentions a "USD policy".
6. Unify duplicated chain and gas constants when touching their callers; a
   wider module reorganisation is not a release prerequisite.
7. Show that each Petal/account has independent token limits. Do not imply
   that the persona preset is one wallet-wide pool. Test that adding routes,
   retrying and rearming do not multiply an existing budget. Package updates
   and replacements must explicitly preserve usage or require fresh owner
   review that explains any newly granted capacity.

Workstream 0 does not change the Polymarket spend shape. That happens in
workstream 1.

## Workstream 1: typed effects first; profiles are a future sketch

**Deliver now:** have the existing Polymarket verifier return typed order fields
and derived debits. Render review labels from that result, never parse display
labels back into authority. Remove redundant declarations only for this verified
path, keeping its payload binding and negative tests. Preserve existing wire
formats until a concrete migration needs to change them.

The profile design below is exploratory, not an implementation requirement.
Do not build its evaluator, wrappers or link registry in the first delivery.

### Verification boundary

EIP-712 signing hashes cannot be decoded back into messages. Broker receives a
complete structured domain, type schema and message (plus wrapper data where
needed), independently reconstructs the exact signing payload/hash and checks
the binding. Typed input replaces a bespoke witness encoding, not the need for
evidence. Machine deriving a hash does not replace Broker verification.

A successful binding check establishes what was signed. Economic interpretation
also depends on reviewed protocol semantics: exact chain and contract identities,
token behaviour, wrapper semantics and relevant upgradeability. Each supported
verifier/profile documents those assumptions and the fields it actually bounds.
An upgradeable target needs an explicit reviewed upgrade trust policy; a package
hash does not pin deployed contract behaviour. Unsupported semantics remain
app-reported or exact-reviewed. Do not claim universal maximum exposure.

A catalog signature authenticates the approved profile and package; it does not
prove that its economic interpretation is correct. Existing reviewed verifiers
remain until a replacement passes equivalent positive and adversarial tests.

### Profile contents (future sketch)

A profile describes one operation class: how to decode its signing input,
what must hold, and what effects follow. Profiles live in the Petal
manifest, are copied into the installer-signed catalog record, and are
bound to the package hash. A changed profile is a changed package and needs
owner re-consent.

```toml
[[sign.profile]]
id           = "polymarket.buy.v2"
class        = "polymarket.order.poly1271"
format       = "eip712"
wrapper      = "erc7739"
domain       = { name = "Polymarket CTF Exchange", version = "2", chain_id = 137,
                 verifying_contract = ["<CTF_EXCHANGE>", "<NEG_RISK_EXCHANGE>"] }
primary_type = "Order"
require      = { side = 0, signatureType = 3, metadata = "0x0", builder = "0x0",
                 maker = "$link.polymarket.deposit-wallet",
                 signer = "$link.polymarket.deposit-wallet" }
debit        = { asset = "erc20:evm-137:<PUSD>", amount = "makerAmount" }
```

| Field | Meaning |
|---|---|
| `format` | `eip712`, `evm-call` (ABI calldata on an EVM transaction), `evm-transfer` (native value), `personal` (EIP-191 text, `auth` only), `svm-transfer`. |
| `wrapper` | An optional named wrapper around the inner struct, for example `erc7739` for deposit-wallet signing. Each wrapper is implemented once in Broker. |
| `require` | Predicates over decoded fields and context: equality, `in` (a reviewed list), `max`/`min` on integers, `nonzero`. Every predicate must hold. |
| Effects | `debit` (one or more) or a specifically supported `auth` operation. `allowance` and generic `none` eligibility are deferred. Transaction fees require verified transaction fields and chain-specific fee semantics; a rule cannot omit them. |
| `when` | Optional. Several profiles may share a class with disjoint `when` predicates, for example BUY versus SELL. |

Context references:

| Reference | Value |
|---|---|
| `$tx.to`, `$tx.value`, `$chain` | From the transaction being signed. |
| `$account` | The exact KeyRef address. |
| `$link.<name>` | A linked address registered for this account by an exactly reviewed operation, for example the Polymarket deposit wallet created during venue onboarding. Unregistered links fail closed. |

### Evaluation (Broker)

1. Parse complete structured signing input according to `format` and `wrapper`.
2. Independently reconstruct the exact payload/hash from that input. Reject
   malformed input or any mismatch outright. The structured input is the
   evidence; it need not be a second bespoke witness object.
3. Select the profile whose class equals the claim's operation class and
   whose `when` matches. Selection is never by package. No match, or more
   than one match, means exact review.
4. Evaluate every `require` predicate. A valid action outside the approved
   scope uses exact review. Invalid encodings, provenance or payload bindings
   are rejected, never offered as approvable requests.
5. Derive effects and charge them through the existing reservation and
   rolling-window accounting.
6. For a verified profile, the request carries no Petal-declared debits. If
   any are present, reject the request.

Limits:

- Profiles are size-bounded and loop-free, and each evaluation has a fixed
  cost bound.
- Amounts use checked uint256 arithmetic. Different assets never net.
- Asset identity is chain-qualified. Symbols never select authority.

### Owner review

Render each profile as a human sentence from its fields, for example
"Polymarket BUY orders from your deposit wallet: up to 1,000 pUSD per order,
10,000 pUSD per 7 days". Show the tier (verified or app-reported) and the
reviewed spender and recipient lists. Remove the classification by
operation-class prefix; the label comes from the signed catalog record.

### Declared tier

For classes no rule can express, a profile may set `effects = "declared"`
together with the assets it may declare. The existing effects-v1 path
applies: Broker checks accounts, networks, provenance and arithmetic over
the Petal's runtime declaration. This tier is available to Trader and Degen with explicit owner consent (P2).
Review copy says amounts are app-reported and that Broker does not independently
verify the maximum spending authorized by the bytes. Institutional remains
individually approved.

### Allowance effects — deferred

Do not implement the proposed approve-once/uncharged-consumer model in this
iteration. ERC20 approvals and Permit2 authorizations create authority that can
outlive a Broker window or session. A later consumer can spend an old approval;
a Machine-reported chain read can be stale and does not independently establish
a safe maximum debit. Revoking a Bloom permission does not revoke that authority.

Retain exact review for approval and consumer operations not covered by an
existing specifically reviewed verifier. Do not treat arbitrary consumer calls,
approval resets or Permit2 messages as automatically safe generic profiles.
Even a zero approval needs correct target/selector binding and gas accounting.

A future automatic integration must define bounds for the particular protocol,
pre-existing authority, transaction ordering, retries and changes in chain state.
If an app-reported integration is separately approved, label its reliance on the
Petal explicitly; it must not be presented as protocol-verified. No new outstanding
allowance database or chain-read attestation system is planned here.

### Auth effects

```toml
[[sign.profile]]
id      = "venice.siwe.v1"
class   = "venice-x402.siwe"
format  = "personal"
auth    = { scheme = "siwe", domain = "api.venice.ai", uri_prefix = "https://api.venice.ai/",
            chain_id = 8453, max_lifetime_s = 600, statement = "<exact text>" }
rate    = { max_per_hour = 30 }
```

Broker parses the SIWE message, checks every constraint and the freshness
window, and applies the rate limit. No asset is charged. Eligibility
requires persona opt-in for the specific profile. ClobAuth's existing
one-use timestamp-refresh scope becomes an `auth` profile with
`scheme = "clob-auth"`.

### Retirements

Remove display-label-based economic parsing and duplicate derived declarations
as the typed Polymarket result lands. Retain payload reconstruction, existing
protocol verifiers and native transfer verification. Do not remove the closed
verifier enum, class restrictions or prepared-record format merely to satisfy
the future profile sketch. Replace each only when a tested concrete integration
requires it.

## Workstream 2: data-driven eligibility (incremental)

First move labels and discovery metadata for existing supported verifiers into
the reviewed catalog. Do not require the full manifest/evaluator design below.
Remove a route restriction only when its replacement has equivalent checks.
The remaining steps describe the possible later evaluator design.

1. **Manifest.** `[[sign.profile]]` in `petal.toml`, validated by the SDK
   builder and by Machine at install. Remove the `economic_effects_schema`
   flag; a profile with declared effects is what implies it.
2. **Catalog record.** Carries the profiles, the human label, the allowed
   destinations and the setup template. This replaces `DEFAULT_PETALS`,
   `petal_label`, `petal_destinations::for_petal` and `POLYMARKET_SETUP` in
   Machine source.
3. **Broker registry.** Profiles from installer provenance, keyed by
   (package hash, class). Broker advertises evaluator capabilities
   (`bloom.effects/eip712@1`, `bloom.effects/evm-call@1`, wrappers,
   `auth` schemes) rather than per-profile capability strings.
4. **Machine.** Persona discovery is allowed on every route whose class has
   an eligible profile. Format handling follows the profile's `format`. The
   two-format allowlist is removed.
5. **Onboarding.** Petals selectable in the browser come from the catalog,
   not a compiled list. Each eligible Petal has its own toggle and shows its
   profiles.

Future evaluator exit criterion: a fixture Petal with a new EIP-712 profile becomes eligible
end to end against real Broker and Signer with no source change outside the
fixture.

## Workstream 3: minimal Petal SDK surface

Start with shared retry/outcome/status helpers used by Polymarket and the next
Petal. Preserve durable identity, ambiguity handling and reservations. Derive
macros, a status index and API deletions are optional follow-ups, not requirements.
The following is a target API sketch, not a checklist to implement wholesale.

Target Petal code for a signed action:

```rust
#[derive(Serialize, Deserialize, Prepared)]
#[prepared(class = "polymarket.order.poly1271", format = "eip712", wrapper = "erc7739")]
struct PreparedOrder { order: Order, neg_risk: bool, draft_id: String }

impl PreparedOrder {
    fn validate(&self, ctx: &Ctx) -> Result<()> { /* domain checks only */ }
}

let signature = petal::signing::sign_or_resume(ctx, wallet, &draft_id, || build_order(&params))?;
```

1. **Typed payloads.** `Eip712::new(domain, message)`, `EvmCall::new(chain, to,
   value, calldata)` and so on. The host derives the hash. Petals never supply
   preimages, hashes or witnesses for verified formats.
2. **`sign_or_resume`.** On first call it persists the prepared value under
   the operation key. On retry it reloads, re-validates and compares. Then it
   signs and maps the outcome to one result type with standard
   error codes and user messages. Retry after approval is the same call.
3. **`Attempt<T>`.** A durable `{id, completed, value}` record for operations
   whose payload legitimately refreshes, such as a login timestamp.
4. **Status.** `route_status!` generates status and `approval.json` routes. A
   host query lists pending operations for the route, so Petals do not
   enumerate keys. A typed `NotFound` replaces string matching.
5. **Typed spend for the declared tier.** `Spend::erc20(chain_id: u64, Address,
   U256)`, not strings.
6. **Deletions.** Remove `Effects::batch_claim` and the effects-v1 builder from
   the public SDK after migration, and remove Hyperliquid's private copy of
   `ClaimEffects`.

Polymarket after migration:

- Delete the `Spend` match, `review_witness`, `PreparedSigning`,
  `action_for_prepared`, `operation_identity`, `relayer_attempt`,
  `LoginAttempt` (now `Attempt`) and `approval_projection` (now the status
  macro).
- Prefer less duplicated plumbing, but use behaviour and tests as the acceptance
  criterion; do not target a line-count reduction at the expense of recovery.

## Workstream 4: outbox coverage (after the first additional Petal)

near, pendle and privacy-pools stage transactions rather than signing payloads.

1. Session matching runs over Petal-staged EVM transactions, using the same
   profiles (`evm-call`, `evm-transfer`). This extends
   `native_session_projection` beyond wallet-origin transfers.
2. Staging and confirmation keep their existing outbox semantics. A staged
   transaction covered by an allowance proceeds without a ceremony; anything
   else uses the existing approval.
3. **Multi-step operations.** Preserve existing staging/reconciliation. Pendle
   approve-then-router automation is deferred under P4; both steps retain
   their existing exact-review requirements. No batch interface is added.
4. **Destinations.**
   - Quote-derived recipients, such as a NEAR Intents deposit address, are
     not on a reviewed list. A near swap is therefore eligible only under the
     declared tier, or under a rule that binds the recipient to a value Broker
     can check.
   - Specify which before migrating near.

## Workstream 5: non-token sessions (integration-specific follow-ups)

- **Hyperliquid.**
  - Orders move margin, not tokens, so no order budget is invented.
  - Under Trader or Degen, onboarding proposes the existing agent-session
    approval (`approveAgent`, with the derived-key lifetime) as a persona
    member. Orders then need no owner approval, as they do today after
    session setup.
  - `usdSend` and `withdraw3` become EIP-712 `debit` profiles once P9
    exists.
  - Remove the Broker class denylist entries one class at a time as each
    gains a profile.
- **venice-x402.** SIWE uses the `auth` profile (P5). Top-ups use the
  EIP-3009 profile.
- **EIP-3009.** One built-in-style profile template covers gasless and venice:
  debit `value` of the token at `verifyingContract`, with `to` on the
  profile's reviewed list (`RELAY_PERMIT_RECEIVER`, the Venice pay-to
  address).

## Workstream 6: accounting semantics and UX

1. **Copy (P6).** Replace "up to N per 7 days" with "can sign up to N per
   7 days; cancelling does not refund; open orders are not limited by the
   window". Show this on onboarding and on status.
2. **Single source of presets.**
   - Use one reviewed preset source keyed by exact asset identity rather than
     symbol. Reuse existing catalog plumbing; moving ownership to Broker is
     not a prerequisite and must not create a second registry.
   - The onboarding page renders presets from that catalog instead of
     hardcoding them (currently in `onboarding/index.html:33`).
   - Duplicate symbols on one chain must not both receive a preset unless
     each is reviewed.
3. **Persona downgrade** reviews and revokes permissions no longer allowed.
   Remove the any-recipient marker when leaving Degen; keep standing permission
   support where still needed for Trader. Institutional has no automatic grants.
4. **Per-Petal stop** as well as whole-pool stop.
5. **Rearm in the browser bridge.** After restart or lock, the owner rearms
   from the Bloom page, not only through
   `bloom wallet persona rearm`.
6. **Venue ceiling.** Stop seeding Polymarket's daily venue ceiling equal to
   Degen's weekly Broker allowance. The two limits mean different things.
7. **Wallet-wide asset ceilings (P10).** Deferred pending an explicit product
   decision; not required for adding another Petal.

### Wallet-wide asset ceilings — optional future product change

Current allowances are independent per Petal/account and exact asset. This was
intentional: two Petals with 10,000 USDC each can authorize 20,000 USDC in total.
Onboarding must show that additive capacity rather than suggesting one shared
10,000 allowance. Status must identify which Petal/account budget applies.

A wallet-wide ceiling would instead make those grants compete for shared capacity.
It may be useful, but is a new owner-visible constraint requiring an explicit
product decision. It must not be silently introduced as an implementation fix.
Ceilings for individual exact assets do **not** bound the combined capacity of
26 different assets or unify stablecoins across contracts/chains. No cross-token
pool or prices are being reintroduced.

For now, preserve budget identity across routes/retries/rearm, and make package
replacement and re-grant semantics explicit and tested. An update must not quietly
refresh capacity under an apparent continuation of the same consent. Fix that
identity/lifecycle issue directly rather than relying on a second accounting layer.

If shared ceilings are later selected, retain per-Petal limits alongside them,
show both in review/status, and use atomic authenticated reservation accounting.
Design history retention and unresolved reservations carefully: rolling-window
signed-volume accounting is not outstanding-exposure tracking. No journal schema,
checkpoint chain or wallet-wide aggregation is required by this revision.

## Workstream 7: production hardening

Prioritize observed correctness failures and the release-shaped end-to-end test.
Performance work needs measurement; do not add checkpoint chains or status
indexes speculatively. The table is a backlog, not a first-release gate.

| Item | Owner |
|---|---|
| Measure reservation cost with realistic history. Optimize only if needed, preserving authenticated history and rolling-window semantics; no prescribed checkpoint design. | Broker |
| Confirm existing standing-grant counter bounds and rate backstops; retain checked arithmetic and fail closed on overflow. | Broker, Machine |
| Make the Solana RPC for SOL verification configurable and authenticated, not hardcoded public mainnet. | Broker |
| Typed error codes across Machine and Broker. No `message.contains("APPROVAL_EXPIRED")`. | Machine, Broker |
| Measure prepared-operation status lookup; add an index only if scans are a demonstrated problem. | Machine |
| Confirm expired-approval renewal in strict prepared mode with a test. | Machine |
| `subject_declares_operation_class` must select by claim class, not first match across the package when selecting reusable coverage; review this against the actual revision. | Broker |
| Wire the Broker JS checks (`test-session-review-summary.cjs`, `test-wallet-continue.cjs`) into CI. | Broker |
| Audit the effect of enabling `serde_json/arbitrary_precision` workspace-wide on JCS digests. | Broker |
| Persona end-to-end test against real Broker and Signer in CI, not only the opt-in Polymarket script. | Machine |

## Petal migration plan

This is a coverage backlog, not a promise of zero-prompt support for every Petal
in the next release. First migrate Polymarket incrementally, then one additional
Petal (prefer a narrowly bounded EIP-3009 use). A new protocol may need a small
Broker verifier. Leave unrelated existing flows intact; Signer gains no economics.

| Order | Petal | Needs | Approvals after (within allowance) |
|---|---|---|---|
| 1 | polymarket | Correct release catalog; typed results from existing verifier; shared helpers where useful. No wholesale rewrite or new link registry. | 0 per BUY; SELL exact (P7) |
| 2 | venice-x402 | SDK bump off `sign_hash`; `auth` SIWE profile; EIP-3009 top-up profile | 0 (was about 13 per hour) |
| 3 | gasless | SDK bump; EIP-3009 profile with the reviewed receiver | 0 per relay |
| 4 | near | WS4; recipient decision | 0 per swap |
| 5 | hyperliquid | WS5 agent-session member; P9 for transfers; delete the private claim and nonce machinery in favour of `sign_or_resume` | 0 per order after onboarding |
| 6 | privacy-pools | Later protocol-specific review of deposit and withdrawal authority. Zero wallet debit is not proof of zero economic effect. | Only reviewed covered operations; no generic `none` exemption |
| 7 | pendle | Deferred: needs a separately designed bounded protocol integration (P4). | Existing exact review |

Per-Petal acceptance:

- With the built WASM and real isolated Machine, Broker and Signer, two
  distinct covered actions need zero additional ceremonies, with exact
  ledger charges recorded.
- Retries and restart/rearm do not double-charge.
- An over-limit action requires exact review before signing.
- An action outside every profile requires exact review.
- A mutated field outside approved scope cannot sign automatically.
- Malformed input, invalid provenance and mismatched signing bytes are rejected
  outright, without an approvable fallback.
- Assurance labels match the actual verifier assumptions; app-reported limits
  are not described as independent maximum-exposure enforcement.
- Trader/Degen coverage is explicitly opted in; Institutional still requires
  individual approval.
- New routes, retries and rearm preserve usage; package replacement cannot
  silently present refreshed capacity as continuation of the old allowance.

## Delivery order and ownership

1. **Release readiness (Machine, Broker, Polymarket, SDK pins):** validate the
   real catalog and fresh-install Chrome onboarding, covered actions without
   further prompts, browser rearm and accurate labels/status. Record exact
   built revisions. Existing Signer work is integrated without new economics.
2. **Small cleanup (Broker, SDK, Machine):** typed results from the existing
   Polymarket verifier, shared helpers justified by real duplication, and
   catalog metadata for existing supported capabilities.
3. **One additional Petal:** demonstrate its actual covered action with real
   isolated Broker/Signer and negative tests. Add only the verifier needed.
4. **Reassess:** decide whether recurring integration duplication warrants a
   bounded evaluator. Shared wallet ceilings and approval/consumer accounting
   are separate decisions, not dependencies of steps 1–3.

Do not implement speculative schemas, registries, macros or tracking stores to
complete the future sketches. No production line-count estimate is a commitment;
keep each change tied to an observable user flow or a tested invariant.

## Out of scope

- A generic profile evaluator in the first delivery.
- Automatic approve/consumer accounting and outstanding-allowance tracking.
- Wallet-wide asset ceilings without a separate product decision.
- New linked-address registries or wholesale prepared-action rewrites.
- Simulation.
- An exposure model for open venue orders.
- Composing several approvals into one ceremony.
- Netting across assets.
- Ceilings across separate wallets, or across different assets (a combined
  dollar cap would need prices).
- Settlement proofs.
- A general-purpose scripting language for profiles.
- Changing custody, Signer counters or replay protection.

## Later decisions

1. Which additional Petal provides the smallest useful second integration?
2. Does measured duplication justify a bounded profile evaluator after that?
3. Should independent per-Petal budgets gain an optional shared wallet ceiling?
4. What protocol-specific guarantees would permit automatic approval/consumer
   flows without introducing a general authority-tracking subsystem?
5. How can a NEAR quote-derived recipient be independently bound? Until answered,
   do not describe that path as protocol-verified.
