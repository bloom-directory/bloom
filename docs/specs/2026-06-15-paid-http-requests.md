# Bloom Paid HTTP Requests

**Status:** draft  
**Date:** 2026-06-15  
**Owners:** —  
**Audience:** Bloom engineers, product, protocol collaborators

## 1. Summary

Bloom should support paid machine-readable HTTP resources through the same
filesystem-native workflow it uses for wallets and transactions:

```sh
echo 'GET https://data.vendor.com/alpha/signal' > /bloom/requests/new
cat /bloom/requests/latest/plan.md
echo y > /bloom/requests/latest/confirm
cat /bloom/requests/latest/response/body
cat /bloom/requests/latest/receipt.json
```

The user-facing concept is **a request**, not a payment protocol. Bloom should
not expose top-level `/bloom/x402` or `/bloom/mpp` folders. x402, Tempo MPP, or
future paid-resource protocols are implementation details detected during the
HTTP 402 challenge flow and surfaced only as metadata inside a staged request.

Spending policy should remain wallet-owned. Existing Bloom policy lives at:

```text
~/.bloom/keystore/<wallet>/policy.toml
```

and is exposed through the VFS as:

```text
/bloom/wallets/<wallet>/policy.toml
```

Paid HTTP extends that policy instead of introducing a separate budget authority
under `/bloom/requests`.

If exactly one wallet exists, `/bloom/requests/new` defaults to that wallet. If
multiple wallets exist, the request must specify `wallet = "..."` or use a
future daemon/user default.

## 2. Goals

1. Add a first-class VFS surface for HTTP requests, including paid HTTP 402
   flows.
2. Preserve Bloom's safety invariant: **reading files must never spend money**.
3. Require staged, inspectable `plan.md` and `policy_check.json` before any
   signing, payment, channel top-up, or retry-with-credential.
4. Reuse existing per-wallet policy as the canonical authorization layer.
5. Hide protocol names from the primary filesystem UX. Users should create
   requests; Bloom may internally use x402, MPP, or another adapter.
6. Support both one-time paid requests and session/channel-style repeated usage.
7. Produce durable receipts and audit artefacts for every paid request.
8. Provide a CLI fallback with the same semantics for environments without the
   mount.

## 3. Non-goals

- No top-level `/bloom/x402` or `/bloom/mpp` namespaces.
- No automatic spend from `cat`, `ls`, `stat`, `open`, preview rendering, or
  daemon metadata refresh.
- No protocol-specific SDK exposed to the user as the primary API.
- No policy authority duplicated under `/bloom/requests/budgets`.
- No silent wallet selection when more than one wallet is present.
- No private key, credential, passphrase, or bearer-token material readable
  through the VFS.
- No server-side paid endpoint support in the first client milestone. Server
  middleware can come later.

## 4. Existing policy model

Bloom currently stores policy per wallet. The keystore layout is:

```text
~/.bloom/keystore/<wallet>/
├── address
├── pubkey
├── kind
├── encrypted.key
└── policy.toml
```

The VFS exposes the same policy as:

```text
/bloom/wallets/<wallet>/policy.toml
```

The parsed policy type is `bloom_proto::policy::Policy`, and transaction staging
uses `bloom_tx::policy_engine` to produce `policy_check.json` and block or warn
on policy violations.

Paid HTTP should reuse this pattern:

- request creation stages an operation;
- stage-time evaluation produces `plan.md` and `policy_check.json`;
- confirmation performs the side effect;
- hard policy denials block confirmation;
- soft warnings require the configured override sentinel.

## 5. User-facing VFS

Add a protocol-neutral request tree:

```text
/bloom/requests/
├── new                         # writable sink: create request
├── latest -> pending/<id>       # symlink/ref to newest request by this daemon
├── pending/
│   └── <id>/
│       ├── request.toml
│       ├── request.http
│       ├── status
│       ├── plan.md
│       ├── policy_check.json
│       ├── payment_method.json
│       ├── challenge.raw
│       ├── challenge.json
│       ├── credential.json      # redacted/public metadata only
│       ├── confirm              # writable side-effect sink
│       ├── cancel               # writable side-effect sink
│       ├── response/
│       │   ├── status
│       │   ├── headers.json
│       │   ├── body
│       │   └── body.sha256
│       ├── receipt.json
│       └── audit.json
├── sent/
│   └── <id>/...
└── failed/
    └── <id>/...
```

The primary flow is intentionally shell-native:

```sh
echo 'GET https://data.vendor.com/alpha/signal' > /bloom/requests/new
cat /bloom/requests/latest/plan.md
echo y > /bloom/requests/latest/confirm
cat /bloom/requests/latest/response/body
```

Richer requests can be TOML:

```toml
method = "POST"
url = "https://api.example.com/inference"
wallet = "research"
max_amount_usd = "0.05"

[headers]
content-type = "application/json"

[body]
inline = '{"prompt":"summarize this document"}'
```

or HTTP-message-like:

```http
POST https://api.example.com/inference
content-type: application/json

{"prompt":"summarize this document"}
```

The parser should accept the simple one-line form first:

```text
GET https://data.vendor.com/alpha/signal
```

and later support inline attributes:

```text
GET https://data.vendor.com/alpha/signal wallet=research max_amount_usd=0.05
```

## 6. Wallet defaulting

Request staging needs a paying wallet.

Selection rules:

1. If the request explicitly specifies `wallet`, use it.
2. Else if exactly one wallet exists in the keystore, use that wallet.
3. Else if a future daemon-level default wallet is configured, use that wallet.
4. Else fail closed and create a failed request with a readable error.

Multiple-wallet failure should be obvious:

```text
/bloom/requests/failed/<id>/error.txt
```

Example content:

```text
No wallet specified and multiple wallets are available.
Set wallet = "<name>" in the request or configure a default wallet.
Available wallets: alice, research, treasury
```

Never guess based on wallet order when multiple wallets exist.

## 7. Payment protocol detection

Bloom performs an unpaid probe first. For normal free HTTP resources, this may
return the final response immediately. For paid resources, the server returns
HTTP `402 Payment Required` with protocol-specific challenge material.

Bloom then detects the adapter from headers/body. Internally this may map to:

```rust
enum PaidHttpProtocol {
    X402,
    Mpp,
    Unknown,
}

enum PaidHttpIntent {
    OneTime,
    Session,
    Stream,
}
```

The selected protocol is recorded as metadata, not as a filesystem namespace:

```json
{
  "protocol": "mpp",
  "intent": "session",
  "network": "tempo",
  "asset": "pathUSD",
  "merchant": "data.vendor.com"
}
```

This belongs at:

```text
/bloom/requests/pending/<id>/payment_method.json
```

## 8. Request lifecycle

```text
write /bloom/requests/new
        │
        ▼
parse request
        │
        ▼
select wallet
        │
        ▼
unpaid HTTP probe
        │
        ├── 2xx/3xx/free response ──► sent/<id>/response/*
        │
        └── 402 challenge
                │
                ▼
        detect protocol + normalize challenge
                │
                ▼
        evaluate wallet policy
                │
                ▼
        write pending/<id>/{plan.md,policy_check.json,...}
                │
                ▼
        wait for confirm
                │
                ▼
        sign/pay/open-channel/sign-voucher as required
                │
                ▼
        retry HTTP request with payment credential
                │
                ▼
        write response, receipt, audit
                │
                ▼
        move pending/<id> → sent/<id> or failed/<id>
```

Important: an unpaid/free request can complete without `confirm`, because no
spending or signing occurs. A paid request must stage and wait for confirmation
unless wallet policy explicitly allows auto-confirm for that exact case.

## 9. Policy extensions

Extend existing `wallets/<name>/policy.toml` with payment-specific sections.
The exact schema can evolve, but this shape is a good starting point:

```toml
[caps]
per_tx_usd = 100
per_day_usd = 1000
require_confirm_above_usd = 25

[automation]
auto_confirm_below_usd = 0.01

[payments]
enabled = true
require_plan = true
require_confirm_for_new_merchant = true

[payments.http]
per_request_usd = 0.05
per_day_usd = 5.00
allow_hosts = ["data.vendor.com", "fal.mpp.tempo.xyz"]
deny_hosts = []

[payments.sessions]
enabled = true
max_deposit_usd = 2.00
max_session_spend_usd = 10.00
require_confirm_to_open = true
require_confirm_to_top_up = true

[payments.assets]
allow = ["USDC", "pathUSD"]
deny = []

[payments.networks]
allow = ["base", "tempo"]
deny = ["ethereum-mainnet"]
```

Policy evaluation should merge existing generic caps with payment-specific caps
using the existing “most restrictive wins” principle.

Examples:

- `caps.per_tx_usd = 100` and `payments.http.per_request_usd = 0.05` means a
  paid HTTP request is capped at `$0.05`.
- `payments.sessions.max_deposit_usd = 2.00` limits channel open/top-up size.
- `payments.sessions.max_session_spend_usd = 10.00` limits cumulative spend
  against a channel/session.

## 10. Confirm semantics

`confirm` is the only normal file write that can spend money for a paid request.

Accepted values:

```text
y
yes
confirm
```

Soft policy warnings require the wallet policy override sentinel, currently
`override` by default unless configured otherwise.

Hard policy denials must reject confirmation.

Confirmation may perform different concrete actions depending on the staged
plan:

| Plan action | Side effect on confirm |
|---|---|
| one-time paid request | sign/pay and retry request |
| existing session voucher | sign voucher and retry request |
| open session/channel | submit/open deposit tx, then retry with voucher |
| top up session/channel | submit top-up tx, then retry with voucher |
| free request | no confirm required |

`plan.md` must state exactly which action confirmation will perform.

## 11. Session/channel state

MPP-style sessions and future payment channels need durable state, but this
state should still not create protocol folders.

Use a protocol-neutral internal state surface under requests, and optionally a
read-only operational surface later:

```text
/bloom/requests/sessions/
└── <session-id>/
    ├── merchant
    ├── wallet
    ├── network
    ├── asset
    ├── deposited
    ├── spent
    ├── remaining
    ├── status
    ├── vouchers.jsonl
    ├── topup       # writable side-effect sink only when a fresh scoped challenge is staged
    └── close       # writable side-effect sink only when a fresh scoped challenge is staged
```

If this feels too payment-specific for `/requests`, a later top-level
`/bloom/sessions` may be acceptable, but not `/bloom/mpp`.

## 12. Artefacts

### `plan.md`

Human-readable and safe to share. It should include:

- method and URL;
- wallet;
- merchant/realm;
- detected payment method;
- asset/network;
- one-time vs session action;
- cost now;
- maximum possible cost for this confirmation;
- policy result summary;
- exact side effect of writing `confirm`.

Example:

```md
# Payment plan

Request: GET https://data.vendor.com/alpha/signal
Wallet: research
Merchant: data.vendor.com
Payment method: paid_http:mpp/session
Network: tempo
Asset: pathUSD
Cost now: $0.01
Session: existing, remaining $1.42

Policy: allowed
- payments.http.per_request_usd: pass, $0.01 <= $0.05
- payments.assets.allow: pass, pathUSD allowed
- payments.networks.allow: pass, tempo allowed

On confirm: sign an EIP-712 session voucher and retry the HTTP request.
No on-chain transaction will be submitted.
```

### `policy_check.json`

Machine-readable policy evaluation, following the existing transaction pattern.

### `challenge.raw` and `challenge.json`

Raw protocol challenge and normalized Bloom challenge. Useful for debugging
without requiring the user to understand protocol-specific folders.

### `credential.json`

Redacted metadata only. Never expose a reusable bearer credential, private key,
raw signed voucher if replayable, raw `Authorization` value, signed transaction,
or secret token unless it is specifically safe as a receipt/public proof.

### Wallet signing and passkey unlocks

Tempo MPP confirmation always obtains the signer through Bloom's unlocked
keystore path (`Keystore::signer(wallet)`). Passkey-gated wallets are supported
when their foreground `unlock-passkey` / `unlock_passkey` flow has populated the
same unlocked signer cache; they are not a separate unsupported wallet type.
Locked local wallets fail before MPP credential creation. Locked passkey wallets
fail with an explicit instruction to run the foreground passkey unlock flow before
writing `confirm`.

### `receipt.json`

Normalized receipt with raw receipt nested if available:

```json
{
  "request_id": "req_...",
  "wallet": "research",
  "merchant": "data.vendor.com",
  "amount": "0.01",
  "currency": "pathUSD",
  "network": "tempo",
  "protocol": "mpp",
  "intent": "session",
  "tx_hash": null,
  "session_id": "...",
  "response_sha256": "...",
  "raw": {}
}
```

## 13. Rust crate shape

Suggested crates:

```text
crates/bloom-paid-http/     # request lifecycle, challenge normalization, traits
crates/bloom-paid-x402/     # x402 adapter
crates/bloom-paid-mpp/      # MPP/Tempo adapter
crates/bloom-vfs/           # RequestsHandler integration
```

Core trait:

```rust
#[async_trait]
pub trait PaidHttpAdapter {
    fn name(&self) -> &'static str;
    fn detect(&self, response: &HttpResponse) -> bool;
    fn parse_challenge(&self, response: &HttpResponse) -> Result<PaidChallenge>;
    async fn prepare(&self, ctx: PrepareContext) -> Result<PaymentPlan>;
    async fn confirm(&self, ctx: ConfirmContext) -> Result<PaymentCredential>;
    async fn retry(&self, ctx: RetryContext) -> Result<PaidHttpResponse>;
}
```

The generic lifecycle owns staging, policy, artefacts, and VFS semantics. The
adapters only own protocol-specific parsing/signing/credential behavior.

## 14. CLI fallback

The CLI should mirror VFS semantics:

```sh
bloom request new 'GET https://data.vendor.com/alpha/signal'
bloom request plan latest
bloom request confirm latest
bloom request body latest
bloom request receipt latest
```

With explicit wallet:

```sh
bloom request new --wallet research 'GET https://data.vendor.com/alpha/signal'
```

With dry-run:

```sh
bloom request new --dry-run --wallet research 'GET https://data.vendor.com/alpha/signal'
```

`--dry-run` should never spend, sign, open a session, top up a channel, or send a
credential. It may perform the unpaid probe and stage a plan.

## 15. Security invariants

1. Reads never spend.
2. Metadata refresh never spends.
3. `confirm` is the normal spend boundary.
4. Auto-confirm is policy-gated and must be visible in `plan.md` and
   `policy_check.json`.
5. Multiple-wallet environments fail closed unless wallet selection is explicit
   or a default is configured.
6. Wallet policy remains the authority for spending limits and allow/deny rules.
7. Protocol adapters must not expose secrets as readable files.
8. Receipts and audit trails are durable.
9. Paid request retries must bind credentials to the intended request whenever
   the underlying protocol supports it.
10. Session/channel spend must track cumulative amounts, not only per-request
    voucher amounts.

## 16. Decisions

Resolved for the implementation pass:

1. Implement all milestones in this spec, with tests for the introduced VFS,
   policy, adapter, wallet-default, and CLI behavior.
2. Add a daemon-level `default_wallet` in `config.toml`. It is used after an
   explicit request wallet and before the single-wallet fallback. When the first
   wallet is created/imported and no default is configured, Bloom sets it as the
   default and prints an obvious message with the config path.
3. Retain successful free HTTP responses in the same `/bloom/requests/sent/<id>`
   tree as paid requests.
4. Implement both x402 and Tempo MPP challenge handling/adapters while keeping
   protocol names as request metadata only, never top-level VFS namespaces.
5. Keep session/channel state under `/bloom/requests/sessions`.
6. `credential.json` contains redacted/public metadata only. Raw signed vouchers,
   bearer credentials, private keys, passphrases, or replayable secrets must
   never enter the VFS.

Deferred question:

- Named policy profiles under each wallet may be considered later:

  ```text
  /bloom/wallets/<wallet>/policies/research.toml
  /bloom/wallets/<wallet>/policies/media.toml
  ```

## 17. Milestones

### Milestone 1 — request staging

- Add `/bloom/requests/new`.
- Parse one-line and TOML request forms.
- Select wallet by explicit field or single-wallet default.
- Perform unpaid HTTP probe.
- Store free responses or stage paid challenges.
- Generate `plan.md` and `policy_check.json`.

### Milestone 2 — policy extensions

- Extend `Policy` with `[payments]` sections.
- Evaluate host, asset, network, per-request, daily, and session caps.
- Render payment policy results in `plan.md`.

### Milestone 3 — first paid protocol adapter

- Implement one adapter first, likely whichever has the easiest test endpoint.
- Keep adapter-specific details inside `payment_method.json`, `challenge.*`, and
  receipt raw fields.

### Milestone 4 — sessions/channels

- Add durable session/channel state.
- Enforce cumulative spend caps.
- Support top-up and close flows with explicit confirmation.

Implementation note: the Tempo MPP adapter uses the real `mpp` Rust SDK
(`TempoProvider`/`TempoSessionProvider`) for Payment challenge parsing, Tempo
charge/session credential creation, and Authorization/Payment-Receipt formatting.
Tempo MPP charges and sessions are normalized and policy-gated (including
cumulative session-spend caps) and share the same confirm path as x402: signing
runs only after confirmation and policy approval, x402 keeps its keystore signer
with a staged request-id–bound EIP-3009 nonce, the paid retry is a real HTTP
request, and a failed retry (HTTP >= 400 or a signing/settlement error)
transitions the request to the `failed` state. Tempo MPP signing uses
`Keystore::signer(wallet)`, so passkey-gated wallets work after the foreground
`unlock_passkey` flow has unlocked the signer and locked passkey wallets fail
before credential creation with an unlock-specific error.

Only redacted credential metadata, receipts, audit entries, and cumulative
session spend are written; no raw Authorization headers, signed transactions,
voucher signatures, or other replayable secret material are stored in the VFS.
Durable Tempo MPP channel reuse, top-up, and close are **not** implemented: the
adapter constructs a fresh `TempoSessionProvider` per confirm and records only
redacted session metadata, and no `mpp-rs` channel open/deposit/top-up/close
primitives are linked into `bloom-vfs`, so durable provider channel
registry/reuse, efficient repeated vouchers, and top-up/close from persisted
channel state are deferred product work rather than implemented behavior. A
settled session is therefore marked `settled_no_durable_channel` (never `open`)
to avoid overclaiming a reusable channel. The `topup` and `close` control
files are not advertised as writable controls and direct writes fail with a
precise unavailable-until-fresh-challenge error instead of synthesizing
credentials from redacted metadata; top-up must be confirmed from a fresh Tempo
MPP session challenge and close requires a live `TempoSessionProvider` channel
registry.

### Milestone 5 — CLI parity

- Add `bloom request` commands matching VFS semantics.
- Add dry-run support.
- Add receipt/body helpers.

## 18. Recommendation

Implement `/bloom/requests` as the only user-facing paid HTTP surface. Keep
payment protocol selection internal and metadata-only. Extend existing
per-wallet policy rather than adding a separate budget tree. Default to the only
wallet when exactly one exists; otherwise fail closed and ask for an explicit
wallet.

This gives Bloom the desired UX:

```sh
echo 'GET https://data.vendor.com/alpha/signal' > /bloom/requests/new
```

without baking x402, MPP, or any future protocol name into the filesystem model.
