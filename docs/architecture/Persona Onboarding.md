# Persona onboarding

`bloom init` opens the real local browser onboarding flow. `bloom onboard`
opens or resumes it after install; `bloom onboard --no-open` prints the URL for
Firefox or another browser. First-install packaging starts it as the enrolled
login user: macOS after service readiness, Linux at the next graphical login
once new group membership applies. Repairs and upgrades do not reopen setup.
`--if-needed` skips the automatic welcome once persona and setup choices are
saved; it does not imply that wallet policy or session authority is active.

The browser reuses the unchanged Broker ceremony stylesheet, logo and single
panel layout. It discovers existing wallets from the running Machine/Broker
projection. One wallet is selected automatically; multiple wallets require an
explicit choice. No wallet named `main` is assumed. The convenience selection
uses account 0 by default; explicit account and selection inputs support the
existing EVM/SVM accounts named by exact public KeyRefs.

Persona setup saves preferences for the explicitly selected existing wallet
and opens only policy/session approval ceremonies. It has no wallet creation,
seed-import, registration or migration endpoint, never opens a separate home,
and cannot fall back to a local daemon. No wallet found means this is the wrong
installation or normal wallet setup has not yet completed; custody setup remains
separate. Package owners and per-wallet venue settings are not rewritten by
persona selection. A change to global persona preferences disables managed
persona sessions before saving; unrelated manual authority is preserved.

Every mutation rechecks live wallet membership. A removed wallet never silently
switches to another. Unsupported installed services are reported explicitly;
reading an existing wallet does not prove that persona APIs are available.
Returning from an approval reconciles its actual result; refreshing creates no
authority.

The HTTP server binds only `127.0.0.1` on an ephemeral port with a random 256-bit
path capability, exact Host and POST Origin checks, JSON-only bounded mutation
requests, no CORS, no caching, no referrer and a restrictive CSP. It stops after
30 minutes or 15 idle minutes. It never stores private key or passkey input.
`bloom init --no-browser` retains scripted setup; explicit `--persona` flags also
retain the terminal/script path.

The persona picker offers Custodian, Trader and Degen. Custodian is the default and
retains the current transaction approval behavior. Config records suggestions,
not grants: selecting Trader or Degen cannot authorize an action by itself.
Legacy homes with no persona keep their current choices, venue settings and
signed authority. Repeating init preserves an existing persona and custom
limits unless the owner explicitly changes them.

The suggested profiles are Trader ($100 per action, $1,000 per day, 24 hours)
and Degen ($1,000 per action, $10,000 per day, 7 days). An explicit scripted
selection and optional overrides use:

```sh
bloom init --persona trader --persona-per-action-usd 50 --persona-daily-usd 500 --persona-session-seconds 86400
bloom wallet persona activate main --account 0
bloom wallet persona set main trader --per-action-usd 50 --daily-usd 500 --session-seconds 86400
bloom wallet persona status main
bloom wallet persona stop main --reason 'pause trading'
```

New/import onboarding invokes activation after its policy is applied.
Activation compiles a concrete proposal from fresh authenticated wallet/key,
policy and immutable package provenance. The owner reviews exact accounts,
operation classes, destinations, asset limits, counts, fees and validity before
any grant becomes active. Distinct package scopes can need separate approval
ceremonies. A policy-update approval is not a session activation.

The convenience compiler proposes Polymarket BUY for the explicitly selected
existing EVM account. `bloom wallet persona activate WALLET --selection FILE`
compiles arbitrary certified Petal and native members sharing one USD pool;
`--proposal FILE` accepts already-frozen exact public terms. Selection is not
authority: Broker verifies every key, package, route, class and native scope.
Updated immutable Petal artifacts must be published and installer-certified
before their generic effects are eligible; old packages retain owner approval.

The [operator selection example](../examples/generic-session-selection.json)
combines an EVM native/ERC-20 member and an unrelated SVM Petal member, with
ETH, EVM USDC, SOL and SVM USDC in their shared permitted asset set. It contains
synthetic keys/package/provenance digests and a demonstration recipient: replace
all of those with the exact public projections and intended recipients before
submitting. It is a schema example and grants no authority as shipped.

```sh
bloom wallet persona set main trader --per-action-usd 100 --daily-usd 1000
bloom wallet persona activate main --selection ./reviewed-selection.json
bloom wallet persona status main
```

The browser session step accepts the same JSON file. Each member's Broker
ceremony displays the full pool and all member templates, asset scope, prices,
raw caps and fixed allocations. Finish each member ceremony and repeat activation
until the pool reports active. Partial approval is not automatic authority.

A selection JSON contains `assets` (canonical `AssetId` entries) and `members`.
Every member supplies `account`, exact `key_ref`, `subject`, `selector`,
`provenance_digest` and `allowed_crypto_suites`. Copy these public identities
from the authenticated wallet/account and installer provenance projections.
Petal selectors carry the immutable package/routes/classes. Native
`system_session` selectors additionally require explicit recipient allowlists,
networks and supported transfer actions. Empty native raw-cap arrays request
fixed caps computed from the review quote; explicit caps remain narrower
owner-selected restrictions. Native SPL and automatic Polymarket SELL remain
outside this release.

The compiler asks Broker for release-approved metadata and review quotes,
then suggests fixed raw-token caps with exact downward rounding. It freezes
all member proposals before preparing the first ceremony. Repeat the same
selection after each ceremony to activate the remaining members; interrupted
and exhausted pools retain their original descriptor and cannot silently reset.
Changing assets, members, profile, package or pricing requires stopping the
retained pool and reviewing new authority.

Profiles allow at most 4,096 operations/signatures across the pool, allocated
into fixed independent member backstops. The per-action, lifetime and rolling
24-hour limits are actual integer USD microdollars enforced by Broker. Broker
uses keyless CoinGecko first, then keyless DefiLlama, accepting provider timestamps
at most 15 minutes old. Missing prices retain ordinary owner approval; no
stablecoin is assumed to equal USD 1. Gross outgoing amounts and maximum
wallet-paid costs count; receipts never replenish usage.

Generic Petal effects remain trusted declarations, not independent containment
of a dishonest Petal/Machine. Native supported transfer bytes and Polymarket
BUY retain their stronger required verification. Signer independently limits
signature volume/duration and owns custody; no prices or economic state enter
Signer. Status comes from Broker rather than saved persona preferences.

Setup settings obligations are versioned journals recorded before package acquisition,
binding main/account 0, exact package hash, desired body and digest, route and
setup-config revision. Replay refuses package/template/config changes and
retains the journal for explicit reconciliation. Legacy empty markers also
require reconciliation because their original revision cannot be established. Partial
provisioning failures therefore cannot strand an installed Petal without its
chosen settings. Recovery invokes the same validated route with an immutable
package hash and a host-only initialize-if-absent private store. Every guest
put is atomic create-only for that invocation: a concurrent owner write wins
without being overwritten. Existing settings reconcile the obligation as
preserved; genuine backend failures keep it pending. Ordinary Petal writes
retain their existing editing behavior. This path changes no guest ABI.

Native EVM currency/ERC-20 and mainnet SOL transfers use explicit System
provenance through the same lifecycle, with supported single-transfer byte
verification and immutable recipient/raw-unit caps. Unsupported native formats
retain exact approval. A native verifier/context refusal steps up only after
Broker authoritatively reports no retained operation; ambiguous or unreadable
operation status keeps the original attempt pinned. Machine cannot borrow a Petal identity for native work.

The extension negotiates Machine–Broker 1.10 and structural Broker–Signer 1.8.
Broker retains the descriptor, valuations and journal; Signer receives existing
Petal or structural-only System scopes. Stop first persists local disable,
then atomically fences the Broker pool before revoking its members. Completed
signatures remain recoverable and already signed spending stays charged.

Local grants are boot-bound. A saved preference does not rearm them after
logout/restart. An orphaned grant requires inspection and explicit stop before
fresh reviewed activation; repeating activation does not reset a consumed
budget. Broker's journal is the economic source of truth; Signer backups do
not contain that journal. Keep its history and existing audit/recovery fences.
Completed signing results remain recoverable after stop/revocation. Confirmed
remote revocations are recorded locally, so repeated stop does not resubmit
already-completed revocations with a new server timestamp.
