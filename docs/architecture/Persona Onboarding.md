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
explicit choice. No wallet named `main` is assumed. Account 0 is the current
supported account for automatic sessions.

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

The initial automatic compiler covers fee-free Polymarket BUY orders on
account 0 of the selected existing wallet, using `polygon:pusd`. It requires the updated Polymarket order
accounting package to be published and adopted in the installer catalog; the
currently pinned v0.1.6 package supplies no positive debit claims and therefore
falls back to exact approval. Publishing that package and updating its immutable
release/hash pins are separate rollout gates. Other Petal classes, SELL shares,
builder fees, funding and withdrawals retain exact review.

Profiles allow at most 4,096 signed actions/signatures across a session. Daily
caps use a rolling 24-hour window measured when signing authority is reserved;
they bound gross authorized amounts rather than venue settlement timing or
realized losses. Lifetime collateral is capped at the daily amount times the
rounded-up number of days. Open or uncertain signed orders retain lifetime
usage, even after their authorization ages out of a rolling window. Venue settings may further narrow
these limits. Existing venue choices are preserved.

Dollar suggestions cover only nominal supported stablecoin collateral, such as
USDC or pUSD. They do not represent total-wallet USD exposure or an independently
verified valuation of arbitrary calldata, native ETH/SOL or unpriced assets.
Unsupported scopes require exact approval or separately reviewed unit limits.
A shared budget must be part of signed authority before separate grants can be
presented as sharing a cap. Status comes from Broker, not from saved preferences.

The frozen Machine-client PersonaSessionProposal contains exact
SealedApprovalTerms, the preparation operation ID and a reviewed plan-facts
digest. Config preferences are not signing capabilities.
Retrying an interrupted ceremony reconciles its original frozen terms; changing
preferences cannot silently widen an existing grant.

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

Native transfers retain exact approval. The experimental `SystemSession`
selector is refused, including explicit `--proposal` files. The first release
reuses the existing Petal selector for fee-free Polymarket BUYs; it does not add
a new wallet-wide signature authority.

Broker owns economic accounting. The complete descriptor remains in Broker's
approval metadata and signed review and is committed through the existing
opaque request nonce. Signer receives ordinary Petal Sealed Approval terms and
enforces its existing structural counters, expiry, revocation and replay; it
has no asset-conversion or shared spending ledger. Machine forwards the full
order witness on use and preserves it in its durable retry identity. Broker
reconstructs the signed order and checks that its gross maker amount equals
the charged pUSD debit. This checks signing terms, not settlement or a live USD
valuation, and does not contain the economic impact of a compromised Broker.

The extension negotiates Machine–Broker 1.9 while preserving Broker–Signer
1.6. The combined Polymarket clear-signing/accounting package must be published
and pinned before default onboarding can consume it. Other message operations
keep their existing exact-approval path.

Local grants are boot-bound. A saved preference does not rearm them after
logout/restart. An orphaned grant requires inspection and explicit stop before
fresh reviewed activation; repeating activation does not reset a consumed
budget. Broker's journal is the economic source of truth; Signer backups do
not contain that journal. Keep its history and existing audit/recovery fences.
Completed signing results remain recoverable after stop/revocation. Confirmed
remote revocations are recorded locally, so repeated stop does not resubmit
already-completed revocations with a new server timestamp.
