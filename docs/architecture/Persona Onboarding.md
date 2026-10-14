# Persona onboarding

`bloom init` opens the real local browser onboarding flow. `bloom onboard`
opens or resumes it after install; `bloom onboard --no-open` prints the URL for
Firefox or another browser. First-install packaging starts it as the enrolled
login user: macOS after service readiness, Linux at the next graphical login
once new group membership applies. Repairs and upgrades do not reopen setup.
`--if-needed` skips the automatic welcome once persona and setup choices are
saved; it does not imply that wallet policy or session authority is active.

The browser uses Bloom Broker's ceremony design tokens and components. It saves
persona, limits and Petal choices through the sole Machine daemon's IPC owner,
provisions the same canonical catalog, then launches actual wallet creation or
import, policy review and session activation ceremonies. Secret entry remains
on the Broker origin. Returning from a ceremony explicitly reconciles its
result; refreshing state never creates authority. Unsupported scopes and the
Polymarket package rollout gate remain visible.

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
main/account 0, using `polygon:pusd`. It requires the updated Polymarket order
accounting package to be published and adopted in the installer catalog; the
currently pinned v0.1.6 package supplies no positive debit claims and therefore
falls back to exact approval. Publishing that package and updating its immutable
release/hash pins are separate rollout gates. Other Petal classes, SELL shares,
builder fees, funding and withdrawals retain exact review or require an explicit
separately reviewed proposal.

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

Typed native EVM sessions currently cover Ethereum (chain 1), Polygon (137)
and local development chains (31337). Other EVM networks, including OP Stack
chains, retain exact approval because additional network fees are not covered
by the current maximum-gas-fee projection. Solana retains exact approval.

Native sessions use explicit reviewed asset/fee unit limits, not automatic USD
pricing. A complete frozen proposal can be submitted with
`bloom wallet persona activate main --account 0 --proposal file.json`.

Local grants are boot-bound. A saved preference does not rearm them after
logout/restart. An orphaned grant requires inspection and explicit stop before
fresh reviewed activation; repeating activation does not reset a consumed
budget. Selective Signer archive restore disables grouped grants and permanently
blocks their unrecovered budget descriptors. New session authority needs a
fresh owner-reviewed descriptor. Ordinary SQLite reopening retains usage, and
completed signing results remain recoverable after stop/revocation.
