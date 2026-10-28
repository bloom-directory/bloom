# Persona onboarding

The current economic contract is [recurring token allowances](../specs/2026-10-26-generic-evm-svm-sessions.md).

Wallet creation offers Continue to setup. `bloom onboard` opens or resumes the local wizard for an existing wallet; `--no-open` prints its URL. The wizard selects the actual wallet/account from authenticated projections, saves Institutional/Trader/Degen preferences, then embeds the Broker's owner reviews in order. Returning from a ceremony reconciles its actual result before advancing. Refresh never creates authority. The final page states completion only after the required grants are active.

Institutional retains individual approval. Trader uses independent token allowances per rolling 24 hours; Degen uses larger allowances per rolling seven days. Standing permissions last until revoked. Picking a radio button grants nothing; policy and exact app/account/token amounts require passkey consent. The legacy `custodian` spelling remains accepted for Institutional.

The convenience automatic integration is Polymarket BUY on the selected EVM account, using the exact Polygon pUSD identity. Degen additionally proposes native-wallet ERC20 transfers to any recipient on configured Ethereum and Polygon, with independent seven-day token and gas allowances. Other integrations need installer-certified effects and explicitly reviewed supported scopes. Existing stronger profiles remain enforced. Account 0 is a convenience, never an alias for a different key or wallet.

```sh
bloom init --persona trader
bloom wallet persona set WALLET degen
bloom wallet persona activate WALLET --account 0
bloom wallet persona status WALLET
bloom wallet persona stop WALLET --reason 'pause trading'
```

Dollar and duration override flags are retired. Config schema 2 stores the persona and its rolling period, not a dollar amount. Old unshipped USD configs/grants fail closed and require choosing a persona again in a fresh dev installation. Existing audit and recovery data must be retained.

Advanced operators can compile `--selection FILE` or review already frozen `--proposal FILE` terms. The [selection example](../examples/generic-session-selection.json) contains synthetic public identities and grants no authority as shipped. Selections contain exact assets, member KeyRefs, subjects/selectors, provenance and crypto suites. Optional `token_allowances` supply per-action/per-window amounts in raw units, required for native fees/transfers or assets without a preset. Preset quantities are converted using trusted deployment decimals with integer arithmetic. No price service is called. Duplicate Petal/account members must combine their routes instead of multiplying budgets.

Each compiled default budget belongs to one member. Routes within that grant share accounting; different Petals/accounts have independent token capacity. Freeze proposals before any activation RPC. Repeating activation reuses the same reviewed descriptor, including consumed usage. Changed assets, exact amounts or member scopes require stopping retained authority and reviewing replacement consent. Unresolved or orphaned authority remains fenced for explicit recovery.

The signed wallet policy explicitly opts into standing permissions. Local grants use durable-local activation, with boot-activated wallet keys: locking or restarting services may require wallet unlock, but does not reset accounting or require inventing a new grant. Finite/exact approvals retain their existing expiry rules. Signer owns custody, replay and structural rates; Broker owns economic accounting. Generic effects remain assertions by the pinned Petal/Machine. Native transfer bytes and Polymarket BUY witnesses retain their existing stronger checks.

Status reports exact token usage and rolling remaining capacity, including reservations and quarantined signatures. Successful retries reuse their frozen identities; only authenticated no-signature release refunds a reservation. Ordinary window aging restores capacity, including when an external order is still open. Neither stop nor window aging cancels a signed order or external venue permission.

The local bridge uses loopback, a random path capability, exact Host/Origin, bounded JSON mutations, restrictive CSP and idle/absolute timeouts. Secrets/passkey input remain in the Broker-hosted ceremony. No local signing fallback or separate custody home is created by onboarding. Package owners and existing venue settings are preserved; Broker token presets are not venue-dollar settings.

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


Native sessions keep explicit recipients, networks, fees and supported byte verification. Degraded native context steps up only after authoritative absence of a retained operation; ambiguous/unreadable status preserves the original identity. Stop persists local disable, durably fences Broker authority, then revokes the grant. Completed signatures remain recoverable after revocation. Never delete accounting history or rotate an operation to bypass a denial.

An owner can unlock retained local authority with `bloom wallet persona rearm WALLET` (`--approval ID` selects a specific grant). This reuses the sealed-approval passkey ceremony with the unchanged standing terms and a signed rearm purpose. It preserves both Broker usage and Signer counters, refuses stopped/revoked or changed terms, and retains an operation identity across retries. It does not add a wallet-unlock ceremony kind or silently create replacement authority.

Fresh Polymarket settings seed the existing pUSD order-cost ceiling (`max_daily_usd`, a historic setting name) from the persona's token quantity. Degen's Broker seven-day allowance remains stricter than that venue daily ceiling. Saved owner settings are preserved; this is not a new price calculation or Broker dollar budget.
