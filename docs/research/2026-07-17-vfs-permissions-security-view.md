# Issue 114: VFS Permissions & Security view

Status: research recommendation for [issue #114](https://github.com/bloom-directory/bloom/issues/114).

## Recommendation

Build a wallet-scoped inventory of **standing authority and key custody**, not a generic
security score:

```text
/wallets/<wallet>/permissions.json                       canonical snapshot
/wallets/<wallet>/permissions.md                         universal readable view
/wallets/<wallet>/permissions.html                       optional rich view
/wallets/<wallet>/permissions/entries/<permission_id>.json
/wallets/<wallet>/permissions/recovery.{json,md,html}     custody and recovery detail
```

The first screen should answer whether anything needs attention, who can act for the
wallet, what they can do, and how complete the check was:

```text
Permissions & security
2 need attention · 7 standing permissions · Coverage partial · checked 2m ago

Needs attention
┌ Remote access remains ────────────────────────────────┐
│ Hyperliquid agent “bloom-session”                    │
│ Bloom stopped locally · still authorized remotely    │
│ Review →                                             │
└──────────────────────────────────────────────────────┘

Account control
Owner key             Passkey protected
Polymarket wallet     Controlled by owner
Base delegation       None found at block 34,567,890

Spending & trading access
Polymarket Exchange   Unlimited pUSD · Polygon · Revoke →
```

Never render “Secure,” “all clear,” or a 0–100 score. The honest empty state is “No
active permissions found in checked sources.” Coverage is part of the result, not a
footnote.

## Scope and page structure

A permission is durable or reusable authority. Pending one-shot Sealed Approvals,
unsigned drafts, open orders, and transactions awaiting confirmation remain in
[Activity](./2026-07-16-vfs-activity-view.md) and
[Next Moves](./2026-07-16-vfs-next-moves-view.md). They may link to this page when they
create or revoke standing authority.

Use these sections:

1. **Needs attention** — deterministic findings requiring user review.
2. **Account control** — owner signer, EIP-7702 delegate, Hyperliquid multisig, and
   Polymarket deposit-wallet controller.
3. **Spending & trading access** — token/NFT/Permit2 approvals, Bloom standing
   sessions, Hyperliquid API wallets, and builder-fee approvals.
4. **Service access** — credentials that can query, cancel, or submit already-signed
   requests but cannot independently sign value movement.
5. **Safeguards** — wallet kind, passkey protection, signed-policy state, assurance,
   autonomy mode, and policy caps.
6. **Recovery & key custody** — backup facts, passkey-management options, and guarded
   recovery/export ceremonies.
7. **Recent security changes** — permission, policy, credential, backup, and raw-reveal
   events linking to Activity rather than a duplicate timeline.
8. **Coverage & blind spots** — exact chains, block anchors, providers, ranges, errors,
   and facts Bloom cannot observe.

Installed Petal authority is host-global, not inherently wallet-specific. A later
`/security/apps.{json,md,html}` should inventory each Petal's VFS, network, signing,
store, and route consent. The wallet page names a Petal only when a live wallet-specific
session binds that Petal identity and digest.

## Authority model

Every entry must answer:

- **Who** is authorized, using a full chain-qualified identity and label provenance.
- **What** it can actually do in plain language.
- **Which account and assets** are in scope.
- **What limits and expiry** constrain it.
- **Whether the enforcing chain or venue still authorizes it.**
- **Whether Bloom can currently exercise it.**
- **When and how** the state was verified.
- **How it can be stopped**, without overstating local cleanup as remote revocation.

Use two independent states:

```text
authorization_state  active | expired | revoked | unknown
executor_state       available | stopped | missing | not_applicable | unknown
```

Derive the user-facing state from both:

| Enforcing system | Bloom executor | Meaning |
|---|---|---|
| active | available | Bloom can act within the displayed scope |
| active | stopped or missing | External authority remains; Bloom no longer controls it |
| expired or revoked | available | Stale local credential; it should not be treated as usable |
| expired or revoked | stopped or missing | Inactive history; omit from the primary list |
| unknown | any | State is unverified, never assumed safe |

This distinction is load-bearing. Hyperliquid API wallets sign for a master account or
subaccount and are removed by matching-name replacement, expiry, or other pruning
conditions ([Hyperliquid API wallets](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/nonces-and-api-wallets)).
Bloom's current `stop` implementation only marks its local session stopped and expired;
it sends no venue-side action
([`hyperliquid.rs`](../../crates/bloom-vfs/src/handlers/hyperliquid.rs)). It must be
labelled “Stop Bloom locally,” never “Revoke,” until remote state is changed and
verified.

## Snapshot contract

All formats are pure renderings of one short-lived `PermissionsSnapshot` and share its
`snapshot_id` and `as_of_ms`:

```json
{
  "schema": "bloom.permissions.v1",
  "snapshot_id": "...",
  "wallet": "alice",
  "as_of_ms": 1784304000000,
  "account_graph": [],
  "summary": {
    "needs_attention": 2,
    "active_permissions": 7,
    "coverage": "partial"
  },
  "findings": [],
  "permissions": [
    {
      "id": "perm_7K4M...",
      "kind": "venue_agent",
      "account": "hyperliquid:mainnet:0x1234...",
      "actor": {},
      "effects": [],
      "scope": {},
      "limits": {},
      "expires_ms": null,
      "signing_model": "holds_delegated_key",
      "authorization_state": "active",
      "executor_state": "stopped",
      "effective_state": "authorized_elsewhere",
      "evidence": [],
      "next": []
    }
  ],
  "safeguards": {},
  "recovery": {},
  "coverage": [],
  "errors": []
}
```

Use decimal strings for quantities and money. Permission IDs are bounded, path-safe
digests; exact addresses and provider identifiers remain in the entry. Never serialize
private keys, recovery material, passphrases, HMAC secrets, signatures, WebAuthn PRF
outputs, salts, bearer tokens, or raw credential IDs.

Build the account graph from explicit ownership facts: the EVM owner account per chain,
Polymarket proxy/deposit wallet and controller, and Hyperliquid account/subaccount and
multisig roles. Do not infer ownership from transaction history or similar addresses.

## Discovery and coverage

### Bloom-native authority

Bloom already exposes `/wallets/<wallet>/capabilities/active.{json,md}`, but it is only
a source for the new view:

- its EVM projection reads legacy in-memory policy sessions and omits the durable
  owner-signing sessions that `/policy-session/active.json` also reads;
- EVM session `created_ms` is currently hard-coded to zero;
- it contains only active entries, so expired and revoked lifecycle evidence is absent;
- it does not include policy safeguards, on-chain approvals, service credentials,
  account controllers, or complete Petal consent; and
- the approval-credential store supports point lookup and revocation but not a wallet-
  scoped list, so approval authenticators cannot yet be inventoried completely.

The new snapshot should join legacy sessions, durable standing sessions, Hyperliquid
sessions, signed policy state, passkey-safe metadata, and any wallet-bound Petal
identity/digest without changing `/capabilities/active` compatibility. Full installed-
package consent remains in the host-global apps inventory.

### EVM authority

For ERC-20, ERC-721, and ERC-1155:

1. Start with Bloom-known token/spender pairs and venue contracts.
2. Discover additional candidates from `Approval` and `ApprovalForAll` logs using
   durable per-chain checkpoints or an optional indexer.
3. Re-read `allowance`, `getApproved`, or `isApprovedForAll` at one pinned
   `(block_number, block_hash)` before rendering current state.
4. Report the scanned range, provider, block anchor, and gaps.

Events discover candidates; they are not current truth. Finite ERC-20 allowance can
fall during `transferFrom`, and ERC-721 transfer clears token approval without requiring
another approval event. Bloom's RPC layer already supports block-hash-pinned read
sessions, so each chain can produce an internally consistent snapshot.

Permit2 needs two visible layers: the token's approval to Permit2 and Permit2's nested
owner/token/spender allowance. The nested amount and expiry may remain recorded while
the top-level token approval is zero; call it dormant, not revoked. Permit2 reusable
allowances are explicitly amount- and time-bounded
([AllowanceTransfer](https://developers.uniswap.org/docs/protocols/permit2/concepts/allowance-transfer)).

Detect EIP-7702 by reading the account code and recognizing
`0xef0100 || delegate_address`. This is persistent account control and the delegate code
executes in the account's context, so an unknown or changed delegate belongs in “Needs
attention” ([EIP-7702](https://eips.ethereum.org/EIPS/eip-7702)). Other contract-wallet
code is `unsupported` or `partial` until a controller adapter exists.

Bloom cannot enumerate an unsubmitted EIP-2612 permit, Permit2 signature transfer, or
other off-chain signature made outside Bloom. Once submitted, its resulting on-chain
state becomes discoverable. State this blind spot explicitly.

### Venue authority

- **Hyperliquid:** query remote API wallets, native multisig signers and threshold, and
  builder-fee approvals. Multisig controls HyperCore while the original wallet still
  controls HyperEVM, so those are separate account-control facts
  ([multisig](https://hyperliquid.gitbook.io/hyperliquid-docs/hypercore/multi-sig),
  [builder codes](https://hyperliquid.gitbook.io/hyperliquid-docs/trading/builder-codes)).
- **Polymarket:** show the deposit-wallet owner/session-signer relation, pUSD allowances,
  CTF operator approvals, and CLOB/builder/relayer credentials separately. L2 CLOB
  credentials can cancel orders and post already-signed orders, but a new order still
  needs its owner/deposit-wallet signature
  ([authentication](https://docs.polymarket.com/api-reference/authentication),
  [deposit wallets](https://docs.polymarket.com/trading/deposit-wallets)).
- **Service credentials:** show exact effects and remote/local status, never secret
  material. Deleting a local secret is not remote revocation. Keep the local credential
  until remote deletion is confirmed when it is needed to authenticate that deletion.

Independent adapters run concurrently with bounded timeouts. A failed source must not
blank the page, and “zero found” is valid only for the range and provider actually
checked. Reorg-sensitive chain facts stay pending until the configured confirmation,
safe, or finalized boundary.

## Findings, labels, and revocation

Use deterministic findings rather than a risk score.

“Needs attention” includes:

- a stopped, expired, or missing Bloom executor whose remote actor remains authorized;
- a remote agent, signer, or controller with no matching local record;
- an unexpected or changed owner, EIP-7702 delegate, or multisig configuration;
- unsigned, stale, or invalid wallet policy where protection is expected;
- secret-bearing local files with permissions broader than owner-only;
- failed revocation or revocation awaiting remote/on-chain verification; and
- incomplete coverage that prevents a claimed check.

“Review” includes broad/unlimited/operator-wide permission to an unknown actor with
current assets in scope, or non-expiring service access. A recognized contract is not
automatically safe. Labels must say whether they are Bloom-pinned, explorer-reported,
user-saved, provider-reported, or app-claimed. Proxy code may change, so source
verification never becomes a “trusted” badge.

The view is read-only. A stop or revoke link enters the existing canonical action path:

```text
revalidate → stage exact terminal action → simulate and show dependencies
→ Sealed Approval when required → submit → verify current state → Activity
```

Use `approve(spender, 0)`, ERC-721 approval clear, operator `false`, Permit2 lockdown,
or the venue's exact terminal operation as appropriate. Do not offer a generic EOA
“revoke all” multicall: an external multicall contract is `msg.sender` and cannot revoke
the owner's approvals. Batch only where the account or protocol natively supports it.
Warn when revocation can invalidate open orders or workflows. A successful transaction
or API response remains `revocation_pending_verification` until the enforcing system
reports the terminal state.

Wallet connections and token approvals must stay separate. Disconnecting an app does
not remove its on-chain allowance
([MetaMask explanation](https://support.metamask.io/more-web3/learn/how-to-revoke-smart-contract-allowances-token-approvals/)).

## Recovery and key export

Recovery is a safeguard, not a permission. The primary page should summarize it and
link to `/permissions/recovery.*`; no recovery file ever contains secret material.

Show facts Bloom can prove:

```text
Recovery & key custody
Owner key            Passkey-wrapped
Key-unlock passkeys  1 active
Approval credentials Not fully inventoried
Recovery backup      Unknown
Portable copy        May exist; recovery key was shown at creation

Recommended          Add another passkey (when supported)
Available            Create encrypted backup
Advanced             Reveal raw private key
```

Use separate fields for:

- `custody_model`: `watch_only`, `passkey_wrapped`, or `passphrase_encrypted`;
- `key_unlock_credentials` and `approval_credentials`, each with its own role and
  lifecycle; when one authenticator serves both roles, say so only after matching it
  internally and never expose its raw credential ID;
- `backup_state`: `not_recorded`, `artifact_created`, `verified`, or `unknown`;
- `last_backup_created_ms` and `last_backup_verified_ms` when Bloom has receipts;
- `portable_copy_may_exist` and a reason such as `shown_at_creation`,
  `shown_after_rebind`, or `imported_key`; and
- available recovery actions and the fresh verification each requires.

“Verified” means Bloom successfully decrypted a selected backup in memory and derived
the expected wallet address. It does not prove that the file still exists, that its
password is remembered, or that no other copy exists. Historical wallets remain
`unknown`; never infer “backed up” from the user's acknowledgement click.

Offer recovery in this order:

1. **Add another passkey** when multi-passkey support exists. This adds redundancy
   without exposing the owner key. It must gain owner-key-unwrapping material; an
   approval-only WebAuthn credential is not a recovery credential.
2. **Create encrypted backup** as the recommended portable export. Use the standard
   Web3 Secret Storage v3 JSON format with a fresh recovery password and memory-hard
   `scrypt`, so the artifact can be restored outside Bloom without storing plaintext
   ([Ethereum Web3 Secret Storage](https://ethereum.org/developers/docs/data-structures-and-encoding/web3-secret-storage/)).
   Explain that a weak password permits offline guessing, require confirmation, and
   make clear that Bloom cannot recover a forgotten backup password.
3. **Reveal raw private key** only as an advanced interoperability escape hatch. Explain
   before verification that any copy can move all assets outside Bloom and bypass its
   passkey, policy, and Sealed Approval protections. Established wallet UX treats
   cleartext export as a high-risk operation
   ([MetaMask export warning](https://support.metamask.io/configure/accounts/how-to-export-an-accounts-private-key/)).
4. **Verify backup** by selecting the encrypted artifact, entering its password in the
   trusted local ceremony, decrypting only in zeroizing memory, and comparing the
   derived address. Persist only a ciphertext fingerprint and verification metadata.

An encrypted file is the useful default, but it is not harmless: whoever obtains both
the artifact and password can access the key independently of Bloom. Similar production
key-export systems therefore lead with an encrypted artifact and explicitly warn about
independent access and loss of the backup factors
([Coinbase Prime key export](https://help.coinbase.com/en/prime/onchain-wallet/key-export)).

### Trusted recovery ceremony

Key material must never cross an agent-readable surface. The permissions view may
describe or initiate a trusted local ceremony, but it must not return a key through VFS,
IPC, stdout/stderr, an audit record, a command result, a URL, or a reusable HTTP
endpoint. An agent may request the foreground ceremony, just as it can request Sealed
Approval, but only the trusted browser and a fresh human verification may reveal or
download anything.

Requirements:

- Ignore an already-cached signer. A passkey wallet requires a fresh WebAuthn PRF
  assertion with user verification; a local wallet requires its passphrase entered
  freshly in the trusted UI. The WebAuthn PRF is specifically designed to derive an
  encryption key available only through an assertion, and its exposed PRF requires user
  verification
  ([WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/#prf-extension)).
- Stage passkey backup/reveal as a canonical hardened local action, but complete it
  inside the trusted ceremony. Never mint an agent-consumable grant whose retry can
  retrieve key material. Local wallets use the strongest enrolled approval method plus
  a fresh passphrase; where no hardened method exists, state that weaker assurance.
- Show the wallet name, full address, operation, and consequence before requesting the
  authenticator gesture. Require an explicit second confirmation for raw reveal.
- Use a random one-shot challenge, exact origin validation, short expiry, single
  consumption, `Cache-Control: no-store`, restrictive CSP, and no remote resources.
  Zeroize Rust-owned secret buffers and discard browser secret state on completion,
  timeout, or navigation; do not claim JavaScript can guarantee forensic erasure.
- Return only encrypted bytes for the normal download. The recovery password and raw
  key never appear in the invoking shell or chat transcript.
- Audit only operation kind, wallet, timestamp, result, backup format/fingerprint, and
  action ID. Never audit the password, key, PRF output, or secret-bearing URL.
- State the threat boundary: this separates the trusted browser ceremony from agents,
  VFS readers, and logs; it cannot protect a machine whose OS or browser is already
  compromised.

Do not reuse the current recovery display unchanged. It serves the raw key from a
`/data` endpoint and falls back to returning it for terminal display
([`passkey.rs`](../../crates/bloom-keystore/src/passkey.rs)). That is reasonable for its
original interactive creation flow but would expose an on-demand export to an agent
that launched the command. The export ceremony needs a one-shot authenticated response
with no secret-bearing fallback.

Rebinding a passkey changes the authenticator wrapping the same owner key; it is not a
backup and not owner-key rotation. True EOA key rotation means creating a new address
and migrating assets and permissions. A Polymarket deposit wallet has no independent
exportable key—it is controlled by its owner/session signer. Hyperliquid agent keys are
bounded delegated credentials and should be replaced or revoked, never promoted into
portable backups. Service API credentials remain in Service access, not key export.

## Presentation and safety

- HTML is semantic, single-column, script-free, escaped, self-contained, and makes no
  network requests. The separate trusted recovery ceremony may use the minimal script
  required for WebAuthn; it is not embedded in the view.
- Use `<section>`, `<article>`, `<dl>`, and `<details>` rather than a wide table. The page
  must reflow at 320 CSS pixels and remain clear at 200% and 400% zoom.
- Status is conveyed in text, not color. Full addresses, scopes, evidence, and coverage
  remain one disclosure away.
- Treat actor names, token symbols, and provider text as hostile: escape markup, remove
  control/bidirectional characters from display labels, cap lengths, and never fetch
  remote logos.
- Do not compute a single “amount at risk.” ERC-20 allowance applies to future deposits,
  NFT operators cover a collection, delegated account code can have arbitrary effects,
  and venue agents have policy-dependent powers. Show exact authority instead.

## Suggested implementation sequence

1. Add versioned `PermissionsSnapshot`/entry/recovery models and one short-lived snapshot
   service. Project existing capability, durable auth-session, policy, wallet-kind, and
   sanitized passkey metadata into it.
2. Add direct high-value adapters: Bloom-known EVM approvals, Permit2, EIP-7702 account
   code, Polymarket onboarding approvals/credentials/controllers, and Hyperliquid remote
   agents/builders/multisig. Report partial coverage from day one.
3. Render JSON, Markdown, and HTML plus per-entry and recovery detail. Project findings
   into Next Moves and security changes into Activity.
4. Add durable background approval-log discovery with explicit chain/range checkpoints
   and current-state revalidation.
5. Implement the fresh trusted ceremony for encrypted backup and verification. Replace
   creation-time raw-key display with encrypted backup as the recommended path; retain
   raw reveal as an explicit advanced option.
6. Add revocation actions only after each adapter has exact staging, simulation,
   dependency disclosure, canonical signing, and terminal-state verification. Fix
   Hyperliquid remote expiry/stop semantics separately before calling it revocation.
7. Add `/security/apps.*` from full `PetalConsentSummary` data after the wallet view is
   useful.

Current implementation gaps that this work should track explicitly are the omitted
durable EVM sessions in the capability rollup, local-only Hyperliquid stop, lack of a
general approval index, missing CLOB credential deletion/reconciliation, and absence of
a complete installed-Petal consent inventory.

Fixtures must prove that local-stopped/remote-active authority is urgent; partial log
coverage never renders as zero; Permit2's two layers and EIP-7702 delegation are
correct; account controllers are not mistaken for assets; watch-only and contract
wallets do not offer key export; a cached signer cannot skip fresh recovery verification;
no secret appears in any VFS/IPC/log/command output; backup verification derives the
expected address; malicious labels cannot alter HTML; provider failures remain visible;
and all formats share one snapshot ID.

V0 is ready when a user can identify every authority Bloom knows about, distinguish
remote authorization from Bloom's local ability to act, understand exactly what was not
checked, and reach a safe recovery or revocation workflow without exposing a secret or
creating a new signing bypass.
