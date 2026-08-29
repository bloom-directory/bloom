# Working with bloom

bloom exposes chain workflows — EVM and Solana — as a virtual filesystem.
Prefer inspecting the mounted tree with normal filesystem tools. Run
commands from the mount root (the directory containing this file) so
examples can use relative paths.

Useful commands:

- `ls` lists the VFS root.
- `ls docs` lists the embedded documentation.
- `cat docs/README.md` reads the VFS overview.
- `cat docs/examples.md` reads workflow examples.
- `cat docs/petals.md` discovers the Petals installed in this Bloom home.
- `ls chains` lists configured networks.

For more information, start in the `docs` folder. It contains the canonical
VFS usage notes and examples exposed by the mounted tree.

## Security model

bloom gatekeeps every value-moving action through capabilities:

- **Reads are always safe.** No signing, no ceremony, no wallet needed for chain
  state, balances, prices, books, candles, account state.
- **Direct writes require owner approval.** The outbox stage-confirm flow and
  one-off Petal operations cross a Broker-owned ceremony when fresh owner
  approval is required.
- **Automated action uses a capability.** Create a bounded session/capability
  first — the human approves the bounds once, then the agent operates inside
  them without re-prompting until expiry, breach, or revocation.
- **The owner key is never handed off.** EVM, Solana, and installed-Petal
  authority is prepared by Broker and signed only by Signer; Machine never
  receives the private key.

To see what a wallet can do without a human, check its per-chain state, outbox,
and the mounted capability views of installed Petals.
A read-only `wallets/<wallet>/capabilities/` roll-up and a VFS-root `next.md`
aggregator expose the current capability and next-action view when the daemon
has the relevant handlers mounted.

## Wallets

When asked for an address for a certain wallet, consider displaying in-line the QR code image for the relevant wallet e.g. `wallets/<wallet>/address.qr.png`.

A wallet's chains are listed at `wallets/<wallet>/chains` and include both
EVM chains and any configured Solana chains — `ls wallets/<wallet>/chains`
enumerates both together. Solana chains route through the exact same
`wallets/<wallet>/chains/<chain>/outbox/...` route family described below
(stage at `outbox/new.tx`, confirm/cancel under `outbox/pending/<id>/`,
inspect `outbox/{pending,sent,failed}/<id>/`) — there is no separate
Solana-specific surface to look for.

## Creating a wallet (asynchronous passkey registration)

Writing a plain name to `wallets/new` **starts a passkey registration — it
does not create a local wallet**, and the write returns before the ceremony
completes:

```sh
printf 'main\n' > wallets/new
cat wallets/registrations/main/status.json
```

- The registration projection is keyed by the requested wallet petname. Verify
  its `requested_name` before opening or polling its `ceremony_url`, or
  cancelling it.
- Open or forward `ceremony_url` to a human; do not attempt it yourself. Never
  imitate WebAuthn, supply PRF material, read recovery material, or silently
  downgrade to a Machine-local credential flow — none of that is available or safe from
  an agent.
- If the registration page reports an unsupported passkey method, ask the
  human to retry with a browser/device passkey, a password-manager passkey
  (iCloud Keychain, Google Password Manager), or a compatible hardware
  security key — and specifically to choose **"Use browser, device, or
  hardware key"** if Bitwarden intercepts the prompt.
- Do not proceed until `status.json`'s `ceremony_state` is `COMPLETED`; only then read
  the new wallet's address at `wallets/<name>/address`.
- Registration requires Machine's authenticated Broker edge. If Broker or
  Signer is unavailable, the write fails closed; do not fall back to a
  Machine-owned wallet-creation path.
- To cancel a live registration, write `y`, `yes`, or `cancel` to
  `wallets/registrations/<petname>/cancel`.

Import, recovery, rebind, and deletion are also Broker custody operations.
Sensitive inputs belong only in the Broker-hosted owner ceremony, never in a
mounted write.

## Mounted Sealed Approval flow

When working through a mounted tree, a confirm write that needs fresh owner
approval does **not** open a browser by itself. The daemon exposes the challenge
first, then denies the triggering write so the writing agent can deliberately
open or forward the ceremony URL.

Expected mounted flow for value-moving outbox actions:

```sh
# 1. Stage a Petal action, then discover its concrete central action id.
ls outbox/pending
cat outbox/pending/<action_id>/plan.md

# 2. Confirm through the Petal projection. If fresh approval is needed, opening
#    the write should fail with permission denied after the daemon writes
#    approval_challenge.json.
printf 'confirm\n' > wallets/<wallet>/chains/<chain>/outbox/pending/<id>/confirm

# 3. Read the challenge from the same central action directory.
cat outbox/pending/<action_id>/approval_challenge.json
```

Before opening the ceremony, verify that `approval_challenge.json` has the same
`action_id` as the directory you are acting on and that `expiry_ms` is still in
the future. Then open or forward `ceremony_url`.

The ceremony is owned by Broker and completed cryptographically by Signer.
After successful completion, retry the same mounted confirm write. Machine has
no local approval or signer state and cannot substitute another action's
receipt.

If the pending transaction has soft policy warnings and you intend to bypass
them, use the sibling write sink `confirm.override`. Mounted override intent
lives in the path so Bloom can make the approval decision before accepting
payload bytes.

After execution, inspect `outbox/sent/<action_id>/` or
`outbox/failed/<action_id>/` for `status.json`, `result.json`, and audit/result
artifacts. Petal-specific wallet paths are projections of the same central
action id; do not treat them as separate approval queues.

## Updating wallet policy

`wallets/<wallet>/policy.json` is the only writable policy surface. It accepts
the complete canonical JSON document.

```sh
# 1. Read the current canonical policy and prepare exact replacement bytes.
cat wallets/<wallet>/policy.json > proposed-policy.json

# 2. The initial write stages Broker policy.validate_update. Broker validates
#    the baseline and proposed bytes and originates a policy_update custody
#    ceremony; the mounted write returns permission denied while approval waits.
cp proposed-policy.json wallets/<wallet>/policy.json

# 3. Discover and read the challenge through the mount.
ls wallets/<wallet>/policy-updates/pending
cat wallets/<wallet>/policy-updates/latest/status.json
cat wallets/<wallet>/policy-updates/latest/approval_challenge.json

# 4. Complete the Broker ceremony, then retry the exact proposed bytes.
cp proposed-policy.json wallets/<wallet>/policy.json
```

The retry must send the **exact same proposed bytes**. Machine obtains the
completed custody receipt from Broker and calls `policy.commit_update`; Broker
then performs Signer's policy compare-and-swap against the authenticated
baseline. Changed bytes require a distinct operation and fresh review. A stale
baseline fails the compare-and-swap rather than overwriting concurrent policy.

`status.json` and `approval_challenge.json` are read-only Machine projections.
They expose operation identity, review digest, ceremony status, retry guidance,
and the public commit outcome. The completed custody receipt remains on the
authenticated Broker/Signer path and is reflected in status; private receipt
material, keys, and passkey output are never exposed through the mount.

## Paid HTTP (x402 and MPP)

Paid HTTP requests live under `requests`. Agents should stage the request,
read `plan.md`, and confirm only when the quoted cost, network, asset, and
merchant match the task. Bloom handles both x402 and MPP internally.

### Selecting the payment protocol

Bloom handles credentials and settlement internally, but the merchant may use
request headers to select its payment rail.

For a merchant supporting both x402 and MPP:

- No negotiation header may default to x402.
- To request MPP, include the negotiation header
  `authorization: Payment` in the staged request.

### Approval

If paid confirmation needs passkey approval, the first confirm write may return
permission denied after writing
`requests/pending/<id>/approval_challenge.json`. Read that file, check
`action_id`, `expiry_ms`, merchant/payment details in `plan.md`, then open or
forward `ceremony_url`, then retry the same VFS write.

Broker records the completed Sealed Approval for the exact request. x402 and
MPP then ask Broker to authorize the exact payment payload and Signer to
produce the signature; one allowance is consumed atomically only when a
signature is produced.
Failed policy checks, bad attestations, failed credential preparation, or retry
failures before signing do not consume Sealed Approval capacity. Raw payment
authorization headers, signed payloads, passkey material, and PRF output are
not written to VFS artifacts; credential metadata is redacted.

Request confirmation executes from the daemon's sealed paid-HTTP subject bytes
and sealed policy snapshot. Files such as `request.toml`, `challenge.json`, and
`policy_check.json` are views for agents. If a pending projection differs from
the sealed subject, or `private/request_body` no longer matches the sealed body
hash, confirmation fails before signing or minting credentials. Live policy may
narrow or deny, but it cannot widen the already sealed payment terms.

### Examples

```sh
cat > requests/new <<'REQUEST'
POST https://api.exa.ai/search wallet=<wallet> max_amount_usd=0.05
content-type: application/json

{"query":"latest Base USDC x402 developer tools","numResults":5,"type":"auto"}
REQUEST

cat requests/latest/plan.md
printf 'confirm\n' > requests/latest/confirm
cat requests/latest/response/body
cat requests/latest/receipt.json
```

Wallet-native paid endpoints that passed live checks:

```sh
# Pre-swap token safety for Base USDC + WETH.
printf '%s\n' 'GET https://x402.fiasignals.com/token-safety/batch?chain=base&token_addresses=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913,0x4200000000000000000000000000000000000006 wallet=<wallet> max_amount_usd=0.05' > requests/new

# Hyperliquid trader score.
cat > requests/new <<'REQUEST'
POST https://graphadvocate.com/hyperliquid/score wallet=<wallet> max_amount_usd=0.03
content-type: application/json

{"user":"0x..."}
REQUEST

# MPP forced based on presence of `authorization: Payment` header
cat > requests/new <<'REQUEST'
POST https://api.nansen.ai/api/v1/smart-money/netflow wallet=<wallet>max_amount_usd=0.10
content-type: application/json
accept: application/json
authorization: Payment

{"chains":["ethereum"],"filters":{"token_sectors":["DeFi"],"include_stablecoins":false},"pagination":{"page":1,"per_page":10},"order_by":[{"field":"net_flow_7d_usd","direction":"ASC"}]}
REQUEST


# Polymarket ghost-fill risk.
cat > requests/new <<'REQUEST'
POST https://graphadvocate.com/polymarket/risk wallet=<wallet> max_amount_usd=0.03
content-type: application/json

{"wallet":"0x..."}
REQUEST

# Onchain data routing to GraphQL or REST.
cat > requests/new <<'REQUEST'
POST https://graphadvocate.com/route wallet=<wallet> max_amount_usd=0.02
content-type: application/json

{"request":"Find the best subgraph for Uniswap V3 pools on Base and give me a ready GraphQL query for top pools by TVL"}
REQUEST
```

Prefer request-local USD caps. If `plan.md` says policy is denied, do not retry
blindly; inspect the wallet policy or ask the human to change it.

## Hyperliquid

The native Hyperliquid handler and agent-session authority are retired. Use an
installed Hyperliquid Petal under `petals/<name>/` when one is present; discover
its exact mounted routes and declared capabilities through `docs/petals.md`.
Do not assume a Hyperliquid Petal is installed or fall back to native paths.

## Petals

Petals are installed wallet extensions. They add application-specific routes
under `petals/<name>/` while using Bloom's wallet, policy, approval, network,
storage, and transaction capabilities.

Installed Petals vary by Bloom home; do not assume a particular extension is
present. Read `docs/petals.md` first. It is generated from the immutable
`petal.toml` manifests of the currently installed packages and lists:

- the installed Petal name and its `petals/<name>/` directory;
- the package's `[consent].summary`; and
- the capabilities declared by that package.

After choosing a Petal, read `petals/<name>/README.md` and
`petals/<name>/AGENTS.md`, then list its directory to discover the current
route tree. Treat those package documents as authoritative for its workflows
and review requirements.

## Sealed Approval capacity

Broker may authorize bounded reusable capacity after owner review. Capacity is
limited by its exact subject, operation classes, counters, expiry, and current
wallet policy; Signer enforces those bindings for every signature. It is never
a blanket unlock, and Machine cannot mint, widen, or consume it locally.
