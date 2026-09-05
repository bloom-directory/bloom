# Bloom VFS examples

Run these examples from a normal scratch directory outside the Bloom VFS mount.
Set the mountpoint once, quoted, and keep scratch files in that directory:

```sh
BLOOM="<bloom-vfs-mount>"
cat "$BLOOM/AGENTS.md"
```

Replace every angle-bracketed value, and always list the live surface before
choosing it.

## Local Anvil transaction

```sh
# 1. Discover and inspect the exact inputs.
ls "$BLOOM/chains/"
ls "$BLOOM/wallets/"
cat "$BLOOM/chains/anvil/chain_id"
cat "$BLOOM/wallets/alice/projection.json"

# 2. Stage once.
printf 'send 0.01 ETH to 0x0000000000000000000000000000000000000001\n' \
  > "$BLOOM/wallets/alice/chains/anvil/outbox/new.tx"

# 3. List pending actions. Set ID to the exact entry created by this staging
#    operation after matching its intent; do not choose by ordering.
ls "$BLOOM/wallets/alice/chains/anvil/outbox/pending/"
ID="<exact-id>"
cat "$BLOOM/wallets/alice/chains/anvil/outbox/pending/$ID/intent.json"
cat "$BLOOM/wallets/alice/chains/anvil/outbox/pending/$ID/plan.md"

# 4. Confirm only that inspected action.
echo y > "$BLOOM/wallets/alice/chains/anvil/outbox/pending/$ID/confirm"

# 5. If approval_challenge.json appears, validate it, complete the human
#    ceremony, and retry its exact retry_path. Otherwise inspect the terminal
#    projection directly.
ls "$BLOOM/wallets/alice/chains/anvil/outbox/sent/"
ls "$BLOOM/wallets/alice/chains/anvil/outbox/failed/"
```

Never use a glob such as `pending/<glob>/confirm` as action identity. A glob is
not stable identity and fails when no entry or several entries match.

## Creating a wallet

Wallet creation is asynchronous passkey registration:

```sh
# 1. Request the petname. This does not block and does not create a local
#    wallet.
printf 'main\n' > "$BLOOM/wallets/new"

# 2. Read the projection keyed by the requested petname. Confirm that
#    requested_name is "main" and forward ceremony_url to the human.
cat "$BLOOM/wallets/registrations/main/status.json"

# 3. Poll the same projection until ceremony_state is COMPLETED.
cat "$BLOOM/wallets/registrations/main/status.json"
cat "$BLOOM/wallets/registrations/main/result.json"
cat "$BLOOM/wallets/main/projection.json"
```

Before acceptance, cancellation is explicit:

```sh
printf 'cancel\n' > "$BLOOM/wallets/registrations/main/cancel"
```

Do not put a mnemonic, private key, passkey response, or PRF output in the
mount. Those inputs stay inside the Broker-hosted browser ceremony.

## Solana account-aware reads and transfer

```sh
# 1. Inspect accounts and choose the full Ed25519 fingerprint from the public
#    projection. Do not select by position.
cat "$BLOOM/wallets/alice/accounts.json"
FP="<full-fingerprint>"
cat "$BLOOM/wallets/alice/chains/solana/accounts/$FP/address"
cat "$BLOOM/wallets/alice/chains/solana/accounts/$FP/balance.json"
cat "$BLOOM/status/chains/<solana-chain>/status.json"

# 2. Solana new.tx accepts strict JSON. Pin the selected account explicitly.
#    The scratch file is written in the working directory outside the mount.
cat > solana-transfer.json <<'JSON'
{
  "destination": "<solana-address>",
  "lamports": 10000000,
  "account_fingerprint": "<full-fingerprint>"
}
JSON
cp solana-transfer.json "$BLOOM/wallets/alice/chains/solana/outbox/new.tx"

# 3. Inspect the exact resulting action.
ls "$BLOOM/wallets/alice/chains/solana/outbox/pending/"
ID="<exact-id>"
cat "$BLOOM/wallets/alice/chains/solana/outbox/pending/$ID/intent.json"
cat "$BLOOM/wallets/alice/chains/solana/outbox/pending/$ID/plan.md"
```

Verify that the staged intent names the chosen fingerprint. After confirmation,
verify the same fingerprint and transaction signature in the receipt. Do not
blindly retry an ambiguous broadcast.

## ERC-20 discovery

```sh
A="<holder-address>"
T="<token-contract>"
ls "$BLOOM/chains/base/addresses/$A/tokens/"
cat "$BLOOM/chains/base/addresses/$A/tokens/README.md"
cat "$BLOOM/chains/base/addresses/$A/tokens/known.json"
cat "$BLOOM/chains/base/addresses/$A/tokens/$T/balance"
cat "$BLOOM/chains/base/addresses/$A/tokens/$T/balance.raw"
cat "$BLOOM/chains/base/addresses/$A/tokens/$T/balance.json"
```

These are network-backed reads. They do not authorize a transfer, but they can
contact the configured RPC provider.

## NFT reads and writes

```sh
# Collection and token reads.
cat "$BLOOM/chains/ethereum/contracts/<contract>/nft/kind"
cat "$BLOOM/chains/ethereum/contracts/<contract>/nft/name"
cat "$BLOOM/chains/ethereum/contracts/<contract>/nft/owner_of/<token-id>"

# Stage an ERC-721 transfer, then use the exact transaction loop above.
printf 'nft transfer <contract> <token-id> to <recipient>\n' \
  > "$BLOOM/wallets/alice/chains/ethereum/outbox/new.tx"
```

Inspect `plan.md` before confirmation. Operator-wide approval is broader than
a single-token approval and should be clearly visible in the policy projection.

## Updating wallet policy

```sh
# The proposal is a scratch file in the working directory, outside the mount.
cat "$BLOOM/wallets/alice/policy.json" > proposed-policy.json
# Edit the complete proposal, then stage those exact bytes.
cp proposed-policy.json "$BLOOM/wallets/alice/policy.json"
cat "$BLOOM/wallets/alice/policy-updates/latest/status.json"
cat "$BLOOM/wallets/alice/policy-updates/latest/approval_challenge.json"
```

After the human completes the Broker ceremony, retry the exact same
`proposed-policy.json` bytes. Broker performs `policy.validate_update` before
approval and `policy.commit_update` on the authorized retry.

## Installed Petal workflow

```sh
# 1. Discover the actual package and read both instruction files.
cat "$BLOOM/docs/petals.md"
cat "$BLOOM/petals/<name>/README.md"
cat "$BLOOM/petals/<name>/AGENTS.md"

# 2. Follow that package's staging grammar. Correlate any resulting Petal
#    action with its exact central outbox action before confirmation.
ls "$BLOOM/petals/<name>/"
ls "$BLOOM/outbox/"
```

Enso, Hyperliquid, Polymarket, and other applications are Petals when installed.
Do not guess retired native paths or reuse examples from another package.

## Pure tools

```sh
cat "$BLOOM/tools/keccak/abc"
cat "$BLOOM/tools/address/checksum/0xabc..."
cat "$BLOOM/tools/unit/parse/1.5/eth"
cat "$BLOOM/tools/unit/format/1500000000000000000/18"
```
