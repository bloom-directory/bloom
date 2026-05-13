# Wallets, Simulate, Watch

Cheatsheet for the three write-heavy surfaces of the `/bloom/` VFS.
Every command below is a plain `cat`, `ls`, `echo > path`, or `tail -f`
against the mounted filesystem. Mainnet broadcasts are gated by
`block_mainnet_broadcast = true` in `config.toml` (the kill-switch);
per-chain broadcast also requires `allow_broadcast = true`. The
runnable flows here use `anvil` or `base` so they are safe by default.

## 1. Wallets

### List, create, import, watch

```sh
ls /bloom/wallets/
```

`new` is a writable file. The body can be plain text (a wallet name)
or a TOML spec.

```sh
# Shorthand: plain name = create a local wallet called 'alice'.
echo alice > /bloom/wallets/new

# Full TOML form for a fresh local wallet.
cat <<'EOF' > /bloom/wallets/new
name = "alice"
kind = "local"
passphrase = "devonly"
EOF

# Import an existing private key (BLOOM_PASSPHRASE applies if 'passphrase' is omitted).
cat <<'EOF' > /bloom/wallets/new
name = "imported"
kind = "import"
private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
passphrase = "devonly"
EOF

# Watch-only (no private key, signing is disabled).
cat <<'EOF' > /bloom/wallets/new
name = "vitalik"
kind = "watch"
address = "0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045"
EOF
```

Wallet names must match `[A-Za-z0-9_-]{1,64}`. Local/import wallets are
encrypted at rest with argon2id + chacha20poly1305 and are *locked* on
daemon start; you must `wallet unlock` before signing or confirming.
The keystore is process-scoped — when you go through the long-running
`bloom serve` daemon, the unlock survives across VFS calls; a one-shot
CLI process re-locks every invocation, so the daemon path is what the
runnable examples assume.

### Per-wallet leaves

```sh
cat /bloom/wallets/alice/address          # 0x... (EIP-55 checksum)
cat /bloom/wallets/alice/public_key       # 0x04... uncompressed secp256k1
cat /bloom/wallets/alice/kind             # local | watch
cat /bloom/wallets/alice/policy.toml      # current policy

# Per-chain native balance + nonce.
cat /bloom/wallets/alice/chains/base/balance       # raw wei
cat /bloom/wallets/alice/chains/base/balance.eth   # human "0.123 ETH"
cat /bloom/wallets/alice/chains/base/balance.raw   # same as balance
cat /bloom/wallets/alice/chains/base/nonce
```

`policy.toml` is read-only via this surface — edit `~/.bloom/keystore/<wallet>/policy.toml`
out-of-band and the daemon picks it up on the next `info` call.

ERC-20 reads are not under `wallets/` — they live under the
chain-rooted reader at
`chains/<c>/addresses/<addr>/tokens/<token>/{balance,balance.formatted,balance.raw,symbol,decimals}`.
For example, alice's USDC balance on Base:

```sh
ALICE=$(cat /bloom/wallets/alice/address)
cat /bloom/chains/base/addresses/$ALICE/tokens/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913/balance.formatted
```

### Signing

All three sign endpoints write the resulting hex signature to a
`<kind>.sig` file in the keystore directory. The wallet must be unlocked.

```sh
# EIP-191 personal_sign over a UTF-8 message.
echo -n 'gm bloom' > /bloom/wallets/alice/sign/message
cat ~/.bloom/keystore/alice/sign/message.sig

# Raw 32-byte hash (must be 0x-hex, exactly 32 bytes).
echo -n '0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8' \
  > /bloom/wallets/alice/sign/hash
cat ~/.bloom/keystore/alice/sign/hash.sig

# EIP-712 typed data — body is the standard RPC JSON shape. Example:
# an EIP-2612 permit for USDC on mainnet (chainId 1).
cat <<'EOF' > /bloom/wallets/alice/sign/typed_data
{
  "types": {
    "EIP712Domain": [
      {"name":"name","type":"string"},
      {"name":"version","type":"string"},
      {"name":"chainId","type":"uint256"},
      {"name":"verifyingContract","type":"address"}
    ],
    "Permit": [
      {"name":"owner","type":"address"},
      {"name":"spender","type":"address"},
      {"name":"value","type":"uint256"},
      {"name":"nonce","type":"uint256"},
      {"name":"deadline","type":"uint256"}
    ]
  },
  "primaryType": "Permit",
  "domain": {
    "name": "USD Coin",
    "version": "2",
    "chainId": 1,
    "verifyingContract": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
  },
  "message": {
    "owner": "0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045",
    "spender": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
    "value": "1000000",
    "nonce": "0",
    "deadline": "1893456000"
  }
}
EOF
cat ~/.bloom/keystore/alice/sign/typed_data.sig
```

Permit2 typed data has the same shape — just swap `domain.name` to
`"Permit2"`, `verifyingContract` to `0x000000000022D473030F116dDEE9F6B43aC78BA3`,
and use the Permit2-specific `PermitSingle` / `PermitBatch` types.

## 2. Outbox: stage, review, confirm, broadcast

Demo against `anvil` (or `base`); mainnet shown only as a path. The
outbox routes are scoped per `wallet/chain`. Every staged tx gets a
`<seq>-<hash>` directory id (e.g. `0001-21699`) under `pending/`,
`sent/`, or `failed/`.

### Stage an intent

There are three accepted bodies for `outbox/new.tx`: shell shorthand,
JSON, or TOML.

```sh
# Native send, shell shorthand.
echo 'send 0.01 eth to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 on anvil' \
  > /bloom/wallets/alice/chains/anvil/outbox/new.tx

# Native send, JSON.
cat <<'EOF' > /bloom/wallets/alice/chains/anvil/outbox/new.tx
{
  "kind": "send",
  "to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  "value": "0.01 eth",
  "chain": "anvil"
}
EOF

# ERC-20 transfer, JSON. Token + value with a unit triggers ERC-20 encoding.
# The engine resolves the token, encodes transfer(address,uint256),
# and renders the plan as a token transfer (TokenRef in plan.md).
cat <<'EOF' > /bloom/wallets/alice/chains/base/outbox/new.tx
{
  "kind": "send",
  "to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  "value": "10",
  "token": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  "chain": "base"
}
EOF

# Generic call against an arbitrary contract via ABI signature + args.
# Example: WETH deposit() with 0.05 ETH attached on Base.
cat <<'EOF' > /bloom/wallets/alice/chains/base/outbox/new.tx
{
  "kind": "call",
  "contract": "0x4200000000000000000000000000000000000006",
  "method": "deposit()",
  "args": [],
  "value": "0.05 eth",
  "chain": "base"
}
EOF
```

Staging always: parses the intent, fills nonce + fees, simulates, runs
policy, and writes `pending/<id>/{intent.json, plan.md, policy_check.json}`.
A failed simulation or a `Deny` policy outcome surfaces as a write
error — nothing lands in `pending/`.

### Review

```sh
ls /bloom/wallets/alice/chains/anvil/outbox/pending/
# 0001-21699/

ID=$(ls /bloom/wallets/alice/chains/anvil/outbox/pending/ | head -n1)

cat /bloom/wallets/alice/chains/anvil/outbox/pending/$ID/plan.md
```

`plan.md` is rendered from the `StagedTx` and looks like:

```
# Staged tx 0001-21699

Wallet: alice
From:   0x70997970C51812dc3A010C7d01b50e0d17dc79C8
To:     0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
Chain:  anvil (id 31337)
Value:  0.01 ETH (10000000000000000 wei)
Nonce:  3
Gas:    limit=21000 max_fee=1500000000 prio=1000000000
Data:   (none)

## Policy
- No policy rules configured.

## Confirm
Write `y` to `confirm` to broadcast, `cancel` to discard, `override` to bypass soft policy warnings.
```

For an ERC-20 transfer, the `To:` line annotates the token contract
and the `Action:` line names the recipient and human amount
(`Action: Transfer 10 USDC to 0x70997...`). For NFT intents the same
slot renders `transfer ERC-721 …` / `transfer ERC-1155 …`.

```sh
# The full StagedTx JSON. (Note: the on-disk file is intent.json — there
# is no separate tx.json; the staged record carries every field.)
cat /bloom/wallets/alice/chains/anvil/outbox/pending/$ID/intent.json
cat /bloom/wallets/alice/chains/anvil/outbox/pending/$ID/policy_check.json
```

### Confirm (broadcast)

`confirm`, `replace`, and `cancel` are *virtual* writable files: they
appear in `ls` of any pending entry even before they exist on disk.
The wallet must be unlocked. Empty bodies are rejected.

```sh
# Plain confirm.
echo y > /bloom/wallets/alice/chains/anvil/outbox/pending/$ID/confirm

# Override token to bypass soft-policy warnings (Warn outcome only;
# Deny is never overridable).
echo override > /bloom/wallets/alice/chains/anvil/outbox/pending/$ID/confirm
```

After a successful broadcast the daemon moves the directory to
`sent/<id>/` and writes a `tx_hash` file alongside the original
artefacts:

```sh
ls /bloom/wallets/alice/chains/anvil/outbox/sent/$ID/
# intent.json   plan.md   policy_check.json   tx_hash

cat /bloom/wallets/alice/chains/anvil/outbox/sent/$ID/tx_hash
# 0xabc...

# The receipt itself is exposed under the chain reader, keyed by hash:
HASH=$(cat /bloom/wallets/alice/chains/anvil/outbox/sent/$ID/tx_hash)
cat /bloom/chains/anvil/tx/$HASH/receipt
```

Note: there is no `receipt.json` written by the outbox. The status of
a sent tx — including its receipt — is accessed through
`chains/<chain>/tx/<hash>/`. Failed broadcasts land under
`outbox/failed/<id>/` with the same artefacts plus the engine error.

### Replace and cancel

Both routes live next to `confirm` on a `pending/<id>/`. Both require a
non-empty body and require the wallet to be unlocked.

```sh
# Replace: bumped fees plus a substituted intent body. Same nonce, the
# original record stays in place; the engine writes replacement_intent.json
# and replacement_tx_hash alongside.
cat <<'EOF' > /bloom/wallets/alice/chains/anvil/outbox/pending/$ID/replace
send 0.02 eth to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 on anvil
EOF

# Cancel: fires a self-send replacement at the same nonce with a >=10%
# fee bump. Body is any non-empty token, conventionally 'y'.
echo y > /bloom/wallets/alice/chains/anvil/outbox/pending/$ID/cancel
```

### Mainnet broadcast

The same paths work for `chain = "ethereum"`, but the daemon refuses to
broadcast there unless both knobs are flipped: top-level
`block_mainnet_broadcast = false` AND the chain entry's
`allow_broadcast = true`. Stage + review still work read-only with the
defaults; only the `confirm` write fails.

## 3. Simulate

Sessions are in-memory. Lifetime is the daemon process.

### Create a session

```sh
ls /bloom/simulate/
# new   last

# Native send simulation (no signing, no broadcast).
cat <<'EOF' > /bloom/simulate/new
{
  "kind": "send",
  "from": "0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045",
  "to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  "value": "0.1 eth",
  "chain": "ethereum"
}
EOF

ID=$(cat /bloom/simulate/last)   # sim-0001
ls /bloom/simulate/$ID/
# intent.json   plan.md   simulation.json   state-override.json   trace.json
```

`from` is honoured only at the simulate layer (so balance / nonce
overrides bind to the right account); the underlying intent parser
ignores it.

### Read results

```sh
cat /bloom/simulate/$ID/simulation.json   # SimResult: success, gas_used, return_data_hex, ...
cat /bloom/simulate/$ID/plan.md           # short markdown summary
cat /bloom/simulate/$ID/trace.json        # debug_traceCall, or {"unsupported": "..."}
cat /bloom/simulate/$ID/intent.json
```

### State overrides

Drop a JSON map onto `state-override.json` and the session re-runs
synchronously against the original intent. The shape is the standard
`eth_call` overrides object: balance / nonce / code / storage (or
`stateDiff`) per address.

```sh
# Force USDC balance for vitalik.eth to 1,000,000.000000 (1e12 raw).
# USDC stores balances in slot 9; storage keys are the keccak256 of
# (address || slot) padded.
cat <<'EOF' > /bloom/simulate/$ID/state-override.json
{
  "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48": {
    "stateDiff": {
      "0xb1a3aff1b2eb541fcfdab3ee7339183b39bcb6f72d4a4d3eb2d6d8f95c54a3a4": "0x00000000000000000000000000000000000000000000000000000000e8d4a51000"
    }
  }
}
EOF

# Re-read the result.
cat /bloom/simulate/$ID/simulation.json
```

A simpler override — zero out a sender's native balance to test that
your transfer reverts with insufficient funds — is the canonical demo:

```sh
cat <<'EOF' > /bloom/simulate/$ID/state-override.json
{
  "0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045": { "balance": "0x0" }
}
EOF
cat /bloom/simulate/$ID/simulation.json
# {"success": false, "revert_reason": "insufficient funds ...", ...}
```

### eth_call against overridden state

`/simulate` is itself the `eth_call`-with-overrides surface — there is
no separate `eth_call/<to>/<calldata>` path. Stage a `call` intent with
the calldata you want, attach overrides, and read `simulation.json`:

```sh
cat <<'EOF' > /bloom/simulate/new
{
  "kind": "call",
  "contract": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
  "method": "balanceOf(address)",
  "args": ["0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045"],
  "chain": "ethereum",
  "state_override": {
    "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48": {
      "stateDiff": {
        "0xb1a3aff1b2eb541fcfdab3ee7339183b39bcb6f72d4a4d3eb2d6d8f95c54a3a4": "0x00000000000000000000000000000000000000000000000000000000e8d4a51000"
      }
    }
  }
}
EOF
ID=$(cat /bloom/simulate/last)
cat /bloom/simulate/$ID/simulation.json   # return_data_hex carries the balance
```

NFT intents are not simulated through `/simulate` — they go through
the wallet outbox stage path. Enso routes are not simulated through
`/simulate` either (use `defi/intents/`).

## 4. Watch

Subscriptions are TOML specs written to `watch/new`. Each gets an id
`w-NNNN` allocated globally across wallets. The executor ticks every
2 s, polls the relevant RPC, and appends a JSONL line to a per-watch
`live` file when something changes. When `live` exceeds 1 MiB, it
rotates to `history.jsonl.<n>` and a sentinel record is appended to
the new `live` so tailing agents can keep up.

For `Block` and `Event` specs, when the chain client reports
`supports_subscriptions = true` the executor also spawns a per-spec
WebSocket supervisor that drives `eth_subscribe` directly and emits
records as headers / logs arrive. The poll loop continues to run as a
watchdog; both paths share a per-spec `(blockHash, logIndex)` ring
buffer so duplicates from overlap or reorgs are dropped silently. From
a consumer's point of view the live / history files look identical.

### Subscribe (one example per kind)

```sh
ls /bloom/watch/
# new

# 1. Balance watch on vitalik.eth.
cat <<'EOF' > /bloom/watch/new
kind = "balance"
wallet = "alice"
address = "0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045"
threshold_wei = "0"
comparator = ">"
note = "any balance change"
EOF

# 2. Block watch.
cat <<'EOF' > /bloom/watch/new
kind = "block"
wallet = "alice"
chain = "base"
EOF

# 3. Gas-price watch (fires when below 25 gwei).
cat <<'EOF' > /bloom/watch/new
kind = "gas_price"
wallet = "alice"
chain = "ethereum"
threshold_gwei = 25.0
EOF

# 4. Event watch — WETH Transfer on mainnet.
# topic0 = keccak256("Transfer(address,address,uint256)")
cat <<'EOF' > /bloom/watch/new
kind = "event"
wallet = "alice"
chain = "ethereum"
contract = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
topic0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
EOF
```

Listing then shows the allocated ids:

```sh
ls /bloom/watch/
# new   w-0001   w-0002   w-0003   w-0004
```

### Tail and read

```sh
# Stream live JSONL as records are appended.
tail -f /bloom/watch/w-0001/live

# Most-recent rotated archive (when live overflowed 1 MiB).
cat /bloom/watch/w-0001/history.jsonl

# Older archives are numbered.
cat /bloom/watch/w-0001/history.jsonl.1
ls /bloom/watch/w-0001/
# spec.toml   live   history.jsonl   history.jsonl.1   delete
```

### Subscription metadata

The spec is round-trippable as TOML at `spec.toml`. The id, wallet,
created-time millis, kind, and optional note all live on the spec:

```sh
cat /bloom/watch/w-0001/spec.toml
# id = "w-0001"
# wallet = "alice"
# created_ms = "1731177900000"
# note = "any balance change"
#
# [kind]
# kind = "balance"
# address = "0xd8dA6BF26964aF9D7eeD9e03E53415D37aA96045"
# threshold_wei = "0"
# comparator = ">"
```

There is no `config.json`, `last_seen`, or `since` file on the
watch handler — `spec.toml` is the only metadata leaf. Last-seen
state is kept in-process by the executor and replayed via the dedup
ring buffer; consumers reason about progress from the timestamp on
each `live` / `history` record.

### Delete

```sh
echo y > /bloom/watch/w-0001/delete
```

Removes the spec from the registry and the per-watch directory.
