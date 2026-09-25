# Solana native transfer Harbor evaluation

This task moves native SOL through the wallet's mounted outbox:
the agent discovers the wallet's Solana account, stages a transfer, drives the
fail-closed Sealed Approval confirm, follows the documented restage projection
when the blockhash expires, and waits for a finalized receipt.

The Hyperliquid task is safe because its primitive is reversible — place, then
cancel, where the undo is also the proof. A transfer has no undo, so three parts
of that model are replaced.

| Hyperliquid | Solana |
|---|---|
| A bounded agent session caps the loss | The host approver completes a ceremony only for the exact configured transfer: destination, exact amount, fee payer, fee ceiling, and pinned signing account |
| A host-generated CLOID binds the venue record to the trial | A fresh host-controlled destination and an exact host-pinned amount bind it |
| `cancel_all` unwinds the side effect | On mainnet the host sweeps the destination back; only fees are spent. Locally the validator's funds are worthless and its ledger disposal belongs to whoever started it |

Native SOL goes through the triad, not `bloom-petal-solana`, so the Hyperliquid
preflight's package-hash, provenance, delegated-class and lineage checks have no
analogue here and are deliberately absent. The authority chain being verified is
Broker policy, the passkey ceremony, the semantic transfer verifier, and the
independent host verification of chain state.

## Lanes

`local` (default) runs against a disposable `solana-test-validator` endpoint.
It refuses to be pointed at mainnet-beta — checked from the endpoint's actual
`getGenesisHash` answer, not from the network label — because a non-mainnet
genesis is already permitted to broadcast and the validator's funds are
worthless. Develop here.

`mainnet` is the real measurement. Public devnet is deliberately skipped:
it buys nothing the local validator does not and its faucets are unreliable.
The lane requires the explicit network selection, an acknowledgement, the full
transfer contract as configuration, a host-controlled destination, and a
pinned mainnet-beta genesis from the live endpoint.

Both lanes share the same transfer, approval, replacement, and verification
semantics. Only the funding, the destination sweep, and the network identity
differ.

## The host approval contract

The agent drives the confirm, so its ceremony is published while Harbor is
running. A background approver polls the outbox's host state directory and
completes a ceremony **only after** reading the staged `intent.json` and
checking every authoritative field against the configured trial: destination,
exact lamports, fee payer, signing-account fingerprint and derivation path
(omitting them is a refusal, never a silent pass), the fee ceiling, and the
staged `genesis_hash`, which must be the genesis preflight read from the
endpoint. It is never a rubber stamp for whatever the agent staged.

The verifier grades exactly one signature on the destination, so preflight
refuses a destination with any on-chain history; every trial needs a fresh one.

The approver follows exactly one succession: after blockhash expiry the
outbox's restage route moves the approved entry to `failed/` and publishes
`restage_advice.json` naming the replacement id. A pending entry that does not
continue that lineage — a second fresh staging with identical destination and
amount, for example — is refused and fails the trial. Total ceremonies are
capped, so a misbehaving route cannot farm approvals.

## One triad, its own ceremony port

The evaluation runs against one prepared, dedicated triad, with one trial at a
time. Isolation comes from the dedicated developer root, Machine home, wallet,
validator state, and ceremony port. Port 18734 belongs to an installed custody
triad when one exists, so launch the evaluation triad with its own
`--ceremony-port` (DEVELOPMENT.md). `triad.env` records the port and origin; the
wrapper and the approver read them from there. Never kill or stop another
port's owner.

## Prerequisites

- The sibling `bloom`, `bloom-broker`, and `bloom-signer` checkouts, with the
  Broker and Signer at revisions the Bloom pins accept, and
  `cargo`/`jq`/`uv` on PATH.
- The Solana CLI (Agave) for the validator, funding, and destination keys.
- Docker and the Harbor-managed agent image for model trials; `--smoke-only`
  needs neither.
- An authenticator seed file (mode `0600`) for the wallet's owner credential,
  used by the debug driver to complete ceremonies. The harness records the
  next unused WebAuthn counter beside it automatically.

## Preparation sequence

Every command below is the real CLI surface; run them in order.

1. Start a disposable local validator, dedicated to this evaluation:

   ```sh
   export BLOOM_EVAL_SOLANA_VALIDATOR_LEDGER=/private/path/to/eval-ledger
   solana-test-validator --ledger "$BLOOM_EVAL_SOLANA_VALIDATOR_LEDGER" --reset --quiet &
   ```

   Whoever starts the validator owns its lifecycle; the harness never stops
   it or touches its ledger.

2. Read the validator's genesis. The Machine's chain configuration must pin
   it, and the harness independently compares the endpoint's answer:

   ```sh
   solana genesis-hash --url http://127.0.0.1:8899
   ```

3. Prepare the evaluation Machine's config with the Solana chain, pinning the
   genesis from step 2 and enabling broadcast:

   ```toml
   [solana_chains.solana-local]
   name = "solana-local"
   allow_broadcast = true
   expected_genesis_base58 = "<genesis from step 2>"

   [[solana_chains.solana-local.endpoints]]
   url = "http://127.0.0.1:8899"
   weight = 100
   ```

   Point `BLOOM_TRIAD_DEV_MACHINE_CONFIG` at that file; the developer
   launcher copies it into the evaluation Machine home it creates.

   The local-lane trial container shares host networking
   (`docker-compose.local.yaml`) so it can reach this loopback validator.
   That also exposes the Machine's loopback NFS export to the agent, past the
   read-only bind mount. It is accepted for the local lane only: nothing
   signs without the exact-match host approval, local funds are worthless,
   and the mainnet lane never receives the overlay.

4. Launch the dedicated evaluation triad on its own ceremony port (one
   terminal; it stays in the foreground):

   ```sh
   export BLOOM_EVAL_TRIAD_ROOT=/private/path/to/persistent/eval-triad
   export BLOOM_EVAL_BLOOM_MOUNT=/private/path/to/empty/mount
   mkdir -p "$BLOOM_EVAL_TRIAD_ROOT" "$BLOOM_EVAL_BLOOM_MOUNT"

   BLOOM_TRIAD_DEV_MACHINE_CONFIG=/private/path/to/machine-config.toml \
   scripts/triad-dev-launch.sh \
     --developer-root "$BLOOM_EVAL_TRIAD_ROOT/developer" \
     --mount "$BLOOM_EVAL_BLOOM_MOUNT" \
     --machine-socket "$BLOOM_EVAL_TRIAD_ROOT/runtime/machine.sock" \
     --log-dir "$BLOOM_EVAL_TRIAD_ROOT/logs" \
     --ready-file "$BLOOM_EVAL_TRIAD_ROOT/ready" \
     --ceremony-port 28735
   ```

   Linux mounts additionally need the launcher's narrowly scoped sudo mount
   rule; see DEVELOPMENT.md. Source the written connection settings in a
   second terminal:

   ```sh
   source "$BLOOM_EVAL_TRIAD_ROOT/logs/triad.env"
   ```

5. Create the isolated evaluation wallet and its Solana account. The wallet
   is registered through Broker custody ceremonies; complete each printed
   `http://localhost:28735/ceremony/...` URL with the debug driver and the
   authenticator seed file, advancing `--sign-count` each time:

   ```sh
   bloom wallet import solana-eval
   # → ceremony_url: http://localhost:28735/ceremony/<token>
   bloom-broker/target/debug/bloom-broker-debug-driver complete <ceremony_url> \
     --authenticator-seed-file "$HOME/.config/bloom/eval-authenticator-seed" \
     --sign-count 1 --mnemonic-file /private/path/to/eval-mnemonic
   ```

   The mnemonic is a dedicated test secret entered only in the ceremony; it
   must contain no funds and no public-chain history. The import ceremony
   derives the Solana child (`bip44-solana-slip10-ed25519-v1`) itself; print
   its address:

   ```sh
   bloom wallet address solana-eval --profile solana
   ```

6. Fund the eval wallet's Solana address from the validator's faucet:

   ```sh
   solana airdrop 2 <eval-wallet-solana-address> --url http://127.0.0.1:8899
   ```

7. Create the fresh host-controlled destination for the trial and grant it
   through the wallet policy. Policy allow-sets are deny-by-default, so the
   destination must be listed for the `solana` chain family:

   ```sh
   solana-keygen new --no-bip39-passphrase --outfile /private/path/to/eval-destination.json
   solana address --keypair /private/path/to/eval-destination.json
   ```

   Then stage the policy update through the wallet CLI, complete the printed
   ceremony, and commit it with the operation id the staging step printed
   (the projection's policy is `{version, canonical_policy}`; the proposal
   is the base64-decoded `canonical_policy` with the destination added):

   ```sh
   bloom wallet projection solana-eval \
     | jq -r '.policy.canonical_policy' | base64 -d > current-policy.json
   jq '.allowed_destinations = \
     [{"chain":"solana","destination":"<destination address>"}]' \
     current-policy.json > proposed-policy.json
   bloom wallet update-policy solana-eval --file proposed-policy.json
   # → ceremony_url + operation id; complete the ceremony as above, then:
   bloom wallet commit-policy <operation-id>
   ```

   Reusing the wallet across trials is supported; each trial still needs a
   fresh host-controlled destination so its chain evidence remains
   unambiguous, which means repeating this step per destination.

8. Configure and run the harness:

   ```sh
   export BLOOM_EVAL_BLOOM_MOUNT                      # from step 4
   export BLOOM_EVAL_SOLANA_HOME_ROOT="$BLOOM_HOME"   # the triad Machine home
   export BLOOM_EVAL_SOLANA_WALLET_ID=solana-eval
   export BLOOM_EVAL_SOLANA_CHAIN=solana-local
   export BLOOM_EVAL_SOLANA_NETWORK=localnet
   export BLOOM_EVAL_SOLANA_RPC_URL=http://127.0.0.1:8899
   export BLOOM_EVAL_SOLANA_DESTINATION=<destination address>
   export BLOOM_EVAL_AUTHENTICATOR_SEED_FILE="$HOME/.config/bloom/eval-authenticator-seed"
   ```

   The deterministic smoke requires no API key, Docker, or Harbor model
   adapter. It runs against the kernel mount by default; with
   `BLOOM_EVAL_SOLANA_TRANSPORT=vfs` it drives the same VFS handlers through
   `bloom vfs` over the Machine IPC socket instead, so it needs no mount at
   all (point `BLOOM_EVAL_SOLANA_VFS_BIN` at a `bloom` build and source the
   triad env so `BLOOM_RPC_ENDPOINT` is set):

   ```sh
   scripts/evals/run-harbor-solana-local.sh smoke                 # mounted
   BLOOM_EVAL_SOLANA_TRANSPORT=vfs \
     scripts/evals/run-harbor-solana-local.sh smoke               # mount-free
   ```

   The vfs transport is smoke-only; agent trials always use the mounted
   transport so the container sees `/bloom`.

   Model trials additionally require Docker and `uv`:

   ```sh
   GLM_API_KEY="$GLM_API_KEY" scripts/evals/run-harbor-solana-local.sh
   ```

The wrapper defaults to GLM-5.2 through the shared provider adapter. Override
the model with `BLOOM_EVAL_MODEL`, or pass `deepseek`, `opencode`, `codex`, or
`claude` as its sole argument. `deepseek` runs DeepSeek through Claude Code's
Anthropic-compatible adapter; `opencode` runs the same provider through
Harbor's native OpenCode adapter.
Claude Code-backed local Solana trials default to a bounded 24 turns because
discovery, owner approval, possible blockhash restaging, and finality can exceed
the harness's shared 20-turn default. Set `BLOOM_EVAL_MAX_TURNS` to override
it.
The lifecycle lock permits one Solana eval at a time.

A missing mount (outside the vfs transport) or a missing ceremony listener
produces a clear wrapper error; it never stops another service.

## Exercise the blockhash-expiry replacement path

A transfer whose approval lands after its blockhash expires is refused by the
outbox, and the agent must restage it. The deterministic smoke can drive that
whole path — real expiry, restage advice, replacement approval, exactly one
finalized payment — without an LLM:

```sh
BLOOM_EVAL_SOLANA_SMOKE_RESTAGE=1 scripts/evals/run-harbor-solana-local.sh smoke
```

This waits out the local validator's real blockhash window, so it takes a few
minutes. It is the strongest pre-paid gate for the replacement lineage.

## Mainnet parameters

The mainnet lane takes the whole transfer contract from explicit operator
configuration. There is no authorization file, artifact hash, or spent ledger.

```bash
export BLOOM_EVAL_SOLANA_LANE=mainnet
export BLOOM_EVAL_SOLANA_WALLET_ID=...              # Bloom wallet id
export BLOOM_EVAL_SOLANA_CHAIN=solana-mainnet       # the configured chain key
export BLOOM_EVAL_SOLANA_NETWORK=mainnet-beta
export BLOOM_EVAL_SOLANA_RPC_URL=https://...
export BLOOM_EVAL_BLOOM_MOUNT=/path/to/the/selected/bloom/mount
export BLOOM_EVAL_SOLANA_HOME_ROOT=/path/to/machine/home
export BLOOM_EVAL_SOLANA_SOURCE=<base58 source>     # the wallet's account
export BLOOM_EVAL_SOLANA_KEY_FINGERPRINT=<hex>      # that account's fingerprint
export BLOOM_EVAL_SOLANA_DERIVATION_PATH="m/44'/501'/0'/0'"
export BLOOM_EVAL_SOLANA_DESTINATION=...            # host-controlled sweep address
export BLOOM_EVAL_SOLANA_SWEEP_KEYPAIR_FILE=...     # mode 0600, controls destination
export BLOOM_EVAL_SOLANA_LAMPORTS=1000000           # exact, not a ceiling
export BLOOM_EVAL_SOLANA_MAX_FEE_LAMPORTS=10000     # ceiling
export BLOOM_EVAL_SOLANA_MAINNET_ACK=TRANSFER_SOL_MAINNET_EXACTLY_AS_CONFIGURED
export BLOOM_EVAL_AUTHENTICATOR_SEED_FILE="$HOME/.config/bloom/eval-authenticator-seed"

# Read-only: configuration, mount, wallet, driver, and chain identity. No
# ceremony, mounted write, Docker job, or agent run happens in this mode.
scripts/evals/run-harbor.sh solana-transfer --preauthorization-only

scripts/evals/run-harbor.sh solana-transfer claude
scripts/evals/run-harbor.sh solana-transfer codex
scripts/evals/run-harbor.sh solana-transfer glm
scripts/evals/run-harbor.sh solana-transfer deepseek
scripts/evals/run-harbor.sh solana-transfer opencode
```

The harness rejects a configured transfer amount or fee ceiling above 0.02 SOL,
independently of the operator's numbers; it does not check wallet balances.
It refuses a mainnet endpoint whose live
genesis is not mainnet-beta's, refuses a local lane whose endpoint serves the
mainnet-beta genesis, and requires the sweep keypair to control the
destination. Cleanup always sweeps the destination back to the source; only
fees are actually spent. The container never receives the sweep key.

Set `BLOOM_EVAL_MODEL` to select a different model without changing the
harness. The GLM adapter defaults to `glm-5.2` and accepts `GLM_API_KEY`,
`ZAI_API_KEY`, or `ANTHROPIC_AUTH_TOKEN` from the host; the credential is
forwarded only to Harbor's agent adapter.

`deepseek` and `opencode` both require `DEEPSEEK_API_KEY`. OpenCode model
overrides use `provider/model` form, for example
`BLOOM_EVAL_MODEL=deepseek/deepseek-v4-flash`.

The deterministic `smoke` lane is the protocol conformance fixture: it checks
the real mounted route, approval boundary, broadcast, and verifier without an
LLM. For each model trial the harness renders one concrete sentence containing
only the request a user would make: wallet, destination, network, amount, and a
request to wait for finality. It exposes no eval variables, documentation hint,
procedure, or reporting schema to the agent. The operational workflow must be
discovered from the mounted VFS. The verifier grades independent chain and VFS
state, not an agent-authored report.

This is a controlled representation of a real session, not a byte-for-byte
copy. Harbor runs each CLI in a clean `/app` workspace with a temporary tool
home and non-interactive permissions, while a developer normally has a project,
settings, skills, and prior conversation. The important topology is preserved:
Bloom is a sibling mount at `/bloom`, and every wallet read and write reaches the
real VFS.
The host auto-completes the owner's ceremony only after independently checking
the staged terms. Consequently this eval measures Bloom workflow discovery and
safe execution; it does not measure setup-skill discovery, permission prompts,
or the human approval UI.

`BLOOM_EVAL_SOLANA_HOME_ROOT` is required because the approver watches the
canonical `approval_challenge.json` from stable host state rather than through
the live mount. Current outboxes also project that sanitized resume artifact to
the owner filesystem; the agent must not attempt to complete its ceremony.

### The mount contract

`/bloom` is bound read-only and the wallet's `chains/<chain>/outbox` subtree is
over-mounted read-write. A pending entry's id is allocated by the daemon when the
agent stages, so its `confirm` path cannot be enumerated before the container
starts. The Docker flag is defence in depth; the authority boundary is the VFS
mode — everything under `outbox/` is `0444` except `new.tx`, a pending entry's
`confirm`, `cancel` and `restage`, and an expired entry's `failed/<id>/restage`
— plus Broker policy, the ceremony, and the
exact-match host approver. Provision refuses when the outbox is absent, because
Docker silently creates an empty directory at a missing bind source and would
mask the real one.

### Cleanup

Host-owned, ordered, and fail-closed. Pending entries are cancelled and the
directory must drain, since a residual staged entry still holds a broadcastable
blockhash. An entry with a durable broadcast attempt is never treated as
safely cancelled; it fails the cleanup postcondition instead. `sent/` must
hold zero or one reconciled entry. On mainnet, the destination is then swept
back to the source and the drain is confirmed from the chain rather than from
the CLI's exit code. The sweep runs whenever the addresses
are known, not only when a `sent/` entry exists: a broadcast the outbox failed to
record still moved funds, and that is the worst case in which to skip it.
The local lane never sweeps and never touches the externally supplied triad
or validator.

The container's own cleanup cancels staged entries and nothing else. There is
no post-broadcast undo to delegate, and giving a container a path that moves funds
would defeat the bound the eval rests on.

### WebAuthn counters

The harness records the next unused counter beside the seed file it belongs to,
at `<seed file>.sign-count`, rather than leaving it to be tracked by hand. The
record is keyed to the credential because a signature counter belongs to one
authenticator, not to the machine: two evals may be configured with different
seed files, and a shared record would carry one credential's counter into the
other's run. `BLOOM_EVAL_SIGN_COUNT_FILE` overrides the location.
It is written the moment a counter is consumed, before the ceremony's result is
even inspected, because the Broker accepts the counter before a ceremony can
fail. Set `BLOOM_EVAL_AUTHENTICATOR_SIGN_COUNT` to override or to seed the first
run; the recorded value never moves backwards, and falling back to it prints a
line naming the counter and the file it came from, so it is never silent. A
stale record is safe in both directions: too low is rejected by the Broker and
fails the run without moving anything, and too high is simply accepted, since
counters only have to increase.

A Solana transfer spends far fewer counters than a Hyperliquid session. A live
local-validator run of `bloom-it`'s `solana_workflow` shows one signing call for
the confirm, plus key derivation on first use, against Hyperliquid's three. The
harness caps the count rather than asserting it.

### What live runs have confirmed

`cargo test -p bloom-it --test solana_workflow -- --ignored` drives a real
`Daemon` against `solana-test-validator`. Running it settled the outbox
behaviour this task depends on:

- the first `confirm` is refused with a permission error, and `confirm` is
  exposed at mode `644`;
- dynamic write sinks must be addressed directly: editor-style atomic writes
  target an invalid sibling such as `confirm.tmp`, while buffered shell writes
  can hide a late NFS error unless the writer forces it before reporting success;
- `intent.json` carries `fee_payer`, `destination`, `lamports`, `fee_lamports`,
  `blockhash`, and — for a staged entry — `account_fingerprint` (hex) and
  `account_derivation_path`, which is what lets the approver check the signing
  identity and not just the amount;
- `receipt.json` is exactly `{outcome, signature, slot, confirmation_status}`,
  reaching `success` / `finalized`;
- `broadcast_attempted.json` carries the signature, fee payer, destination,
  lamports, and blockhash;
- `restage_advice.json` is `bloom.solana-restage-advice/1` with `reason`,
  `replacement_id`, `wallet`, and `chain`, published on the expired entry
  beside `restage.md`;
- pending ids look like `sol-<32 hex>`, so nothing may assume a numeric id.

The key fingerprint is lowercase hex: the wire crate declares
`fixed_lower_hex!(Digest32, 32, ...)`.

`scripts/test-harbor-evals.sh` drives the verifier against a deterministic
fake RPC shaped like a real node's jsonParsed responses, which proves the
logic. The deterministic smoke on a local validator proves the response shapes
still match a real node: the same verifier code grades the smoke's real
transfer, and its faucet/settlement observations (finalized commitments lag
confirmed ones, so every balance this eval reads is a finalized one) were
established against live validators.

The temporary wallet policy names the destination under the stable `solana`
authority namespace. `solana-local` is the VFS/configuration name; cluster
identity is bound separately by the pinned genesis hash and signed blockhash.
