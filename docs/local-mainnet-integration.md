# Manual local mainnet integration

This is the developer path for exercising the real Bloom binary, installed
Petals, an existing passkey wallet, the Polymarket API, policy evaluation,
the kernel-mounted NFS VFS and interactive browser ceremonies with Machine,
Broker, and Signer running as separate processes.

It is deliberately not a deployment mode and makes no UID-isolation claim.
The `triad-dev-harness` feature adds only same-UID developer enrollment and
transport bootstrap; it adds no custody, passkey verification, or signing code
to Machine. Signer keeps custody, Broker owns the ceremony origin, and normal
release bundles reject this feature.

The developer enrollment and Broker/Signer databases persist at
`$BLOOM_TRIAD_DEV_ROOT` (default `~/.bloom/triad-dev`). Machine state uses a
fresh temporary overlay for every run; only the canonical public wallet
projection cache is copied into it. Process sockets, the kernel mount, and logs
are also new for every run. This is intentional: Signer
must retain the passkey credential, encrypted root, and backend state across
runs. A fresh Signer database cannot use a legacy wallet merely because an
encrypted record exists under `~/.bloom/keystore`; neither Machine nor these
scripts read or copy that legacy private material.

## What the runner protects

`scripts/local-mainnet-integration.sh` defaults to non-spending preflight. Live
mode:

- requires an explicit Polymarket opt-in;
- requires exact venue, market, side, size, price/slippage bound, and order
  type;
- accepts only Polymarket `FAK` or `FOK` orders with at most $25 maximum
  consideration;
- displays the Polymarket plan, policy result, revalidated quote, and final
  review intent before the order is submitted;
- requires an exact terminal acknowledgement and a draft-specific Polymarket
  passkey approval;
- authorizes only the fixture package in a fresh wallet policy through the
  mounted `policy.validate_update` ceremony and exact mounted commit retry;
- derives a fresh Signer-owned, Petal-scoped fixture sub-key, then prepares its
  Petal-scoped Sealed Approval through the mounted approval adapter and signs a
  fixture payload through real passkey ceremonies before the venue
  compatibility gate;
- accesses wallet identity, venue state, Petal routes, plans, ceremonies, and
  receipts exclusively through ordinary reads and writes beneath the temporary
  kernel mount; it never uses the `bloom vfs` fallback or IPC operations.

Venue acceptance is not proof of a fill. `Ioc`/`FAK` with a marketable bound
normally fills immediately up to that bound and cancels the remainder;
`FOK` either fills completely or cancels. Use exact bounds you are prepared
to trade at.

## Prerequisites

- macOS with the passkey available to the current login's browser/keychain;
- Rust/Cargo and `jq` (`brew install jq`);
- a wallet enrolled through a real Broker registration or import ceremony in
  the persistent developer triad root;
- the migrated local Polymarket and Hyperliquid package checkouts, installed
  only into the disposable Machine overlay;
- Polymarket onboarding/funding sufficient for the chosen order;
- no other local process listening on `127.0.0.1:18734`.

The last rule is fail-closed. If the root-installed Broker is active, unload
only its job before the test:

```bash
uid="$(id -u)"
sudo launchctl bootout "system/com.bloom.broker.${uid}"
```

Restore it after the test:

```bash
uid="$(id -u)"
sudo launchctl bootstrap system \
  "/Library/LaunchDaemons/com.bloom.broker.${uid}.plist"
```

The runner does not perform either root action. If the port is owned, startup
fails before any order is staged. An installed enrollment may remain on disk;
the local process does not connect to it.

On first use, start the launcher in one terminal (replace the paths if needed):

```bash
mkdir -p ~/.bloom/triad-dev/machine-home /tmp/bloom-triad-mount /tmp/bloom-triad-logs
scripts/triad-dev-launch.sh \
  --developer-root ~/.bloom/triad-dev \
  --machine-home ~/.bloom/triad-dev/machine-home \
  --mount /tmp/bloom-triad-mount \
  --machine-socket /tmp/bloom-triad-machine.sock \
  --log-dir /tmp/bloom-triad-logs \
  --ready-file /tmp/bloom-triad-ready
```

The launcher writes the exact authenticated connection environment to
`/tmp/bloom-triad-logs/triad.env`. In a second terminal:

```bash
source /tmp/bloom-triad-logs/triad.env
bloom wallet import WALLET_NAME   # or: wallet new WALLET_NAME
```

If macOS cannot mount Bloom's NFS 4.1 VFS, omit `--mount` and use the VFS CLI
against the same running triad:

```bash
mkdir -p ~/.bloom/triad-dev/machine-home /tmp/bloom-triad-logs
scripts/triad-dev-launch.sh \
  --developer-root ~/.bloom/triad-dev \
  --machine-home ~/.bloom/triad-dev/machine-home \
  --machine-socket /tmp/bloom-triad-machine.sock \
  --log-dir /tmp/bloom-triad-logs \
  --ready-file /tmp/bloom-triad-ready
```

Then, from another terminal:

```bash
source /tmp/bloom-triad-logs/triad.env
"$BLOOM_BIN" vfs ls /
"$BLOOM_BIN" vfs cat /next.md
```

`triad.env` selects both the exact developer binary and its authenticated
Machine IPC endpoint. Supplying `--mount` remains fail-closed: the launcher
will not silently switch modes when a requested mount fails. The
`local-mainnet-integration.sh` and projection-fidelity runners below still
require a supported kernel mount because they intentionally test mounted path
behavior.

### Keep Broker and Signer running while iterating on Machine

To rebuild and restart Machine without disturbing Broker or Signer, run the
launcher in services-only mode in the first terminal:

```bash
mkdir -p ~/.bloom/triad-dev/machine-home /tmp/bloom-triad-logs
scripts/triad-dev-launch.sh \
  --services-only \
  --developer-root ~/.bloom/triad-dev \
  --machine-home ~/.bloom/triad-dev/machine-home \
  --machine-socket /tmp/bloom-triad-machine.sock \
  --log-dir /tmp/bloom-triad-logs \
  --ready-file /tmp/bloom-triad-ready
```

The launcher prepares the isolated Machine home and developer Petals, starts
the Session Sentinel, Signer, and Broker, and then stays in the foreground. It
does not start or own Machine. In a second terminal, source the generated
environment and run Machine in your own rebuild loop:

```bash
source /tmp/bloom-triad-logs/triad.env
cd /path/to/bloom
cargo build -p bloom --no-default-features --features mount,triad-dev-harness && \
  bloom serve --endpoint "$BLOOM_RPC_ENDPOINT"
```

`triad.env` prepends the selected debug binary directory to that terminal's
`PATH`, so `bloom` resolves to the newly rebuilt debug binary. Stop Machine with
`Ctrl-C`, rebuild, and run it again; the other services and their state remain
alive. Stop the services launcher with `Ctrl-C` when finished. It tears down
only the Session Sentinel, Signer, and Broker; Machine remains owned by its own
terminal. `--services-only` cannot be combined with `--mount`; add `--mount`
to the manual `bloom serve` command if the host supports it.

Open the printed Broker ceremony URL. Registration creates a fresh address;
import requires entering the key only in the Broker-hosted browser ceremony.
Stop the launcher after the wallet appears under the mount, or under
`"$BLOOM_BIN" vfs ls /wallets` in VFS-only mode. Subsequent runner invocations
reuse that Signer state and select it with `--wallet WALLET_NAME`.

## 1. Run preflight

The smallest invocation is:

```bash
scripts/local-mainnet-integration.sh \
  --wallet hl-mainnet-validation
```

No venue order is created. A fresh wallet first receives a narrowly scoped
policy-update ceremony adding only the deterministic fixture package. The next
ceremony derives a short-lived Signer-owned key scoped to that installed Petal,
and the final ceremony activates a canonical Petal-scoped Sealed Approval
prepared through `/wallets/<wallet>/sealed-approvals/new.json`. A wallet whose
policy already allows the fixture skips only the policy-update ceremony. The
Petal receives only its public `KeyRef`, approval ID, and signature; it never
receives private key material. The harness installs the migrated local
Polymarket package only into its disposable Machine overlay; venue positions
are not changed.
Preflight verifies:

- the mounted wallet exists, reports passkey kind, and exposes its address;
- a normal empty package allowlist is extended through the Broker-originated
  `policy_update` custody ceremony and installed only by the exact mounted
  retry that supplies the completed receipt to `policy.commit_update`;
- the mounted fixture can derive and use a generic Petal sub-key through Broker
  and Signer using exact mounted retries, with missing approval failing closed
  before the runner prepares the canonical mounted Sealed Approval;
- the migrated local Polymarket Petal package loads from its sibling checkout
  (or `BLOOM_INTEGRATION_POLYMARKET_PACKAGE` override);
- the Polymarket route contract and onboarding, account, and trade directories
  are reachable through the kernel-mounted filesystem.

Polymarket's authoritative onboarding, funding, market, and policy checks run
when the mounted `trade/<wallet>/new` file is written in live mode. Preflight
does not invoke its refresh-on-read status leaves through a non-filesystem
fallback.

Supply a candidate market during preflight:

```bash
scripts/local-mainnet-integration.sh \
  --wallet hl-mainnet-validation \
  --pm-slug YOUR-POLYMARKET-SLUG
```

This echoes the explicitly selected Polymarket slug. Live mounted draft creation
refuses unavailable markets, incomplete onboarding, insufficient funding, or
policy failures before its order-specific passkey ceremony or submission.

The harness installs the migrated local package into its disposable Machine
overlay and requires production payload signing `bloom:sign/signing@0.4.0`.
It does not install, patch, or advertise the old hash-signing release.

## 2. Run bounded mainnet submissions

Choose current values yourself. This is a shape example, not a price
recommendation:

```bash
scripts/local-mainnet-integration.sh \
  --wallet hl-mainnet-validation \
  --execute-polymarket \
  --pm-slug YOUR-POLYMARKET-SLUG \
  --pm-outcome Yes \
  --pm-side buy \
  --pm-amount YOUR_USD_AMOUNT \
  --pm-price-bound YOUR_MAXIMUM_PRICE_FROM_0_TO_1 \
  --pm-order-type FAK
```

The command validates all numeric bounds before touching venue state. It then:

1. starts the production session sentinel, Signer, Broker, and Machine protocol
   implementations under the developer profile;
2. mounts Machine's VFS over NFS at a private temporary directory and waits for
   both the mount table entry and a readable mounted root;
3. if required, writes the complete canonical policy to the mounted
   `wallets/<wallet>/policy.json`, completes the Broker-originated
   `policy_update` custody ceremony, and retries the exact policy bytes to
   commit through Signer compare-and-swap;
4. derives a fixture Petal sub-key, completes its owner-only custody ceremony,
   observes that signing without an approval hint fails closed, prepares a
   canonical Petal-scoped approval through the mounted
   `sealed-approvals/new.json`, completes that ceremony, and verifies the
   exact mounted retry's signature result;
5. rechecks the wallet and Polymarket Petal surface
   exclusively with ordinary filesystem reads through that mount;
6. creates and revalidates an unsigned Polymarket draft through filesystem
   writes;
7. prints all available review artifacts;
8. asks for an exact Polymarket mainnet acknowledgement;
9. asks for a draft-specific Polymarket acknowledgement;
10. opens the real passkey ceremony for the exact Polymarket order, retries the
   exact post, and reads the receipt;
11. unmounts and exits.

The runner retains its temporary log directory on any failure and prints its
path. Do not retry blindly after an ambiguous network failure: inspect the
persisted Polymarket receipt first.

## Local deterministic verification

These do not contact mainnet or open a passkey prompt:

```bash
scripts/test-local-mainnet-integration.sh
cargo check -p bloom --no-default-features
cargo check -p bloom --no-default-features --features mount,triad-dev-harness
```

The actual passkey and live venue submissions are intentionally manual because
only the wallet owner can approve them and they can move real money.
