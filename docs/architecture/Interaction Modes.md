# Interaction Modes

**Status:** architecture decision; triad-aligned
**Audience:** Bloom engineers, Petal authors, and implementation agents

Bloom exposes actions through three client interaction modes:

1. foreground CLI commands;
2. the foreground `bloom vfs` facade; and
3. a VFS mounted by a long-running Bloom Machine.

The `bloom` CLI has exactly two local lifecycle commands: `bloom init` creates
the home, and `bloom serve` owns the long-running Machine. Every other command,
including `status`, `completions`, `update`, `petals`, and the `bloom vfs`
facade is only a client proxy to that running Machine over the configured IPC
endpoint. A missing, refused, or inaccessible default or explicit endpoint is
an error which names the endpoint and tells the user to start `bloom serve`.
`bloom --version` is the diagnostic exception: it always reports the local CLI
version and, when reachable, the daemon version and negotiated IPC protocol;
it reports the daemon as unavailable without constructing a one-shot Machine.
There is no one-shot Machine construction or local Broker fallback.
Hidden platform bootstrap and supervision helpers are submodes of `init` or
`serve`; the binary has no pre-parser execution modes outside those lifecycle
namespaces.

Every IPC request advertises the client's current and supported Bloom protocol
range, and every response advertises the daemon's. Both peers fail closed when
the ranges do not overlap or the metadata is absent; package versions are
reported for diagnosis but are not used as the compatibility contract.

The daemon publishes its socket without exposing a permissive bind-to-chmod
window. It creates a unique `0700` staging directory inside the endpoint's
resolved parent, binds the listener there, changes the socket to `0600`, verifies
its owner, type, mode, and inode, then atomically renames that secured inode to
the endpoint and verifies it again. Before inspecting or publishing the endpoint,
`bloom serve` acquires a nonblocking exclusive lock on a persistent, regular,
same-owner, owner-only lock file beside it and holds that lock for the listener's
full lifetime. A second server therefore fails without replacing the live
listener. The parent itself only needs to be a real writable and traversable
directory; Bloom neither changes its permissions nor requires it to be private,
so conventional `/tmp` and `0755` runtime directories remain compatible. Kernel
peer credentials must match the daemon's effective UID before it reads any
request. Clients never remove or replace an endpoint, including after
`ConnectionRefused`. Shutdown leaves an inert socket in place; on the next
startup, the lock-owning server validates that it is a same-owner socket and
atomically replaces it. Invalid endpoint paths are refused without deletion.

All three client surfaces use the same production authority plane. Machine stages,
simulates, executes Petals, and projects public status. Broker is the only
Machine-facing authorization service and owns Sealed Approvals and ceremony
HTTP. Signer is the only process that holds wallet or delegated private keys
and the only process that produces wallet-controlled signatures.

Neither foreground mode embeds Broker, Signer, approval verification, PRF
handling, a wallet signer, or a fallback keystore in Machine.

## Shared action lifecycle

Every sensitive action follows the same lifecycle regardless of its client
surface:

```text
client stages action
Machine renders plan and public projections
Machine asks Broker to prepare a Sealed Approval when required
Broker prepares the exact review with Signer and returns ceremony_url
user deliberately completes the Broker-hosted ceremony
Signer independently verifies completion and activates the approval
client requests execution
Machine sends the exact payload and claim to Broker
Broker authorizes and asks Signer to sign
Machine receives the public signature/receipts and records the result
```

Ceremony completion activates an approval only. It never broadcasts or
executes the Machine action as part of the browser POST. Execution is a
subsequent operation with its own operation identity.

## Mode matrix

| Mode | Machine execution state | Ceremony launch UX | Authority behavior |
|---|---|---|---|
| Foreground CLI | IPC proxy to the running Machine | The deliberate command may open the Broker-provided URL | Broker and Signer remain separate authenticated services |
| Foreground `bloom vfs` | IPC proxy to the same running Machine VFS | The deliberate facade command may open or print the Broker-provided URL | Identical Broker/Signer protocol; no local approval path |
| Mounted VFS | Long-running Bloom Machine | The mount never opens a browser; the expecting client reads and opens or forwards the URL | Identical Broker/Signer protocol; Machine projects status only |

Broker or Signer unavailability leaves cached public reads, staging, and
simulation available where their inputs exist. Signing, approval mutation,
policy mutation, and custody fail closed. No interaction mode restores legacy
authority.

## Foreground clients

Foreground clients may parse presentation flags, read bounded policy or
migration inputs for transport, format an authoritative daemon response, or
write presentation outputs such as QR files. For local Petal install and build,
the client resolves caller paths to absolute paths; the daemon reads the package,
generates artifacts, and writes any requested archive under its serialized Petal
mutation lane. Foreground clients do not acquire the home write lock, open
Machine state, contact Broker directly, or infer an operation identity from a
later mutable `latest` read. Creation RPCs return the identity projection
under the same VFS mutation gate used by ordinary IPC and mounted writes, so a
concurrent mutation cannot replace the identity before it is captured.

A foreground command may make ceremony UX convenient, but it does not own the
ceremony. When fresh approval is required it:

1. stages or loads the action;
2. calls Broker through the authenticated Machine-to-Broker edge;
3. prints or deliberately opens the returned `ceremony_url`;
4. waits for or polls Broker status; and
5. requests execution only after Broker reports the approval active.

The foreground process never receives WebAuthn PRF output, verifies the
approval locally, mints local authorization state, or caches a decrypted
signer. A foreground `bloom vfs` operation uses this same helper rather than a
second authorization protocol.

## Mounted VFS

Mounted writes may originate from agents, editors, shell tools, or unrelated
local processes. They therefore must not open browser windows. The normal
mounted workflow is:

1. the client stages an action and obtains its concrete action ID;
2. the client writes the action's confirm or execute sink;
3. Machine asks Broker to prepare approval and durably projects the returned
   `approval_id`, `ceremony_url`, `ceremony_expires_at`, and review digest under
   that action;
4. the write reports that approval is required;
5. the expecting client reads the same action's projection, verifies the
   action identity and expiry, and deliberately opens or forwards the URL;
6. the browser communicates with Broker, and Broker relays the completion to
   Signer;
7. Machine observes Broker's terminal status, clears the launch URL, and the
   client retries execution; and
8. mounted projections show the resulting sent, failed, or completed state.

Machine never constructs a ceremony URL. While Broker reports the same live
prepared operation, retries return Broker's same idempotent URL and expiry.
After completion, cancellation, failure, or expiry, Machine clears the URL and
cannot revive it from local state.

## Petal requirements

A Petal that can move value, create credentials, change authority, spend a
budget, or request a signature must provide:

- canonical payload bytes and a concrete operation identity;
- an installer-pinned package hash, route, and permitted operation class;
- a human-readable plan and the declared `PetalUseClaim` inputs;
- payload-bearing signing through Machine's Broker client only;
- execution from the staged subject rather than mutable display files; and
- public audit and result projections.

Petals cannot contact Broker or Signer directly. They receive neither private
keys nor Broker credentials. A Petal-scoped delegated identity is a
Signer-owned `KeyRef` cryptographically bound to its package and route.

Venue integrations implemented as Petals do not retain a native CLI authority
path, root-level VFS handler, Machine-held session key, or daemon-owned venue
state. Their installed package documentation defines their mounted routes.

## Examples

- EVM transactions stage unsigned bytes, obtain approval when policy requires
  it, and use Broker/Signer for the final payload signature.
- Paid HTTP stages the selected challenge and payment payload, then obtains any
  required signature through Broker/Signer.
- Installed Polymarket or Hyperliquid Petals use their package-defined mounted
  interface and generic Petal-scoped approval and sub-key mechanisms.
- Policy update uses `policy.validate_update`, the shared `policy_update`
  custody ceremony, and `policy.commit_update` with the completed receipt.

The normative security and wire contracts remain
[`2026-07-23-triad-process-architecture.md`](../specs/2026-07-23-triad-process-architecture.md).
