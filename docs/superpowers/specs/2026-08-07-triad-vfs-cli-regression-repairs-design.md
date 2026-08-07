# Triad VFS and CLI Regression Repairs

## Scope

This branch repairs the user-approved subset of the triad migration audit. Work
is committed in issue order, one behavior change per commit:

1. Advertise `wallets/<wallet>/chains/<chain>/outbox/new.tx` as writable in
   directory listings as well as direct lookup.
2. Make every `bloom petals` operation use the running daemon instead of
   acquiring the Machine home lock or constructing another daemon.
3. Restore the documented plain-name body for `wallets/new`. The existing
   asynchronous Broker registration, random operation identity, and projection
   layout remain unchanged.
4. Make the CLI, except for `serve` and `init`, a strict proxy to the configured
   running daemon. Remove in-process and direct-Broker fallbacks. Preserve useful
   command output, including request and staged-transaction identities, across
   IPC. Document this boundary in Interaction Modes.
5. Make wallet outbox lookup reject nonexistent artifact names instead of
   returning phantom file metadata.

The existing `ceremony.json` behavior is intentionally unchanged. The
capability and `next.md` projections are intentionally unchanged. Sealed
Approval request sinks and the Petal contract pin are explanation-only items.

## Architecture

VFS fixes stay in `WalletsHandler` and retain the existing handler contract.
The registration parser accepts one trimmed wallet name and constructs the
same internal registration request used today; no Broker protocol or operation
discovery changes are included.

The daemon is the sole runtime owner. Existing narrow VFS and Petal IPC methods
remain preferred where they already fit. Additional typed IPC methods or a
narrow command-service seam may be added for commands currently implemented in
the CLI process, but execution must happen inside the running `serve` process.
Client-side formatting and writing explicitly requested output files may remain
in the CLI after the daemon returns authoritative data.

An explicit endpoint failure is terminal. No non-`init`/`serve` command may
silently construct a daemon, acquire the Machine home lock, read Machine-owned
runtime state directly, or connect directly to Broker as a fallback.

## Error handling

- Missing or unreachable daemon endpoints fail closed with the endpoint in the
  error context.
- Daemon RPC errors retain their structured JSON-RPC code and message.
- Plain wallet names are trimmed and validated using the existing wallet-name
  constraints; JSON and legacy wallet descriptors are rejected.
- Outbox lookup returns `NotFound` for absent artifacts while preserving the
  four virtual pending controls.

## Testing

Every change follows red-green TDD. Focused tests cover list/lookup mode parity,
Petal commands with the daemon lock held, plain-name registration, explicit
missing-endpoint behavior for every CLI family, IPC output parity, Interaction
Modes documentation, and phantom-file rejection. Each commit runs its focused
suite before the next task begins. Final verification runs the workspace suite,
with the pre-existing deterministic `bloom-daemon` provenance test failure
reported separately.
