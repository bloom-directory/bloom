# Triad Services-Only Machine Development Loop

## Goal

Let a developer keep the triad's Session Sentinel, Signer, and Broker running
while repeatedly rebuilding and restarting Machine in a separate terminal.
Machine iteration must not restart or discard the state of the other services,
must not require an NFS mount, and must continue to use the isolated developer
enrollment rather than an installed production enrollment.

## Launcher Interface

Add a `--services-only` flag to `scripts/triad-dev-launch.sh`. Without the flag,
the existing full-triad behavior remains unchanged. With the flag, the launcher:

1. Builds the binaries needed to prepare the developer enrollment and run the
   services.
2. Creates or reuses the isolated developer enrollment and Machine home.
3. Prepares configured developer Petals exactly as full-triad mode does.
4. Starts the Session Sentinel, Signer, and Broker.
5. Writes the complete Machine environment to `triad.env`.
6. Publishes readiness after Broker is ready, prints the Machine development
   commands, and remains in the foreground supervising its three children.
7. Does not start, probe, mount, or otherwise own a Machine process.

`--mount` is invalid with `--services-only` because mounting belongs to the
manually launched Machine. This avoids accepting an option that the launcher
cannot honor.

## Machine Preparation

Services-only mode retains the existing one-time Machine preparation. This is
not equivalent to `bloom init`:

- the developer enrollment renderer creates the shared edge manifest,
  identities, service configs, and provenance catalog;
- the isolated Machine config is copied from
  `BLOOM_TRIAD_DEV_MACHINE_CONFIG`, or `~/.bloom/config.toml` by default;
- production preinstalled-Petal downloads are disabled in the isolated config;
- explicitly selected developer fixtures and integration Petals are installed
  into the isolated Machine home.

Preparation may invoke the current debug `bloom` binary, but it does not start
Machine. Subsequent Machine rebuilds do not require restarting the services.

## Developer Environment and Commands

The generated `triad.env` remains the single source of connection and identity
configuration. It exports the isolated Machine home, Machine RPC endpoint,
Broker socket, developer identities and trust documents, and audit checkpoint
paths.

It also prepends the directory containing the selected Machine binary to
`PATH`, while preserving the terminal's existing `PATH`. After sourcing the
file, `bloom` therefore resolves to the debug build selected by the launcher.
The launcher cannot modify another terminal's environment, so it prints an
explicit source command rather than attempting to export variables sideways.

The intended second-terminal loop is:

```bash
source /path/to/logs/triad.env
cargo build -p bloom --no-default-features --features mount,triad-dev-harness && \
  bloom serve --endpoint "$BLOOM_RPC_ENDPOINT"
```

The developer stops Machine with `Ctrl-C`, rebuilds, and runs the same serve
command again. No kernel mount is used unless the developer explicitly adds a
`--mount` argument to that manual command.

## Process Ownership and Cleanup

The services-only launcher remains in the foreground. It owns and supervises
the Session Sentinel, Signer, and Broker, but never owns a manually launched
Machine.

If any owned service exits, the launcher reports the relevant log and exits
after cleaning up the remaining owned services. On `EXIT`, `INT`, `TERM`, or
`HUP`, cleanup terminates and waits for all owned service processes and removes
only the per-run runtime directory. A separate teardown command is deliberately
omitted: normal foreground process ownership provides deterministic cleanup
without the stale-PID and wrong-process hazards of an external PID-based stop
operation.

Stopping the services launcher does not stop a manually launched Machine. The
developer stops that process in its own terminal. If the services launcher is
restarted, its per-run socket paths change, so Machine must also be restarted
after sourcing the newly generated `triad.env`.

## Readiness and Files

In full-triad mode, the ready file continues to mean that Machine passed its IPC
probe and any requested mount is usable. In services-only mode, it means that
Session Sentinel, Signer, and Broker are running and Broker published its
socket. Cleanup removes the ready file only when it is the exact path supplied
to this launcher.

The environment file is written before readiness and has mode `0600`. The
launcher prints its path and the exact build/serve commands only after service
readiness succeeds.

## Error Handling

- Reject `--services-only` combined with `--mount` before building or starting
  processes.
- Preserve existing fail-closed validation of enrollment files, identities,
  sockets, and mutable paths.
- Treat an owned Session Sentinel, Signer, or Broker exit as fatal in
  services-only mode and identify the failed service using its log.
- Never remove a Machine socket or terminate a Machine process in
  services-only cleanup.
- Keep existing full-triad startup, readiness, mount fallback, and cleanup
  semantics unchanged.

## Tests

Static launcher contract tests will verify that:

- `--services-only` is parsed and rejects `--mount`;
- Machine startup, IPC probing, and mount checks are skipped in services-only
  mode;
- Session Sentinel, Signer, and Broker remain required and supervised;
- `triad.env` prepends the selected debug-binary directory to `PATH` while
  retaining all existing Machine environment exports;
- services-only instructions show the exact source, build, and serve workflow;
- cleanup covers `HUP`, removes the ready file, and never claims ownership of a
  manually launched Machine;
- existing full-triad and VFS-only launcher contracts continue to pass.

Shell syntax validation and the affected Rust integration tests complete the
verification.
