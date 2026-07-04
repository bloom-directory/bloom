# Interaction Modes

**Status:** architecture decision
**Audience:** Bloom engineers, Petal authors, and implementation agents

Bloom actions must work through three interaction modes:

1. CLI only
2. VFS with no long-running daemon
3. Mounted VFS with a daemon

This requirement applies to every Petal, including first-party Petals such as
EVM wallet, paid HTTP, DeFi, Polymarket, Hyperliquid, wallet policy, and future
WASM Petals.

The user and agent should not need to learn a different authorization model for
each Petal. A Petal may expose domain-specific paths and commands, but those
paths and commands must map onto the same action lifecycle:

```text
stage action
review plan
request execution
obtain Sealed Approval when needed
execute under sealed grant or bounded capability
record audit/result
```

## Core Decision

Every Bloom action surface must support these modes:

| Mode | Who owns execution state? | Who may open a browser ceremony? | Expected behavior |
|---|---|---|---|
| CLI only | The foreground `bloom` process | The foreground `bloom` process | One command may stage, issue a challenge, run the browser ceremony, mint an in-process grant, retry execution, and finish. |
| VFS with no daemon | The foreground `bloom vfs ...` process | The foreground `bloom` process | The CLI VFS facade may run the same foreground state machine as a domain CLI command. |
| Mounted VFS with daemon | The daemon serving the mounted filesystem | Any deliberate client that expects the challenge — the writing agent or a foreground `bloom` command — opens or forwards the daemon-minted ceremony URL; the daemon never opens a browser itself | Mounted writes stage/challenge or execute already-authorized work. The challenge exposes a `ceremony_url`; writes must not silently pop browser windows from arbitrary filesystem writes. |

## Mode 1: CLI Only

In CLI-only mode, there is no separate daemon process. A command such as
`bloom wallet confirm`, `bloom request confirm`, or a Petal-specific foreground
command builds an in-process daemon and drives the complete action state
machine.

For any Petal action, the command should:

1. load or stage the action;
2. render or locate the daemon-produced plan;
3. evaluate policy and active capability;
4. if fresh approval is required, issue a Sealed Approval challenge;
5. open the browser ceremony from the foreground process;
6. receive WebAuthn assertion plus PRF output over the trusted local ceremony
   channel;
7. verify approval, mint the in-memory grant, and cache any short-lived signer
   material under that grant;
8. retry execution from the sealed action bytes;
9. write result and audit artifacts.

This mode is useful for scripts, tests, and users who do not keep `bloom serve`
running.

## Mode 2: VFS With No Daemon

In this mode, the user invokes VFS operations through the `bloom vfs` CLI
facade, for example:

```text
bloom vfs write /<petal>/<...>/new --data ...
bloom vfs write /<petal>/<...>/pending/<id>/confirm --data confirm
```

There is still no long-running daemon. The foreground CLI owns the process,
therefore it may run the browser ceremony when a write discovers that Sealed
Approval is needed.

The CLI VFS facade should reuse the same action-state helper as the equivalent
domain command. It should not implement a separate authorization path.

For example, a VFS write to a Petal's confirm/execute file may:

1. attempt the write once;
2. if the handler stages an approval challenge and returns approval-required,
   run the browser ceremony in the same foreground process;
3. mint the in-process grant;
4. retry the same VFS write;
5. return success or the final denial.

## Mode 3: Mounted VFS With Daemon

In this mode, `bloom serve --mount` runs a daemon and exposes a mounted
filesystem.

Mounted VFS writes may come from an agent, shell tool, editor, file sync tool,
or any other local process. Therefore a mounted write is not a safe UX trigger
for opening a browser ceremony. It is, however, a safe trigger for *exposing*
the ceremony URL: the writer that requested execution is expecting the
challenge and can correlate it to the exact action directory it wrote to.

Mounted handlers must follow this rule:

```text
mounted write may stage or execute
mounted write may issue or expose approval challenge (including ceremony_url)
mounted write must not open a browser ceremony
the client that expects the challenge deliberately opens or forwards the URL
```

The deliberate client can be the writing agent itself or a foreground `bloom`
command. The normal pattern for an agent working through the mount is:

1. agent writes to the mounted Petal staging path; the pending directory
   (for example `/outbox/pending/<action_id>/`) materializes, so the agent
   knows the concrete `action_id`;
2. agent writes to the mounted execute/confirm path for that action;
3. the daemon stages the sealed action, issues the approval challenge, mints a
   ceremony URL bound to the challenge's `server_nonce`, and writes
   `approval_challenge.json` — including `ceremony_url` — into the same
   pending directory; the file must be durably visible before the write
   returns;
4. the confirm write fails with permission denied;
5. the agent, having just received permission denied on its own confirm write,
   reads `approval_challenge.json` from the same pending directory and checks
   that `action_id` matches the path and `expiry_ms` is in the future — this
   is the "expecting a challenge" condition: the trigger is the agent's own
   failed write, and the challenge is read from the directory it wrote to;
6. the agent opens the browser for the user or sends `ceremony_url` to the
   user over another transport (chat, notification, and so on);
7. the user completes the WebAuthn ceremony; PRF output goes into daemon
   memory only; the ceremony page offers **grant** and **grant + execute**,
   and the user chooses;
8. under **grant**, the daemon mints the grant and the agent retries the
   confirm write, which now executes; under **grant + execute**, the daemon
   executes immediately after minting the grant;
9. mounted VFS projections move the action to sent/failed with result
   artifacts.

The `ceremony_url` is single-use and valid until the challenge's existing
`expiry_ms`; there is no separate URL expiry. While an unexpired challenge is
pending, repeated confirm writes return the same challenge and the same URL —
the daemon must not rotate the nonce or URL on retry, so a URL already
forwarded to the user stays valid. Whether the URL is reachable only on
localhost or over the open internet is described in
[`Open-Internet Sealed Approval Ceremony.md`](./Open-Internet%20Sealed%20Approval%20Ceremony.md).

## Foreground Command Shape

The default foreground command should be the same command users already run to
execute the action, not a second generic approval command.

Prefer:

```text
bloom <surface> confirm <action-ref>
```

over:

```text
bloom <surface> approve <action-ref>
bloom <surface> confirm <action-ref>
```

The `confirm` command should behave as a state machine:

```text
if action can execute now:
  execute
else if fresh Sealed Approval is needed:
  issue or load challenge
  run ceremony
  mint grant
  execute
else:
  return the denial
```

A separate `approve` command may exist later for debugging, administration, or
explicit "approve but do not execute" workflows. It must not become the normal
path required by every Petal.

## Petal Requirements

Every Petal that can move value, change authority, create credentials, spend a
budget, or consume bounded session authority must provide:

- a staging path or command that creates a central action;
- a daemon-rendered review plan derived from sealed bytes;
- a concrete action id, never `latest`, for approval binding;
- a Petal identity: `petal_id`, `petal_digest`, and `petal_version`;
- a sealed policy snapshot;
- daemon grant terms, including allowed signing intents and signature count;
- a foreground ceremony path for CLI-only and daemon-mounted operation;
- passive mounted-VFS behavior that stages challenges and exposes the
  `ceremony_url` in `approval_challenge.json` but never opens a browser;
- audit/result artifacts visible through the central outbox and any Petal
  projection.

Petal-specific names are allowed. The authorization behavior is not.

## Examples

These are examples of the same interaction contract, not separate systems:

- EVM wallet: stage a transaction, confirm it, run Sealed Approval when policy
  requires owner signing, then broadcast.
- Paid HTTP: stage a paid request, confirm the payment credential, run Sealed
  Approval when policy/session authority is insufficient, then send the HTTP
  request.
- Polymarket: stage onboarding, funding, order, redeem, withdrawal, or approval
  revocation actions; run the ceremony for any owner-signing or authority
  change; execute only from sealed action bytes.
- Hyperliquid: stage owner-signed `approveAgent`, `usdSend`, or recovery
  actions; run the ceremony for owner authority; subsequent bounded API-wallet
  trades may execute under the approved session.
- DeFi: stage routes and required approvals as ordered actions; run approval
  for the sealed route; execute the ordered plan without substituting steps.
