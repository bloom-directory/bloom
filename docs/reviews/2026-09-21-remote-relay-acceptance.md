# Public relay acceptance — 2026-09-21

A disposable macOS developer Triad completed remote WebAuthn registration,
policy authorization, Sealed Approval activation, and separate execution through
public HTTPS. The relay did not terminate ceremony TLS. Execution used only a
loopback Anvil chain (31337); no installed wallet state or real funds were used.

## Candidate and evidence

- Machine: the source revision containing this record; `mount,triad-dev-harness`.
- Broker: `76449ab6a19e0982db4c4a739ed48c2f6a63ca10`, `triad-dev-harness`.
- Signer: `61dbbf14211d54c728e910eb30129a82c2d7a90b`, `triad-dev-harness`.
- Shared runtime: `a046fd6075853e8591f295983b572c6e1d65d12d`.
- Relay borrower API: `6c8771b66b618cd13b7cad3e0cd850af2982b5aa`.
- Deployed relay binary: `9cd5864a5f025b66a97569c1a473761ac5da0de7`
  (the later borrower revision changes documentation).
- Installation: `52d66cf9-3347-4b17-858e-b53e786cff0b`.
- Host: `5ixwab6amyu7e42fjobm3myxqe.relay.bloom.directory`.
- Local evidence: `/tmp/bloom-relay-e2e-20260921/case-2`, owner-private.
  Capability URLs and authenticator material are not published with this record.

SHA-256 of the exact copied executables:

| Executable | SHA-256 |
| --- | --- |
| Machine | `af31556061d54ad7b067fbdd2e1f5e861a5201d43f0e65fba0c70e1a0989dd95` |
| Broker | `25b39669562fa45ea725ee39d3d968d9453dbaba5af90bb0c7b102513ef33e57` |
| Signer | `553511d4a0d8d303a12280757bfd4c463f325d30108183347727085748345712` |
| Debug driver | `2469f2f293b3d7587421b19829d227c290070221d43a4134d60b9927dbab0430` |

The saved administrator operation recovered the same allocation after interrupted
provisioning. Production CA issuance completed through scoped DNS-01; Signer
reported `remote_enabled`, `remote_tls_ready=true`, and
`remote_routing_ready=true`. Operator-only enrollment was closed immediately
after assignment and remained closed during wallet acceptance.

The final rerun after a persisted-state restart first required HTTP/2 browser
navigation to return 200 over normal public TLS.
`scripts/test-remote-relay-approval.sh` then passed every assertion:

1. A fresh virtual WebAuthn authenticator registered wallet
   `relay-e2e-1790019658` at the exact public origin/RP ID.
2. Remote WebAuthn authorized the destination policy update.
3. Execution before Sealed Approval was refused and created a durable approval
   operation.
4. Remote Sealed Approval completed while sender nonce and recipient balance
   remained unchanged.
5. A separate VFS confirmation dispatched the approved transfer. The terminal
   projection cleared the ceremony URL and reported `sign_dispatched=true`.
6. Transaction `0xfe598d0e6a3af9515bd6814629dae888ab6a3e73d7aa7219aeb0666e82203cc4`
   mined successfully in block 2. Sender
   `0x5d4de4a59c124d70add57316c70be6fbb5f28830` advanced from nonce 0 to 1;
   `0x000000000000000000000000000000000000dead` received exactly 1 ETH.

## Fixes exercised

- Signer's administrator retains the allocation operation across retries and
  permits the validated same-UID developer principal only in harness builds.
  Production administration remains root-only.
- WebAuthn RP IDs use their own DNS-validated type. Numeric-leading assigned
  hosts are accepted without relaxing generic protocol tokens or surface scope.
- Broker normalizes HTTP/2 `:authority` into the existing exact-host checks,
  rejecting missing, duplicate or conflicting authorities. A live browser-style
  HTTP/2 request exposed this after the first HTTP/1.1 native acceptance pass;
  router regressions and the full public rerun now cover it.
- Broker explicitly selects its existing AWS-LC rustls provider when relay
  dependencies also enable ring.
- The debug driver reuses maintained `ureq` and `url`, existing virtual WebAuthn,
  HPKE and canonical challenges. Custom code implements only Bloom's fragment
  exchange, scoped cookie/CSRF contract and exact origin binding.
- The launcher preserves relay trust pins and administrator state, provides a
  private admin socket, sets the Broker credential directory's actual group,
  and requires authenticated end-to-end readiness.
- `triad-health-check` honors the configured Machine client endpoint; true
  lifecycle commands retain their endpoint-ignore behavior.

## Validation and remaining scope

Machine client: 53 tests passed. Machine CLI: 66 tests passed, including the
nondefault health-check endpoint regression and existing lifecycle behavior.
Strict all-target Clippy for Machine and its client passed with the harness
feature set; formatting and diff checks passed.
Release checks: 51 passed on macOS; ten Linux installer cases hit BSD `mv`'s
lack of `-T`. The maintained Debian container reran all 21 Linux-selected release
tests as unprivileged `nobody`: 21 passed, including those ten cases.

Broker: API 44 tests, debug driver 9, browser suites 11 and three canonical
loopback tests passed; workspace strict Clippy passed. The final HTTP/2 router
regression covers root, CSS, exchange, matching authority/Host, and rejection
cases; all-target/all-feature strict Clippy passed again. Host Node ICU and sandbox
bind failures were rerun with a working Node and loopback access. Signer: API 51,
WebAuthn 41 and both production/harness strict Clippy passed.

This proves the native remote protocol with a virtual authenticator, not browser
JavaScript, real authenticator PRF support, phone enrollment or cross-surface
pairing. The Triad remains disposable and uses no kernel mount. Installed macOS
NFS acceptance and the user-deferred two-login workflow remain separate.

Production rollout still requires independent backup/restore-witness retention
and disaster-recovery drills tracked by bloom-relay issue #2, monitoring/alert
and CT containment checks, and real-browser/passkey acceptance. No release was
published or PR merged by this acceptance run.
