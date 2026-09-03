# Peer Coordination

**Status:** opt-in architecture overview
**Audience:** Bloom engineers, Petal authors, and agent integrators

Bloom peer coordination is a private, advisory request/response edge between
explicitly enrolled Bloom installations. Iroh 1.1 owns endpoint
authentication, encrypted QUIC transport, address lookup, NAT traversal,
direct-path upgrades, and relay fallback. Bloom owns enrollment, the signed
application protocol, replay protection, evaluator policy, and the Petal
sandbox boundary.

It is not an authority edge. Peer decisions never reach Broker or Signer and
cannot stage, confirm, sign, or broadcast an action. It is also not chat,
public agent discovery, a marketplace, copy trading, or remote execution.

## Trust and discovery

Operators exchange short-lived, endpoint-signed enrollment tickets through an
already authenticated channel. The resulting endpoint ID is the durable peer
identity and is stored in a local allowlist. Iroh address lookup can locate a
known endpoint ID; it does not provide a directory of agents, strategies, or
review capabilities. Bloom publishes no semantic discovery record.

Transport authentication and the Bloom envelope signature must name the same
endpoint. The envelope signature also binds message and correlation IDs, kind,
nonce, issue and expiry times, and the canonical payload digest. Bloom reserves
the sender/nonce pair durably before dispatch.

## Evaluation boundary

An inbound request names only a local evaluator alias and exact input/output
schemas. Configuration binds that alias to one installed Petal package hash
and route. The remote peer cannot select a package, route, capability, host,
wallet, or transaction operation.

Automatically invoked evaluators must declare zero capabilities. Bloom runs
them with no VFS, network, private store, signing, key derivation, chain,
Broker, Signer, or outbox access; a deny-all host; deterministic environment;
and bounded time, fuel, memory, input, and output. The package hash and
capability ceiling are checked both at daemon startup and immediately before
execution.

Bloom parses the bounded Petal output, constructs the response itself, and
forces `advisory_only = true`. The receiving agent must still apply local
policy and the normal Bloom authorization flow.

## Lifecycle and surfaces

Coordination is disabled by default. Daemon construction does not bind an Iroh
endpoint; the endpoint starts and stops with long-lived background tasks. When
enabled, the owner CLI manages identity, tickets, enrollment, evaluator
allowlists, requests, and status through `bloom peer`. The optional mounted
projection is under `coordination/` and is documented in the root agent
guidance.

The concrete configuration and operator workflow are in
[`../coordination.md`](../coordination.md).

## Threat model

Protected assets include wallet custody and Signer authority, Broker approval
operations, local Petal implementations and private policy data, VFS data
outside the explicit review input, transaction and broadcast paths, and daemon
availability. The dedicated Iroh identity is connectivity identity only:
compromise can impersonate that peer but must not grant wallet, Broker, or
Signer authority.

Required invariants are:

1. Coordination is disabled by default and opens no socket while disabled.
2. Only explicitly enrolled endpoint IDs may connect or be dialed.
3. The signed sender equals the endpoint authenticated by Iroh.
4. Nonces are reserved transactionally before dispatch.
5. Remote input cannot select a package hash, route, capability, or host.
6. Auto-run evaluators declare and receive zero capabilities, including no
   generic `vfs.read`.
7. Bloom parses bounded output, constructs the decision, and forces
   `advisory_only = true`.
8. No decision path reaches Broker, Signer, transaction staging, confirmation,
   or broadcast.

| Threat | Control |
|---|---|
| Replay | SQLite unique sender/nonce reservation |
| Spoofing | Iroh endpoint authentication plus bound application signature |
| Parser or memory abuse | Length prefix, allocation bound, and timeouts |
| Sandbox escalation | Manifest, installed-cap, route, and runtime checks |
| VFS exfiltration | No VFS capability; host-prepared input only |
| Model extraction | Per-peer allowlist, bounded output, and rate limits |
| Storage exhaustion | Bounded envelopes and TTL cleanup |
| Stale decisions | Exact request digest and `valid_until_ms` |
| Relay metadata leakage | Encrypted payloads; relays can still observe metadata |
| Remote trading | No execute message or transaction integration |

This design does not claim sandbox escape resistance beyond Wasmtime's
security boundary. Fuel, memory and output limits, host timeouts, dependency
updates, and adversarial fixtures remain defense in depth.
