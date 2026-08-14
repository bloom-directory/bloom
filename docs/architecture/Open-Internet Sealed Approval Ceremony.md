# Open-Internet Sealed Approval Ceremony

> **SUPERSEDED — HISTORICAL ONLY.** Do not implement or follow the operational
> instructions below. They predate the triad authority boundary and incorrectly
> assign ceremony and signing material to Machine. The normative architecture
> is [`2026-07-23-triad-process-architecture.md`](../specs/2026-07-23-triad-process-architecture.md):
> Broker owns the loopback ceremony listener and authorization; Signer owns
> custody and signature production; Machine never terminates a custody channel.

**Status:** superseded historical record — not normative
**Audience:** Bloom engineers, Petal authors, and implementation agents

This document describes how the Sealed Approval ceremony URL becomes reachable
over the open internet, so an agent can send it to the user over Slack, chat,
or any other transport and the user can complete the ceremony from another
device.

The open-internet relay described here is not implemented today. The current
mounted-VFS implementation supports Bloom Machine-owned loopback ceremony URLs on
`http://localhost:18734`: `approval_challenge.json` carries a local
`ceremony_url`, the token is derived from `server_nonce`, and the Bloom Machine owns
grant minting for the mounted flows (the EVM outbox, paid-HTTP `/requests`, and
wallet policy updates). This document is the target design for
making that same ceremony reachable from another device over the open internet.
The `ceremony_url` contract itself — the field in `approval_challenge.json`,
single-use token, `expiry_ms` bound — is defined in
[`Sealed Approvals.md`](./Sealed%20Approvals.md) and
[`Interaction Modes.md`](./Interaction%20Modes.md) and applies in both exposure
modes.

## Decision Summary

- The ceremony URL is reachable over the open internet **by default**, via a
  relay.
- Exposure is configurable for security hardening:
  `ceremony.exposure = internet | localhost`, default `internet`.
- Exposure is **uniform across assurance levels**. There is no separate
  localhost-only handling for high-assurance actions; hardening means flipping
  the global setting to `localhost`.
- TLS terminates at the Bloom Machine. The relay is a blind forwarder and never sees
  plaintext.
- The ceremony page and API expose **grant** and **grant + execute** modes;
  the user decides how the approved action is executed.

## Relay Architecture

The Bloom Machine cannot accept inbound connections from the internet, so
reachability comes from an outbound relay connection:

```text
Bloom Machine holds a persistent outbound connection to the relay
relay routes by TLS SNI to the Bloom Machine's connection
Bloom Machine terminates TLS with a certificate for its stable hostname
browser <-- end-to-end TLS --> Bloom Machine, through the relay
```

Properties:

- The relay is a dumb SNI-routing TCP forwarder. It does not terminate TLS
  and never sees plaintext.
- Each installation gets a stable per-install hostname, for example
  `<node-id>.<relay-domain>`. The Bloom Machine holds the certificate and private key
  for that hostname.
- The ceremony URL shape is
  `https://<node-id>.<relay-domain>/ceremony/<token>`.
- A first-party hosted relay is the default; the relay endpoint is
  configurable so users can self-host.

**Why TLS must terminate at the Bloom Machine.** The ceremony returns PRF output —
wallet key-unwrap material — from the browser to the Bloom Machine. Sealed Approvals
requires PRF output to exist only on the trusted ceremony channel and in
Bloom Machine memory. With Bloom Machine-terminated TLS, that invariant holds even though
the bytes transit the internet. A relay that terminated TLS would be in a
position to read PRF output and to serve tampered ceremony JavaScript that
exfiltrates it. That design is forbidden.

## WebAuthn Consequences

- The WebAuthn RP ID becomes the stable per-install hostname
  (`<node-id>.<relay-domain>`), not `localhost`. Passkeys are bound to the RP
  ID, so registration and recovery ceremonies must also run on that origin.
- Existing credentials registered under RP ID `localhost` will not work over
  the relay. Migrating an installation to internet exposure requires
  re-registering credentials under the new RP ID.
- The relay's parent domain must be on the Public Suffix List so that one
  user's subdomain cannot set an RP ID that phishes another user's
  credentials.
- In `localhost` exposure mode, the RP ID question is a deliberate design
  choice at implementation time: keeping a single RP ID across both modes
  avoids maintaining two credential sets per wallet.

## URL and Token Security

- The URL token is at least 128 bits of entropy, single-use, and derived from
  the challenge's `server_nonce`, binding the URL to exactly one sealed
  action.
- The URL is valid until the challenge's existing `expiry_ms`. There is no
  separate URL expiry field.
- The token is considered used only after successful approval completion
  consumes the underlying challenge nonce; repeated page/plan/challenge reads
  before completion remain valid until `expiry_ms`.
- The Bloom Machine rate-limits ceremony endpoint traffic.
- Repeated confirm writes while a challenge is pending reuse the same URL; the
  nonce and URL rotate only after expiry or consumption.

**What URL possession gets an attacker — and does not.** Anyone holding the
link before it is claimed or expired can view the Bloom Machine-rendered plan
(amounts, destinations). They cannot approve: approval requires a WebAuthn
assertion with user verification from a passkey enrolled for the wallet. Plan
visibility to a link holder is the accepted tradeoff of the internet-default
posture. Users who do not accept it set `ceremony.exposure = localhost`.

## Uniform Assurance Handling

Exposure applies uniformly to all actions and assurance levels. High-assurance
actions (authority expansion, credential changes, re-keying) use the same
exposure setting as everything else. There is deliberately no per-assurance
carve-out forcing localhost ceremonies; the approval-security boundary is the
WebAuthn ceremony and the sealed challenge binding, not the reachability of
the ceremony page.

## Grant vs Grant + Execute

The ceremony page and its API expose two completion modes, chosen by the user
at approval time:

- **grant**: verify the approval and mint the grant only. Execution happens
  when the client (typically the agent that staged the action) retries the
  confirm write or command.
- **grant + execute**: verify the approval, mint the grant, and execute the
  sealed action immediately in the Bloom Machine. This matters for the remote case,
  where the user approving from another device may not have a client available
  to retry.

Execute applies only to broadcastable sealed actions (those carrying a
`chain_name`). For non-broadcast actions — wallet-policy updates and paid-HTTP
confirms — the two modes are equivalent: the ceremony mints the grant only, and
the action installs when the client retries the confirm write.

Auto-execution is never a silent Bloom Machine default.

## Changes From the Current Implementation

For orientation, the target relay design differs from today's code in these
ways:

- Today `bloom serve` binds the Bloom Machine-owned mounted ceremony server on
  `http://localhost:18734` with RP ID `localhost`; it does not expose that
  endpoint over the open internet.
- Today `approval_challenge.json` carries a local loopback `ceremony_url` for
  the mounted flows (EVM outbox, paid-HTTP `/requests`, and wallet policy
  updates). In the target relay design, the same projection
  points at a per-install HTTPS hostname.
- Today there is no relay, per-install hostname, internet exposure setting, or
  Bloom Machine-held public certificate for a relay hostname.

The relay-specific parts of this document are not normative until implemented.
