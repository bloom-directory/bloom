# Open-Internet Sealed Approval Ceremony

**Status:** agreed target architecture; implementation pending, 2026-09-17.

This replaces the historical Machine-owned relay proposal. It extends the
[Triad architecture](../specs/2026-07-23-triad-process-architecture.md) and
[Wallet architecture](./Wallet.md) with remote surfaces, two-origin credential
enrollment, and rotating recovery. Existing custody, policy, exact KeyRef,
review, and execution boundaries remain authoritative. The implementation must
reconcile the affected normative Triad sections with these explicit extensions;
this document is not evidence that remote support already exists.

Sources: [original proposal and review comments](https://gist.github.com/GavinPacini/a883117eb19324f01ad0b4affb35fd5c),
[narrowed v1 proposal](https://gist.github.com/GavinPacini/cb6ad4f132726b5d87335a3510728520),
and subsequent product decisions captured here. This revision supersedes the
v1 gist's one-home-surface restriction and deferred cross-origin enrollment.
The [implementation plan](../plans/2026-09-17-remote-ceremonies.md) defines handoff
and acceptance evidence.

## Product scope

Setup enables remote ceremonies by default through Bloom's hosted blind relay
for a **self-hosted** Machine, Broker, and Signer. No user domain or manual
configuration is required for this default. Setup reports provisioning status
and explains how to choose localhost-only operation. Failed provisioning is
reported as incomplete and retryable, never as working remote access.

V1 supports exactly the canonical localhost surface and one stable assigned
relay surface per installation. Official Bloom-hosted Triads, custom domains,
LAN/VPN origins, alternate relay providers, and cross-Triad wallet transfer are
deferred. Localhost means a browser on the Bloom host, not another device on a
private network.

A user can enroll local and remote access to the same wallet. These are two
RP-specific passkeys, even if saved in one password manager. One passkey is not
portable between these origins. New wallets may register remotely first;
existing localhost wallets retain their credentials. Adding access preserves
existing credentials; recovery replaces existing credentials.

## Authority and transport

```text
Browser -> HTTPS <random>.relay.bloom.directory
        -> blind TCP relay -> outbound authenticated Broker tunnel
        -> Broker-owned ceremony application -> local Signer

Machine -> authenticated Broker RPC -> authenticated Signer RPC
Privileged local bloom-signer administration -> Signer-owned administrative state
```

Broker owns browser serving, TLS termination, review, sessions, and policy
semantics. Signer owns wallet custody, surface eligibility, independent proof
verification, credential commits, and signing. Machine projects Broker-returned
URLs and public status only; it never serves browser traffic, holds wallet
secrets, or connects to Signer. Browser PRF and recovery secrets are HPKE-encrypted
directly to Signer. Relay traffic cannot reach either authority RPC, Machine,
Signer, control sockets, or filesystems.

Ceremony completion activates authority only. Execution and broadcast remain
separate Machine operations. Reuse the existing `review_manifest_digest` in
terms, contribution, browser session, completion, receipt, and audit. This does
not prove what compromised Broker-served JavaScript displayed. Broker/browser
compromise remains an accepted trust limitation; TLS-terminating ingress is
inside the Broker boundary.

## Surfaces and credentials

Signer owns surface descriptors with stable ID, exact origin, derived RP ID,
creation timestamp, and separately mutable lifecycle state. Identity is immutable
once activated. A versioned canonical identity digest excludes mutable state;
state changes have a separate monotonic revision and audit trail.

| Surface | Exact origin | RP ID |
| --- | --- | --- |
| Local | `http://localhost:18734` | `localhost` |
| Remote | `https://<random>.relay.bloom.directory` | exact assigned hostname |

Remote origins require lowercase ASCII hostname, HTTPS and default port 443;
reject userinfo, paths, query, fragments, trailing dots, wildcards, and non-ASCII
names. Never use `bloom.directory` or `relay.bloom.directory` as an RP ID.
Descriptors cannot be created from Browser inputs or ordinary Broker requests.

Lifecycle states are `ACTIVE` (authenticate and enroll), `AUTHENTICATION_ONLY`
(existing credentials only), `DISABLED` (no ceremonies), and `TOMBSTONED`
(permanent retirement). Disabled and tombstoned surfaces cannot receive recovery.
The localhost surface remains ACTIVE for authentication, enrollment and recovery
in both modes. V1 exposure switching changes only the remote active/disabled
state; it does not rename origins.
Signer rechecks current eligibility at preparation and commit; disabling a
surface invalidates unfinished ceremonies using it without revoking credentials
or previously activated approvals.

Wallets may hold credentials for both surfaces on **one Signer**. There is no
single home-surface restriction. Bind credentials to wallet, surface, RP, public
key, PRF salt, independent WKEK wrap, counter, and active/revoked state. User
handles are stable per wallet/surface and distinct across surfaces. Credential
lookup includes surface identity. Browser options contain only eligible
credentials for that surface. Public projections expose surface and credential
state, never secret material. A synchronized copy is not independent redundancy.

Bind surface identity/digest into preparation, signed contributions, challenges,
sessions, WebAuthn options, completion, receipts, and audit. Signer verifies
exact origin, RP hash, cross-origin bit, challenge, UV, wallet/credential and
operation bindings. Reject foreign-Signer surface pairs and conflicting retries.
Upgrade existing localhost records without changing their RP, handles, wraps,
wallet root, or derived addresses; version protocol/storage changes explicitly.

## Adding local or remote access

Same-origin add/replace/remove retains the existing custody protocol. Cross-origin
addition has two bound legs, authority first, within one Signer:

1. Prepare exact wallet, operation, source/destination surface identities,
   credential-add terms, expiry, and independent leg capabilities.
2. At the source origin, an eligible passkey authorizes those exact terms with
   UV and sends its PRF envelope to Signer. No credential changes yet.
3. At the destination origin, the user creates a credential and supplies its
   PRF envelope. Signer verifies both legs and commits a new independent wrap of
   the same WKEK atomically. Existing credentials remain active.

Before source authorization, the destination browser establishes a session and
fresh ephemeral proof-of-possession key. Bind that public key and destination
session to the signed source terms/contribution and require possession at
enrollment. This non-authoritative pairing can precede the authority leg; new
credential creation and wallet enrollment cannot. Pairing must support a remote
phone and host-local browser without moving the private key between them.

The destination capability after source authorization is sensitive bearer
**enrollment authority**, additionally constrained by the paired destination key.
Do not expose it as an ordinary public URL. The detailed protocol must specify
canonical pairing messages, user confirmation of the intended destination,
single-use proof challenges and device/tab handoff before coding this seam.
Possession of an unpaired or stolen launch URL cannot substitute a destination
key after authorization. Losing the destination key requires restarting both legs.

Use a short absolute deadline, never extended by the first leg. Keep intermediate
PRF/WKEK material only in Signer volatile secret memory in v1; persist no plaintext
or restart-recoverable intermediate secret. Zeroize on terminal transitions.
Restart durably fails incomplete two-leg ceremonies and requires new authority;
committed results remain reconcilable. Disable core dumps and prevent secret
memory from entering swap where supported; document platform enforcement.
Exact retries return prior progress/result; reordered, substituted, concurrent
conflicting, expired, and cross-wallet/Signer legs fail closed. Replacement, if
exposed, activates the replacement and revokes only the explicitly selected old
credential in one commit. Removal preserves a usable credential or recovery.

## Exposure administration

Expose a small privileged `bloom-signer` interface: status, remote-enabled, and
localhost-only. Command spelling is an implementation detail. macOS `osascript`,
Linux `pkexec`, and a `sudo` fallback invoke the same validated administrative
operation. Setup uses that path to provision sane defaults. Machine is never an
administrative transport to Signer. Manual protected configuration plus restart,
if supported, must pass the same validation and cannot bypass transition guards.

Local elevation authorizes use of protected installation administration identity;
it does not authorize custody changes or authenticate a network request by itself.
Signer owns desired exposure state and revision. Broker observes authenticated
state through its existing edge and applies listener/tunnel changes. Status
separates desired state from effective readiness; restart resumes reconciliation.
Broker reports effective listener/tunnel state tagged with the desired revision
over the existing Broker-to-Signer edge; the admin CLI reads it through local
admin IPC. Signer never becomes a Broker client. Disablement immediately fences
remote commits, then waits for Broker closure acknowledgement before reporting
effective completion. Enablement makes the remote surface ACTIVE only after
Broker reports valid certificate and routing readiness for that revision. A
staged HTTPS health endpoint may be reachable for readiness probes while the
remote surface is disabled; no wallet ceremony is permitted until activation.

The localhost-only command preflights and refuses with actionable wallet IDs
when any active wallet requiring passkey ceremonies lacks an active local
credential; it does not itself
authorize custody or silently start enrollment. Complete missing enrollment
through Broker's browser surfaces, then retry the command to commit disablement. The local leg requires a
browser on the Bloom host. Revalidate the wallet set and eligibility at commit to
avoid a concurrent new remote-only wallet or credential removal causing lockout.
Use an atomic wallet-set/credential-generation check or equivalent serialization.
This guard proves credential coverage, not that a user still possesses the
authenticator; tell the user this limitation. Deleted wallets are excluded;
active passkey-dependent wallets without usable local credentials are not silently
skipped. A credentialless backend wallet is excluded only when its authoritative
backend/custody contract requires no passkey ceremony for continued operation;
unknown requirements fail the preflight with an actionable reason.
If remote access is unavailable and local credentials are missing, use recovery
at the active local surface first. An incomplete transition does not claim success
or silently disable the remaining access path.

Disabling cancels unfinished remote ceremonies and closes outbound routing; it
does not delete remote credentials, hostname reservations, recovery material,
wallet keys, or approvals. Re-enabling reuses the same hostname and credentials,
requires valid TLS before remote readiness, and offers local-authorized remote
enrollment where needed. Local ceremonies remain independently available.

## Registration and recovery

Initial registration/import is prepared by locally authorized setup or existing
authenticated Machine-to-Broker custody operations, not unlimited public signup.
The first credential may be remote; PRF compatibility failure cannot commit a
wallet without a usable credential. Existing adjacent-assertion PRF handling is
retained. Recovery output is Browser-recipient HPKE ciphertext only.

Broker provides browser-initiated recovery bootstrap on active surfaces with
uniform non-enumerating responses. Recovery ID is identifying input; the secret
is sent only encrypted to Signer during completion. Bound resources and attempts
by source IP, installation, recovery ID, and global backoff; audit and alert abuse.
Unauthenticated attempts must not permanently lock out a wallet.

Successful recovery atomically activates the replacement credential, revokes all
prior credentials for that wallet across both surfaces, rotates the recovery
ID/secret and wrap, and leaves the root/addresses unchanged. Other wallets and
installation surface states are unaffected. Failed/cancelled/expired attempts do
not rotate the factor. Bind a per-wallet credential-authority generation into pending credential,
recovery and other passkey-authorized custody/approval ceremonies. Recovery
atomically advances it and completion rechecks it, so old first legs or pending
approval proofs cannot restore revoked access. This generation is distinct from
the existing approval revocation epoch: already activated Sealed Approvals remain
valid under their existing policy/expiry/revocation rules. Recovery grants no new
approvals and does not silently revoke existing ones.

Recovery commits once; interrupted delivery can retrieve the same encrypted
result for a bounded period. Exact retry never re-consumes the old factor or
rotates again. Retrieval uses the original Browser recipient binding; losing its
private key does not permit unauthenticated re-encryption. The replacement passkey
is already committed and remains usable for normal credential management. It
does not decrypt the lost result or imply an existing recovery-factor reset API;
the recovery backup stays unavailable unless an explicitly authorized factor-reset
flow is implemented later. If neither it nor valid recovery
material remains accessible, the result cannot restore access. Detailed
save-confirmation UX is deferred. Recovery cannot replace
lost Signer custody state; backups must preserve integrity and freshness of
revocations, counters, recovery state, and audit history.

## Browser sessions

Remote launch URLs use a random 256-bit single-use fragment capability. Generic
first-party code removes it from visible history, exchanges it over Broker TLS,
and discards it. Store only a verifier server-side. Exchange creates a distinct
short-lived host-only `__Host-` cookie with `Secure; HttpOnly; SameSite=Strict;
Path=/`. Do not put launch capabilities in cookies, logs, telemetry, initial
requests, localStorage, IndexedDB, or durable browser state. Fragment removal
cannot guarantee erasure from browser extensions or prior browser history.

Authorize every operation against its ceremony/session/leg, including result and
acknowledgement; one host cookie must not mix concurrent wallet ceremonies.
Require exact Host/Origin, same-origin Fetch Metadata for mutations, JSON content
type, bounded concurrency/bodies, no-store/no-referrer, strict CSP/frame denial,
and no CORS, third-party scripts/assets, analytics, or service workers. Local HTTP
retains its existing authenticated session mechanism; never weaken remote cookie
requirements to accommodate localhost. Redact sensitive URLs in public diagnostics.

## Relay and certificate operations

Allocate random non-semantic stable hostnames, permanently retained or tombstoned,
including across restore. Authenticate hostname ownership before routing; SNI only
selects an already authenticated installation connection. Separate scopes for
`tunnel`, exact-name `dns_challenge`, and privileged `surface_admin` enrollment or
ACME-account rebinding. Online tunnel compromise cannot obtain rebinding authority.
Protect admin identity under privileged local ownership; define loss/replacement
proof and relay enrollment reconciliation in the control-plane implementation.

Broker owns TLS and ACME keys. Use Let's Encrypt DNS-01 with hooks limited to the
assigned `_acme-challenge` TXT record, with no general DNS credential. Bind each
hostname to its registered ACME account URI; enforce exact-host restrictive CAA,
account/method restrictions and no wildcard issuance. ACME automation includes
staging validation, renewal timers, atomic validated reload, external health
checks, rollback only to a still-valid lineage, and expiry alerts. With no valid
certificate remote access fails closed, never to HTTP or another hostname.

The data-plane relay has no Broker TLS key or plaintext access. Bloom's DNS and
enrollment control plane are nevertheless trusted not to redirect or reissue
certificates. CAA and CT mitigate/detect this trust; CT monitoring has a 15-minute
alert target with containment/notification/revocation drills. Relay sees IPs,
ordinary SNI, timing, duration and byte counts. CT makes names discoverable.
Do not advertise ECH in v1; bound fragmented/malformed ClientHello parsing,
pre-routing bytes, setup timeouts, concurrency, reconnect and backpressure.
No untrusted forwarding header determines browser origin or surface authority.

Use host-only state and exact origin/RP enforcement for sibling isolation; pursue
Public Suffix List registration as defense in depth. DNS mutations reject sibling,
parent, wildcard, stale/replayed and concurrent-substitution requests. Certificate
inventory must accommodate authorized key rotation. Relay outages never extend
ceremonies, change operation identity, or interrupt independently usable localhost
credentials. No service silently restores retired Machine authority fallbacks.
