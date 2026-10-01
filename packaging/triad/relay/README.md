# Hosted relay trust

These public trust inputs are included in the authenticated release payload.
They contain no installation credentials and allocate no hostname themselves.

- `control-ca.pem`: the control endpoint's trust anchors, ISRG Root X1
  (SHA-256 `96bcec06264976f37460779acf28c5a7cfcfea1c0aae11a8ffcee05c0bddf08c6`)
  and ISRG Root X2
  (SHA-256 `69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470`),
  so the control certificate may chain to either. The endpoint still requires
  normal TLS hostname verification.
- `receipt-public-keys.hex`: the relay's Ed25519 allocation-receipt
  verification keys, one per line: the current key, then its pre-published
  successor. Both are AWS KMS keys; the successor signs only after a rotation
  or a compromise of the current key, so the relay can switch to it without
  a client update. Signer accepts a receipt signed by either.
- `superseded-pins`: the pins earlier signed releases installed (CA file
  digests and receipt key sets).

The installer materializes root-only `relay.json` and `relay-control-ca.pem`
under the existing per-login configuration root and fills the Signer receipt
pins before service activation. Each installed pin is judged on its own: the
release's value is left unchanged, a value listed in `superseded-pins` is
replaced (an upgrade adopts the release's pins), and anything else fails
installation before any write. An edited pin, or a newer release's pins met
by an older installer, therefore fails rather than silently rotating trust.
Rerunning after an interrupted install finishes it. Installation identities
and scoped credentials are never packaged.

To change pins in a release, move the outgoing values into `superseded-pins`
in the same change. Never list a value there that was not shipped in a signed
release.

The hidden Machine `init triad-install-relay-trust` command is an installer
renderer, alongside the existing enrollment renderers. It performs no network
requests or Signer RPC. Provisioning remains `bloom-signer admin provision`.
The implementation uses serde_json for lossless field preservation, rustix for
no-follow input opens, and tempfile for private atomic staging. Custom code is
limited to the installer-specific ownership, pin-consistency and retry rules.

Public enrollment remains an operator-controlled rollout gate. A closed gate
must produce a provisioning-pending message, while preserving localhost access
and the installation's durable retry identity. Never use a new key or operation
to work around an ambiguous allocation response.
