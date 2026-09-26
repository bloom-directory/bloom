# Hosted relay trust

These public trust inputs are included in the authenticated release payload.
They contain no installation credentials and allocate no hostname themselves.

- `control-ca.pem`: ISRG Root X1, SHA-256
  `96bcec06264976f37460779acf28c5a7cfcfea1c0aae11a8ffcee05c0bddf08c6`.
  The control endpoint still requires normal TLS hostname verification.
- `receipt-public-key.hex`: the deployed relay's Ed25519 allocation-receipt
  verification key, checked against the operator's public file over SSH on
  2026-09-23. Signer independently verifies assignments using this pin.

The installer materializes root-only `relay.json` and `relay-control-ca.pem`
under the existing per-login configuration root and fills an absent/null Signer
receipt pin before service activation. Existing matching configuration is left
unchanged. A different CA, receipt pin or relay configuration fails installation
rather than silently rotating trust. Rotation requires a separately reviewed
procedure. Installation identities and scoped credentials are never packaged.

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
