# Card checkout Stage 0 spikes

Throwaway feasibility probes only; no checkout service or card custody changes.
The workspace decision record is in
`shared/card-checkout-evidence-2026-10-08/decision-record.md`.

Install `playwright-core@1.64.0` with scripts disabled in private scratch. Use
the absolute path to its module as the first argument to each JavaScript probe.
They use `/usr/lib/chromium/chromium` directly, fresh profiles, the Chromium
sandbox, and a CDP pipe. They never open a personal profile or submit payment.

- `card-checkout-browser.cjs MODULE [HTTPS_URL]`: anonymous pipe and optional
  public-page check. Saves only bounded public metadata; retains the anonymous
  profile. A public landing page is not checkout acceptance.
- `card-checkout-hpke.cjs MODULE BROKER_APP_JS`: executes the unchanged Broker
  crypto in Chromium using synthetic input. Runs a round trip and rejects
  tampered ciphertext, AAD and HPKE domain. This is not a passkey ceremony or
  a Signer interoperability test.
- `card-checkout-principal.py`: run under a root-created DynamicUser unit as
  described in the decision record. Emits a browser PID and profile location
  for negative-access probes by the login user. Its optional `--fixture-root`
  only tests pipe plumbing as the current UID; it proves no isolation.

No cookie-transfer probe is implemented yet: real sites and an authorized
shopping session are prerequisites. Never place cookie values, launch tokens,
card details or complete private checkout URLs in shared evidence.
