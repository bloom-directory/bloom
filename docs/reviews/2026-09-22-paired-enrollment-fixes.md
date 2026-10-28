# Paired-enrollment preparation fixes

Real-browser testing of remote-to-local passkey enrollment exposed two failures
after clicking **Prepare enrollment**:

- Broker started a ten-minute deadline at link creation; Signer started a new
  ten-minute deadline at the later pairing request. Broker correctly rejected
  the later expiry. The request now carries the original absolute deadline;
  Signer validates its remaining lifetime and binds retries to that deadline.
- The durable Broker store still required a unique operation ID for every
  browser session. Pairing needs a destination and auxiliary source session for
  one operation. An atomic, audited migration preserves existing rows and
  replaces the constraint with uniqueness for primary sessions only.

Probe cleanup also exposed incomplete cancellation handling. Signer now durably
cancels pairings and rejects reopening them, fencing completion before dropping
in-memory material. Broker cancels both tabs so the auxiliary source no longer
blocks a new enrollment for the wallet. Committed operations remain uncancellable.

## Candidates and evidence

- Signer: `68f483eefb36d10a4227f01c4059494abc6ef402`.
- Broker: `46486312a3d9057682cbfc8b1d4685c60190a31d`.
- Running Machine binary remains `537efa3be070005afbf203cce857d4c2f9affe41`;
  Machine source changes only repin dependencies, release metadata and CI.
- Signer: 42 ceremony tests and 51 API tests passed. Regression covers delayed
  pairing, fixed deadline/retry identity, expiry bounds, cancellation and refusal
  to reopen a canceled operation. Strict Clippy passed.
- Broker: 51 ceremony tests and five browser tests passed, plus the persistent
  migration regression. Focused cancellation tests and strict Clippy passed
  after the final cleanup change. Older assertions expecting the previous root
  page/error text were aligned with the already implemented UI behavior.
- Machine: eight launcher tests passed after repinning; no Machine runtime
  behavior or authority protocol changed.
- Live dev triad: delayed pairing returned HTTP 200 with the exact original
  expiry; the source approval session loaded via public HTTPS with HTTP 200.
  Cancellation returned HTTP 204. A subsequent pairing/cancellation probe
  confirmed that a fresh enrollment can immediately be created after backoff.

The existing disposable wallet and relay installation were preserved through
restarts. Probes did not enroll or replace credentials. The user subsequently
completed remote-to-local enrollment with a real browser/passkey. Operation
`8c1f176e644ad7f415c5b92bff58d732545796986b0cc5fe29351fd68d4a3d55`
reports `SUCCEEDED`, with receipt digest
`2ac7576fcb77d8ac6daacd7fc1121d6723316dcca3a883ad02ae59adca387717`.
The authenticated Broker wallet projection for `browser-pair-20260922` shows
two `ACTIVE` credentials, one on `local` and one on `remote`. This verifies
real-browser source authorization and destination credential creation. It does
not establish the reverse direction or a fresh post-enrollment approval test.
No capability URLs, browser cookies or private key material are included here.
