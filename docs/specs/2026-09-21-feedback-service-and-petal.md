# Bloom feedback service and default Petal

Date: 2026-09-21  
Status: Implementation prepared; production deployment awaits Google Workspace and Cloudflare Access setup.

## Outcome and agreed scope

Users and agents can submit feedback to Bloom without creating an account.
`https://feedback.bloom.directory/` provides a simple public form; a default
Feedback Petal exposes the same submission capability in Bloom's filesystem.
Anyone with a Google Workspace account whose email domain is exactly
`bloom.directory` can sign in at `/admin` to read and triage feedback.

Confirmed decisions:

- Run the service as a Cloudflare Worker.
- Accept anonymous submissions with optional contact details.
- Include a public submission form and a private inbox with basic triage.
- Allow agents to proactively submit sanitized problem reports.
- Include Feedback in the next Bloom release's default Petals.
- Keep the feedback Petal repository public and the backend repository private.
- Keep the implementation and testing proportional to this small feature.

Implementation: one TypeScript Worker and D1 database per environment,
Cloudflare Access for staff authentication, and a separate Rust/Wasm Petal.
The repositories are `bloom-directory/bloom-feedback` (private backend) and
`bloom-directory/bloom-petal-feedback` (public Petal). Separate production and
preview D1 databases are provisioned; Workspace and Access configuration is
still required before deployment.

## Fit with the current code

Exploration used Bloom HEAD `e24009df510a2aa909d3ef33b85500b634983a0e` and the
current working tree, which contains unrelated uncommitted changes, including
Petal release pins. Recheck those pins during implementation.

- Petals already support synchronous HTTPS writes, private package-local KV
  storage, randomness, and dynamic routes. No host ABI extension is needed.
  See [authoring](../petals/authoring-petals.md) and
  [using Petals](../petals/using-petals.md).
- Integration was updated against Bloom v0.3.1 (`b287d7a3`). The canonical
  default catalog now lives in `github_source::DEFAULT_PETALS` and includes
  Polymarket, Hyperliquid, Enso, Near Intents, and Tolly. Legacy configured
  `preinstalled` lists are ignored by upstream; no list migration is added.
- [github_source.rs](../../crates/bloom/src/github_source.rs) pins prebuilt
  archives and provenance; [petal_provisioning.rs](../../crates/bloom/src/petal_provisioning.rs)
  makes a best-effort provisioning pass after daemon startup. Explicit
  `bloom init` also provisions defaults.
- Feedback needs no wallet, Broker, Signer, signing permission, or broad VFS
  access. A feedback-service outage must not impair wallet operation.

## Architecture

```text
Public browser form ──┐
                     ├── POST /api/v1/feedback ── Worker ── D1
Feedback Petal ───────┘

Staff browser ── Google sign-in / Cloudflare Access ── /admin/* ── Worker ── D1
```

Serve both small interfaces from the Worker using HTML templates, ordinary
CSS, and minimal browser JavaScript. Use Bun for tooling, Wrangler for local
development/deployment, parameterized SQL, and checked-in SQL migrations.
A frontend framework, ORM, separate API server, queue, and object store are
unnecessary for v1. Reuse Bloom's visual style without coupling this service
to the marketing website's deployment. The private backend repository owns
the service, public-form/admin UI source, database migrations, and deployment
configuration; credentials belong in managed secrets, not Git. The public
Petal repository owns its source, operating documentation, and public release
assets. Document the public submission contract there so contributors can
build and use the Petal without access to the private repository. Repository
privacy does not authenticate the public submission endpoint.

## Submission contract

`POST /api/v1/feedback` accepts JSON. No login, API key, wallet signature, or
browser challenge is required. Browser and Petal clients use the same schema.

```json
{
  "submission_id": "629971a9-52c2-48c2-9920-2937060847c9",
  "kind": "bug",
  "message": "After restarting Bloom, this documented path returns not found. Steps: ...",
  "reporter": "agent",
  "contact": null,
  "context": {
    "bloom_version": "<installed-version>",
    "platform": "linux-x86_64",
    "petal": "near-intents"
  }
}
```

| Field | Contract |
| --- | --- |
| `submission_id` | Required random UUID v4, generated once per report and reused for retries. |
| `kind` | `bug`, `feature`, or `other`; defaults to `other`. |
| `message` | Required nonblank text, maximum 16,000 UTF-8 bytes. |
| `reporter` | `human` or `agent`; defaults to `human`. Self-reported, not authenticated identity. |
| `contact` | Optional plain text, maximum 320 UTF-8 bytes; email or another contact handle. Unverified. |
| `context` | Optional object containing only the three fields shown; each at most 100 UTF-8 bytes. |

Reject unknown fields, wrong types, and bodies larger than 32 KiB, including
streamed bodies without a trustworthy Content-Length. Omitted optional fields
and explicit nulls normalize identically; empty optional strings become null.
Reject an invalid provided enum rather than silently replacing it.
Retain the message's formatting. The Petal can add its own build version in a
User-Agent header; the service need not persist that header.

Successful durable insertion returns `201`:

```json
{
  "submission_id": "629971a9-52c2-48c2-9920-2937060847c9",
  "state": "received",
  "received_at": "2026-09-21T12:00:00Z"
}
```

An identical retry returns `200` with the original receipt. The database's
unique submission ID prevents duplicate rows, including concurrent requests.
Compare a digest of the validated, normalized payload on conflict; reuse of
an ID with different content returns `409`. Do not implement check-then-insert
without the unique constraint. Public responses never contain the stored
message, contact details, or internal triage status.

Errors use `{ "error": { "code": "...", "message": "..." } }` with `400`
for invalid input, `413` for size, `415` for content type, `429` for throttling,
and `503` for temporary storage/service failure. Rate limits include
`Retry-After`. Do not echo submitted content in errors.

There is no public list, detail, or status-read API. A receipt means stored,
not reviewed or promised a response. A timeout has an unknown outcome: retry
the same payload and ID, never create a fresh ID to resolve uncertainty.

## Public form

The root page contains a category selector, message textarea, optional contact
field, and Submit button. A short explanation says feedback is private to
Bloom staff and asks people to omit secrets and personal information they do
not want to share. Context fields are optional; do not fingerprint the browser.

Generate the submission ID before sending. Preserve the form and ID after an
error or timeout so retrying is safe; create a new ID only for a new report.
Show a thank-you message and receipt ID after acceptance. Include accessible
labels, keyboard operation, clear validation, and a layout usable on mobile.
No public feedback wall, user accounts, attachments, or email delivery.

## Petal interface and agent behavior

Mount the package as `/petals/feedback/`:

| Route | Behavior |
| --- | --- |
| `README.md` | Readable instructions, payload example, privacy guidance, and error/retry semantics. |
| `submit.json` | Write the submission JSON above; synchronously submit it. Reading returns a schema/example, with no network call. |
| `receipts/<submission_id>.json` | Read local submission state and the backend acknowledgement if received. |

Implement directory listings and lookup so these paths are discoverable.
Required package `README.md` and `AGENTS.md` are not automatically mounted;
the readable documentation route must be included explicitly.

Example through the existing CLI fallback:

```sh
bloom vfs write /petals/feedback/submit.json --data '{"submission_id":"629971a9-52c2-48c2-9920-2937060847c9","kind":"bug","message":"Describe the problem and reproduction steps here.","reporter":"agent"}'
bloom vfs cat /petals/feedback/receipts/629971a9-52c2-48c2-9920-2937060847c9.json
```

Generate a fresh UUID for each real report; the example UUID is illustrative.
The same body can be written through the mounted filesystem. Caller-supplied
IDs make receipts addressable without a shared `latest` pointer and make
filesystem retries safe.

Before HTTP submission, persist the ID and normalized payload digest locally.
Do not persist a second copy of the report body. Local states are `unknown`,
`received`, and `rejected`; include a bounded error code or acknowledgement.
Mark an attempted send unknown before dispatch, record received only after a
valid `200`/`201` acknowledgement, and treat explicit `4xx` rejections as
rejected. Network errors, `5xx`, or malformed acknowledgements remain unknown.
Replay with the same ID/body can resolve that state. A backend acceptance
followed by a local-store failure must still be safely recoverable by replay.
Reading a receipt never retries or sends feedback. Mutable receipt routes use
zero cache TTL. Keep receipts for 30 days, pruning on subsequent writes.

Return an actionable VFS error on rejection or uncertain delivery; only report
successful submission after backend acknowledgement. There is no offline
outbox or background retry loop in v1. Concurrent identical sends are safe
because the backend deduplicates them; do not overwrite a received local
receipt with a later inconclusive result.

Declare only:

```toml
schema = "bloom.petal.package.v1"
name = "feedback"

[consent]
summary = "Submit feedback to Bloom and keep local submission receipts."

[caps]
allowed = ["bloom:http", "bloom:store"]

[[net.allow]]
host = "feedback.bloom.directory"
methods = ["POST"]
paths = ["/api/v1/feedback"]

[store]
namespaces = ["receipts"]
```

Use the current Petal tooling/SDK and route contract. Do not request
`bloom:vfs.read`, wallet authority, or new runtime settings solely to collect
version/platform information; the caller may supply known context or omit it.

Agent guidance should permit one concise proactive report for a distinct Bloom
problem, such as a reproducible failure, misleading documentation, or a missing
capability that blocked the user's task. Respect any user instruction disabling
reporting; do not submit on every retry or successful operation. Mention a
proactive submission briefly to the user when relevant.

Sanitization means writing a minimal description and reproduction using
placeholders. Never automatically attach logs, transcripts, raw configuration,
local paths containing identity information, credentials, wallet addresses,
balances, transaction details, or user-provided private content. Optional
contact information is included only when the user provides it for feedback.
Do not claim a regex can reliably sanitize arbitrary diagnostic dumps. If a
problem cannot be described without sensitive material, omit that material or
ask the user before including it. Installation itself sends no report.

## Staff authentication and inbox

Use hostname/path-based Cloudflare Access to protect both `/admin` and all
descendants `/admin/*`, including APIs. Public `/` and `/api/v1/feedback` remain
outside the Access application. Avoid enabling Worker-wide authentication,
which would also gate anonymous submissions.

Configure Google sign-in with a Bloom-owned OAuth application whose audience
is internal to Bloom's Google Workspace. Allow only that identity provider and
the exact email domain `bloom.directory`; disable email-OTP and other login
methods for this application. Internal audience establishes organization
membership; a typed email suffix or login-screen domain hint is insufficient.
Cloudflare documents this internal-audience restriction in its
[Workspace integration guide](https://developers.cloudflare.com/cloudflare-one/integrations/identity-providers/google-workspace/).
Group synchronization and per-user allowlists are unnecessary here.

The Worker additionally verifies every admin request's Access JWT using a
maintained library and the configured JWKS, issuer, application audience, and
expiry, then checks the authenticated email domain exactly. Never trust an
unsigned email header. Missing/invalid authentication fails closed. This
follows Cloudflare's [JWT validation guidance](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/)
and works if static assets are introduced later. Do not build custom Google
OAuth callbacks or password/session storage into the application.

Disable public `workers.dev` and preview aliases in production. Keep the Worker
authentication guard even with these aliases disabled. Use an eight-hour Access
session and document how an operator revokes a staff session; suspended Google
accounts do not imply instantaneous invalidation of an already issued session.

All eligible staff share the same permissions. `/admin` offers:

- A newest-first inbox, with message preview, kind, reporter, received time,
  optional contact, and status.
- Search across message/contact and filters for status, kind, and reporter.
  Start with parameterized SQL substring search and pages of 50 records.
- A detail page with the full message, supplied context, and receipt ID.
- Status changes among `new`, `reviewed`, `closed`, and `spam`; default to new.
- Permanent deletion with confirmation, for spam or accidental sensitive data.
- Signed-in email and logout.

Keep admin endpoints under `/admin/api/feedback`: list via GET, detail via
GET `/:id`, status via PATCH `/:id`, deletion via DELETE `/:id`. Search inputs,
page limits, and status bodies are bounded and validated. All staff can reopen
reports. Record only the most recent status editor/time; no workflow engine,
assignment, internal discussion, email replies, or notification integrations.

Render feedback as escaped plain text; never execute HTML, render remote
images, or interpret submitted instructions. Treat it as untrusted data if
staff use an agent to review it. Set admin responses to `Cache-Control:
no-store`. Mutations require same-origin requests and a CSRF token. A small
signed CSRF token bound to the verified Access identity is sufficient; no
database session subsystem is needed.

## Storage and operations

One D1 `feedback` table is sufficient: `submission_id` primary key,
`payload_hash`, `received_at`, `kind`, `message`, `reporter`, `contact`,
the three nullable context columns, `status`, `updated_at`, and `updated_by`.
Index receipt time and `(status, received_at)`. Store server timestamps in UTC.
No staff account table, attachment table, or separate idempotency database.

Proposed retention: reports remain until a staff member deletes them. State
this in the public form's privacy text; do not invent automatic deletion or
promise instant erasure from provider backups. Deletion also removes the
deduplication record, so a subsequent replay may create a new report. Local
receipt storage is separate and may be replaced by Petal upgrades; backend
idempotency remains authoritative while the report exists.

Use a Worker rate-limit binding before database access, initially about ten
submissions per minute per source IP. Use only Cloudflare's trusted source-IP
metadata and do not store raw IPs in feedback rows. This is an abuse control,
not authenticated identity or a strict global quota: the
[binding is eventually consistent](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/).
Do not impose a browser-only CAPTCHA on the agent API. Add stronger controls
only if actual abuse warrants them.

Operational logs contain status, latency, and error codes, not report bodies,
contact details, cookies, or tokens. Document that Cloudflare processes network
metadata even though submissions need no account. Anonymous means no required
identity, not a guarantee that voluntarily supplied text cannot identify someone.

Expose a minimal `/healthz`; observe Worker errors and submission failures using
Cloudflare tooling. Maintain separate local/preview and production D1 data,
checked-in migrations, deployment instructions, and a documented database
export/restore procedure. Deployment requires domain/DNS access, D1 binding,
Access application configuration, and Google OAuth configuration; resource
IDs, credentials, and release hashes are supplied at implementation time.

## Next-release integration

1. Deploy the service and verify its public and staff flows.
2. Publish the Feedback Petal's prebuilt archive and provenance through the
   existing reusable Petal release workflow in the public Petal repository.
   Both source and release downloads must work without GitHub credentials or
   access to the private backend repository. Build once for both Bloom platforms.
3. Add `feedback` to `github_source::DEFAULT_PETALS` and the built-in catalog.
   Pin the actual source commit, release tag, archive checksum, package hash,
   and tooling commit. Use the existing non-authority compatible classification,
   with no signing lineage or authority routes.
4. Retain the current canonical default provisioning behavior. Do not restore
   the legacy `preinstalled` configuration or change other Petal release pins.
5. Use existing init/startup provisioning. Preserve manually sourced Petal
   ownership checks; failed startup acquisition remains nonfatal and retryable.
   Installation requires network access; offline installs can acquire it later.
6. Add a concise Feedback pointer and proactive-reporting guidance to embedded
   agent documentation, and update default-Petal documentation/release notes.

Keep Feedback's wire API v1 compatible with the pinned package. Service releases
are independent of Bloom releases. Users may instruct agents not to report feedback; installation itself sends
nothing. Current upstream Bloom provisions a canonical catalog and does not
support an installation opt-out through the legacy configured default list.
No specific next Bloom version or release artifact hash is assumed in this spec.

## Focused acceptance checks

Exercise meaningful boundaries rather than creating a large test matrix:

- Worker with local D1: accepted submission, invalid/oversized request,
  identical replay, changed-payload conflict, concurrent duplicate insertion,
  storage failure, and throttling. Confirm accepted feedback survives restart.
- Admin: valid Bloom Workspace login; rejected outside/consumer identity;
  rejected missing, forged, expired, or wrong-audience token; protected deep
  links/API routes; safe rendering of hostile text; status, deletion, and CSRF.
  Unit fixtures cover token rejection; one deployed smoke check proves real SSO.
- Petal: build/check/package, submit and read receipt via CLI and one mounted
  smoke flow, then exercise an ambiguous response and safe replay. Confirm
  read-only discovery makes no submission and failed writes surface errors.
- Bloom: extend existing catalog/provisioning checks for canonical defaults,
  pinned archive validation, and best-effort acquisition failure. Run existing embedded-doc checks if edited.
- One deployed end-to-end pass: public form and Petal report appear in `/admin`
  and can be triaged by an authorized colleague.

Use affected-package checks and existing release CI gates. This feature does
not require new custody tests, blockchain/devnet scenarios, performance
benchmarks, or exhaustive browser automation. The specification itself requires
only a document/link check; implementation and deployment are separate work.
