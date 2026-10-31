# Authoring Petals

This guide is for developers and coding agents building local/off-chain Petal
applications. A package contains exactly one filesystem-shaped route tree and
builds to content-addressed WebAssembly component artifacts.

## Package layout

The minimum source package is:

```text
my-petal/
  petal.toml
  README.md
  AGENTS.md
  petal/
    example/
      $index.wasm
      status.json.wasm
```

`README.md` is developer/contributor documentation. `AGENTS.md` is the
operating contract for users and agents: document paths, input bodies,
side effects, approval steps, idempotency, and how to recognize completion.

The `name` in `petal.toml` must equal the sole directory under `petal/`. It may
contain ASCII letters, digits, `-`, and `_`; it may not contain dots or Unicode.
Bloom exposes the package's own route tree at `/petals/example/`. Account-bound
routes use adjacent `[wallet]/[index]` captures, for example
`intents/[wallet]/[index]/new`. Public data and documentation stay unscoped.
The host validates the selected account and supplies trusted `bloom.wallet` and
`bloom.account` parameters. There is no awareness flag, root prefix rewrite, or
implicit account-zero selection. Construct links using the explicit captures.
All accounts, including zero, have separate wallet/index private stores.

## Manifest

A representative manifest is:

```toml
schema = "bloom.petal.package.v1"
name = "example"

[consent]
summary = "Read an API and store package-local state."

[caps]
allowed = ["bloom:http", "bloom:store"]

[[net.allow]]
host = "api.example.com"
methods = ["GET"]
paths = ["/v1/*"]

[store]
namespaces = ["cache"]
secret_namespaces = ["credentials"]
```

Policy structures reject unknown fields. Network paths must be explicit; use
`"/*"` deliberately for all paths rather than relying on an empty list.
`[[net.allow]]` may also name a configured endpoint with `binding = "..."`.

Supported component imports map to manifest capabilities as follows:

| WIT import | Manifest capability or policy |
|---|---|
| `bloom:http/fetch@0.1.0` | `bloom:http` plus `[[net.allow]]` |
| `bloom:store/kv@0.1.0` | `bloom:store` plus `[store]` namespaces |
| `bloom:sign/signing@0.2.0` | `bloom:sign` plus `[sign].allowed_intents`; exact payload, optional Signer-owned Petal KeyRef selector, and atomic ordered batches |
| `bloom:key/derive@0.1.0` | `bloom:key.derive`; routes delegating child-key operation classes must also use `[[key.derive]]` |
| `bloom:tx/outbox@0.1.0` | `bloom:tx.outbox` |
| `bloom:chain/read@0.1.0` | `bloom:chain` |
| `bloom:vfs/readwrite@0.1.0` | `bloom:vfs.read` and/or `bloom:vfs.write`, according to used exports |
| `bloom:env/runtime@0.1.0` | no additional capability |

When releasing an upgrade in an authenticated Petal lineage, expect Bloom to
copy the previous release's private `bloom:store/kv` bytes into the new
package's store on first use. A successor must read its predecessor's stored
format or tolerate and replace it. Test the new release against a fixture
store written by the previous release, including settings and secrets. Bloom
does not interpret those bytes or run a migration hook. Every numbered account,
including 0, has a separate store keyed by package, wallet and account number.
The first explicit-account release does not import legacy package-level settings
into account 0; configure credentials again and reconcile funded work with the
old package before upgrading.

Imports, route metadata, and the top-level manifest must agree. Metadata may
narrow installed authority at runtime but may not widen it. A package declaring
`bloom:sign` must list allowed intents, and each signing route's metadata must
select one of them. The retired `bloom:sign/signing@0.1.0` hash-only import is
incompatible with production signing and fails closed.

Child-key operation classes are distinct from the signing intent used
immediately by the route that requests the key. Declare each delegated class on
the exact route pattern that imports `bloom:key/derive@0.1.0`:

```toml
[[key.derive]]
route = "[network]/agent_sessions/[wallet]/[index]/new.json"
operation_classes = ["venue.agent_action"]
allowed_routes = [
  "[network]/agent_sessions/[wallet]/[index]/cancel.json",
  "[network]/orders/[wallet]/[index]/new.json",
]
allowed_crypto_suites = ["secp256k1-keccak256-recoverable"]
maximum_lifetime_ms = 86400000
```

Every listed class must also appear in `[sign].allowed_intents`. Bloom rejects
unknown or duplicate routes, empty or duplicate class lists, invalid class
tokens, and declarations on routes without the key-derivation import. The
installer resolves `allowed_routes` from canonical manifest patterns to the
immutable route IDs in that package and always includes the derivation route
itself. Each allowed route must have a signing intent included in the declared
operation classes. At runtime the component may request non-empty subsets of
the declared operation classes and crypto suites and a shorter lifetime, but it
cannot widen any bound; Bloom supplies the resolved routes. A manifest scope
must declare all three bounds: `allowed_routes`, `allowed_crypto_suites`, and
`maximum_lifetime_ms`.

A crypto suite selects which hash runs over a payload before the child key
signs it. `allowed_crypto_suites` accepts exactly the values of `CryptoSuite`
in `bloom-broker-api`, and Bloom rejects anything else at install:

| Value | Wallet | Use for |
| --- | --- | --- |
| `secp256k1-keccak256-recoverable` | EVM | keccak256, what Ethereum verifies: transactions, EIP-712, EIP-191 |
| `secp256k1-sha256-recoverable` | EVM | SHA-256, for off-chain use such as signed venue API requests; no chain accepts these |
| `ed25519-message` | Solana | the only suite a Solana wallet permits |

The wallet's derivation profile is the ceiling: an EVM wallet permits both
secp256k1 suites, a Solana wallet permits only `ed25519-message`. Declare the
narrowest set the Petal actually needs, since a key limited to
`secp256k1-sha256-recoverable` cannot produce a signature an EVM node accepts.

Omitting all three bounds retains the legacy guest-supplied scope only for
packages created before this manifest contract. New Petals should always
declare the complete scope. Other package-level signing intents are not
inherited.

## Routes and ABI

Every route artifact is a WebAssembly component implementing
`bloom:route@0.1.0`; raw core Wasm is rejected. The complete contract is in
The canonical [`route.wit`](https://github.com/bloom-directory/petal/blob/main/wit/route/route.wit). The route world exports
`metadata`, `lookup`, `list`, `read`, and `write`; return
`route-error.unsupported` for operations the route does not implement.

The route tree is the public VFS declaration:

- `status.json.wasm` creates the file `/petals/example/status.json`;
- `$index.wasm` handles the containing directory;
- `$lookup.wasm` refines lookup for dynamic entries;
- `[wallet]/[index]/balance.json.wasm` selects a wallet and numbered account; and
- static segments take precedence over dynamic segments.

Reserved `$...` names are only valid as recognized special route leaves. A
normal file route is readable by default. A route that advertises write access
must export `write`.

### Writable routes

Bloom waits for the component's `write` export to complete and propagates its
error to the VFS caller. Authors can therefore rely on a returned write error
being visible to a mounted filesystem or `bloom vfs write` client. A successful
return means the route handler completed; it does not imply that a transaction
the handler staged has been approved, broadcast, or confirmed. Represent those
states explicitly through inspectable routes and receipts.

The WIT `route-meta` record retains `write-async` for serialized-format
compatibility. Generated metadata and installation consent may call the same
field `write_async`. It is reserved metadata in this iteration: Bloom does not
detach writes when it is `true`, and authors must not document it as a
background-job guarantee. Set it deliberately for compatibility with existing
components, but design and test every write against synchronous execution.

For composition, a route may have a sibling `.route.toml` sidecar which points
to a primary component under `modules/` or `components/` and dependencies under
`components/`. See the
[file-driven package design](../superpowers/specs/2026-06-23-petals-v1.md)
for route precedence, sidecar composition, metadata narrowing, and archive
normalization rules.

Guest VFS calls cannot invoke another Petal or re-enter the current Petal:
every `petals/…` path is denied, even under the selected wallet and account.
Wallet VFS access is restricted to the selected numbered account. Component
composition described above does not enable nested Petal VFS dispatch.

## Build and validate

Validate the directory and generate route artifacts:

```sh
bloom petals build path/to/my-petal
```

Emit a deterministic uncompressed package archive at the same time:

```sh
bloom petals build path/to/my-petal --out my-petal.petal.tar
```

The build regenerates `artifacts/routes/` and
`artifacts/build-manifest.json`. Do not hand-edit generated artifacts or treat
stale artifacts as source. Install the directory and archive through the same
validation pipeline used for GitHub sources:

```sh
bloom petals install path/to/my-petal
bloom petals install my-petal.petal.tar
```

### Release installs versus the development Triad

A Petal can be installed on any Bloom, but signing authority depends on
provenance. Broker authorizes a Petal's signing and approval routes only for
package hashes in its installer-signed provenance catalog, and refuses
anything else with `PROVENANCE_MISMATCH` (for example "subject is absent from
Broker's installer-owned current catalog"; Machine can refuse with the same
code before the request reaches Broker). On a release install that catalog is signed
at installation and lists only the Petal releases that Bloom ships, so a
locally built package under a new name can be installed and read but cannot
sign. A local build cannot replace a shipped Petal of the same name either:
activation fails with "successor release information is missing from the
loaded installer catalog". This is deliberate; there is no release-mode switch
to trust a local package.

To develop a Petal that signs, use the development Triad
(`scripts/triad-dev-launch.sh`, see [DEVELOPMENT.md](../../DEVELOPMENT.md)).
Its developer installer key can add a record for your package:

```sh
# In the terminal that sourced the Triad's triad.env (debug Machine on PATH).
bloom init triad-enroll-developer-petal-provenance \
  "$BLOOM_TRIAD_DEVELOPER_ROOT/config" path/to/my-petal
# Restart the launcher with the same developer root: Broker loads the
# catalog at startup, and the launcher keeps developer records.
bloom petals install path/to/my-petal
```

Enrollment rebuilds the package first, so the recorded hash matches what you
install; enroll and restart again after every rebuild. The command exists only
in `triad-dev-harness` builds.

The launcher can do this for the bundled integration Petals. Its package
variables do not behave the same way:

| Variable | Builds the package | Enrolls provenance | Installs |
|---|---|---|---|
| `BLOOM_TRIAD_DEV_HYPERLIQUID_PACKAGE` | yes, with its `scripts/build.sh`, unless `BLOOM_TRIAD_DEV_BUILD_PETALS=0` | yes | yes |
| `BLOOM_TRIAD_DEV_POLYMARKET_PACKAGE` | no | no | yes |

So a Polymarket checkout passed this way installs but its signing routes are
refused unless its exact hash is already in the catalog. For any other Petal,
use the steps above.

Before publishing, test both direct VFS fallback and a mounted daemon. Cover
lookup, list, read, invalid input, backend failure, and every writable route.
For a staged transaction workflow, verify that documentation and route output
distinguish staging, approval, confirmation, broadcast, and receipt states.

## GitHub source packages

Source repositories under `bloom-directory` may add:

```toml
[source]
kind = "github"
repository = "bloom-directory/bloom-petal-example"

[build]
command = "./scripts/build-package"
outputs = ["artifacts/routes"]
```

Bloom executes the build command natively with the installing user's
privileges. Publishing under the trusted owner is therefore an assertion about
the repository's source, build script, and dependencies—not only the resulting
Wasm. Keep builds non-interactive and reproducible, minimize dependencies, and
test installation by tag and immutable commit. Bloom records the resolved
commit but intentionally does not sandbox the source build in this iteration.

## Author checklist

- Keep `petal.toml`, `README.md`, and operational `AGENTS.md` current.
- Declare only host capabilities the component actually imports.
- Make network paths, store namespaces, and signing intents explicit.
- Make writes idempotent where retry is possible and expose inspectable status.
- Never imply that a staged or approval-required action has completed.
- Build from a clean tree and install the resulting directory and archive.
- Exercise failure paths and confirm errors are actionable for both people and
  agents.
