# Local Petal Plugins: Architecture and Security Review

**Date:** 10 July 2026  
**Comparison:** `master...feat/local-petal-plugins`  
**Scope:** Code, configuration, WIT interfaces, and binary test fixtures. Documentation changes were excluded from the review.

## Executive summary

This branch is a major Petal architecture rewrite, not an incremental plugin enhancement.

Bloom moves from:

```text
single raw WASI module
  -> manually installed with capabilities
  -> explicitly invoked through CLI/IPC
  -> exposed as metadata under public/
```

to:

```text
versioned multi-route app package
  -> validated, composed, content-addressed install
  -> mounted at petals/<app>/
  -> invoked through ordinary VFS operations
  -> Wasm Component Model route ABI
  -> capability-mediated daemon services
  -> Sealed Approval-bound signing and transactions
```

The comparison covers 60 code/configuration/WIT/binary-fixture files, with approximately 15,706 textual additions and 1,010 deletions. Untracked `cache/` and `out/` directories were not included.

The new Wasm runtime is substantially more defensive and explicit than the old Petal runtime. However, the new GitHub source-install path introduces a dominant risk: it executes repository-provided native build scripts unsandboxed with the user's full local authority.

## Architectural overview

The resulting runtime flow is:

```text
CLI package/source install
        |
        v
package normalization + strict validation
        |
        +-- route discovery
        +-- WIT ABI/import validation
        +-- component composition
        +-- install-time metadata evaluation
        +-- deterministic package/artifact hashing
        |
        v
~/.bloom/petals/store/packages/<package-hash>/
        |
        +-- source/
        +-- artifacts/routes/rNNNNNN.wasm
        +-- route-index.json
        +-- metadata + source provenance
        |
        v
daemon mounts PetalRouter at /petals
        |
        v
/petals/<app>/<route>
        |
        +-- match route and parameters
        +-- evaluate/narrow dynamic metadata
        +-- calculate effective capabilities/policies
        +-- invoke Wasm component export
                |
                v
        mediated daemon host interfaces
        +-- HTTP
        +-- private KV
        +-- signing / Sealed Approval
        +-- EVM outbox
        +-- chain reads
        +-- Bloom VFS
        +-- time/randomness
```

The important boundary is that components do not receive direct filesystem, socket, keystore, RPC, or transaction-engine access. They receive only the WIT imports Bloom chooses to link.

## 1. The old Petal product interface has been removed

Previously, Bloom treated a Petal as one raw WASI module:

- `bloom petals install <file> --name ... --cap ...`
- `bloom petals run <name-or-hash>`
- stdin/stdout command semantics
- optional `vfs.read` and `vfs.write` core-Wasm imports
- raw objects and metadata exposed under `public/local` and `public/names`
- execution through `petals.run` IPC

That product surface is gone:

- The old VFS `PetalsHandler` was deleted.
- CLI `Run` and `Name` subcommands were removed.
- Raw `.wasm` and `.wat` installation is no longer accepted.
- IPC method names still exist for compatibility, but raw install and run now return explicit unsupported errors.
- Listing now enumerates installed Petal packages and reports their `petals/<name>/` mount.
- The CLI accepts package directories, `.petal.tar` files, or trusted GitHub source repositories.

Some lower-level v1 primitives remain public: `PetalStore::install`, `PetalVm::run`, the registry, and core-Wasm machinery. They are no longer wired into the supported daemon/CLI execution path. This is therefore a breaking product/API migration even though some library compatibility remains.

## 2. Petals are now content-addressed app packages

The new unit is a `bloom.petal.package.v1` package represented by `PreparedAppPackage`.

A valid package requires:

- `petal.toml`
- `README.md`
- `AGENTS.md`
- exactly one `petal/<name>/` route tree
- one or more `.wasm` route components

The manifest can declare:

- app name
- consent summary
- allowed capabilities
- network allowlist
- signing intents
- ordinary private-store namespaces
- secret private-store namespaces
- optional source/build information

Package identity is a deterministic BLAKE3 digest over normalized paths and contents with a v2 domain prefix. It is independent of source directory order or tar metadata.

The generated store layout includes:

- the normalized source package
- composed route artifacts
- a route index
- source and artifact hashes
- install-time route metadata
- policy hash
- optional GitHub source provenance

Installation rebuilds and verifies the prepared package before using any supplied hash or route index. It writes a temporary package tree and renames it into place, rejects duplicate app mount names, and validates route IDs before constructing filesystem paths.

Reinstalling the same package checks the stored source, route index, and artifact hashes rather than blindly treating the directory as valid.

### Deterministic archives

`.petal.tar` handling is intentionally strict:

- only normalized relative UTF-8 paths
- no absolute paths, `..`, backslashes, empty segments, or NULs
- no symlinks or special files
- no duplicate paths
- no PAX/GNU long-path metadata
- fixed uid, gid, and timestamps
- restricted modes
- deterministic ustar output

### Route composition

Optional `*.route.toml` sidecars can compose a primary route component with package-local component dependencies through `wasm-compose`.

The sidecar format:

- denies unknown fields
- restricts component/import paths
- names supported operations
- permits package-local aliases
- produces a closed artifact
- revalidates the resulting component's imports and ABI

This provides modularity without allowing arbitrary runtime imports.

## 3. The new Petal interface is a Wasm Component Model ABI

The canonical interface is `bloom:route@0.1.0`, defined in [`bloom-directory/petal`](https://github.com/bloom-directory/petal/blob/main/wit/route/route.wit).

A route component exports:

- `metadata(ctx)`
- `lookup(ctx)`
- `list(ctx)`
- `read(ctx)`
- `write(ctx, body)`

The trusted route context contains:

- app root
- package hash
- requested path
- bound route parameters
- optional actor

Bloom constructs this context. In particular, the component cannot choose its package hash, route ID, operation, or trusted transaction/signing provenance.

Responses use typed component values rather than the old pointer/length core-Wasm convention.

### Route metadata

Metadata describes:

- entry kind
- Unix mode
- cache TTL
- whether reads have side effects
- whether writes are asynchronous
- required capabilities
- signing intent
- executable status
- description and consent-summary fields

Some qualifications:

- Executable routes are currently rejected.
- `description` and `consent-summary` exist in WIT but are currently ignored by VM extraction.
- Returned optional entry sizes are effectively collapsed to zero when absent.
- Route-level executable behavior is therefore a reserved interface field, not an implemented feature.

## 4. The filesystem is now the application/router interface

Route files determine the VFS API:

- `hello.txt.wasm` becomes `hello.txt`
- `$index.wasm` owns lookup, listing, and reads for the containing directory
- `$lookup.wasm` becomes an explicit lookup handler
- `[wallet].json.wasm` creates a dynamic parameter with a suffix
- nested directories become nested VFS routes

Routes receive stable IDs such as `r000001`, assigned after lexicographic sorting.

Matching uses a specificity tuple based on:

- segment count
- number of static segments
- file-route score

Overlapping dynamic routes of equal specificity are rejected at install time, preventing order-dependent ambiguity.

The new `PetalRouter` is mounted at `/petals` by the daemon. It:

- lists installed applications
- resolves the first segment as an app mount
- matches the rest against the package route index
- maps component errors to VFS errors
- validates component-returned entry names
- validates symlink targets
- synthesizes intermediate directories and static listings where possible
- exposes cache TTL and side-effect metadata to the VFS
- implements synchronous or fire-and-forget writes

Application discovery is derived from installed package metadata, not the legacy name registry. Duplicate app names are rejected.

One scaling caveat is that mount resolution currently rescans package metadata repeatedly, making route discovery roughly O(number of installed packages) per operation.

## 5. Static and dynamic metadata have different lifecycles

Static routes, with no path parameters, have `metadata` executed during package preparation under:

- zero capabilities
- a deny-all host
- deterministic time/randomness

The result is stored in the route index.

Dynamic routes need concrete parameters, so their metadata is evaluated at request time. Runtime metadata may only narrow what was accepted at installation:

- remove permission bits
- reduce or remove cacheability
- shorten TTL
- remove capabilities
- turn off side-effecting reads
- turn off asynchronous writes
- narrow the signing intent

It cannot widen authority.

A minor design issue exists for dynamic writes: the router evaluates metadata once to decide whether to spawn an async write, then dispatch evaluates it again. Since runtime time/randomness is available, a deliberately nondeterministic component could produce different answers. It cannot gain more authority, but Bloom could acknowledge an async write that later fails or becomes denied.

Async writes are also best-effort `tokio::spawn`: they are acknowledged before completion, are not durable, and have no backpressure.

## 6. Capability and policy enforcement

The effective authority for a route is the intersection of several layers:

```text
recognized WIT imports
intersect manifest-declared capabilities
intersect install/runtime route metadata
intersect optional runtime capability mask
```

Network, signing-intent, and store-namespace policies are separately intersected with runtime masks.

Recognized capability planes include:

- `bloom:http`
- `bloom:store`
- `bloom:sign`
- `bloom:tx.outbox`
- `bloom:chain`
- `bloom:vfs.read`
- `bloom:vfs.write`

Import validation is unusually strict:

- Wasm must validate structurally.
- Only known Bloom interfaces and versions are accepted.
- Required function and nominal type shapes are checked.
- Non-Bloom component imports are rejected.
- Unknown imports become traps at runtime.
- Import-required capabilities must appear in the package manifest.
- Signing imports require declared signing intents.
- Both signing v0.1 and v0.2 are recognized, with v0.2 supporting structured approval results.

One least-privilege limitation is that the WIT VFS import is a combined `readwrite` interface. Import validation therefore currently requires both read and write capabilities even if the component only calls read functions.

## 7. Runtime isolation

The component VM retains or adds:

- 100 million fuel by default
- a 16 MiB default linear-memory cap
- no filesystem preopens
- no raw sockets
- no directly linked WASI surface for route components
- deterministic floating-point/relaxed-SIMD settings
- bounded HTTP response size
- bounded random-byte requests
- explicit mediated imports only

The daemon-created host defaults sensitive operations to denied unless explicitly implemented.

Remaining availability gaps include:

- no general wall-clock/epoch timeout for component execution
- unrestricted table growth in the custom resource limiter
- no aggregate package size, archive entry-count, or per-file size limit
- package ingestion uses `read_to_end`
- compilation/composition can therefore consume significant CPU or memory before runtime fuel limits apply

## 8. New host interfaces and attack-surface expansion

The Wasm sandbox is stronger, but the useful host surface is much wider.

### HTTP

Components can issue HTTP requests through `bloom:http/fetch`.

Enforcement includes:

- default deny
- HTTPS only
- port 443 only
- exact hostname
- allowed methods
- path matching
- runtime-policy intersection
- manual redirect handling
- policy revalidation on every redirect
- cross-origin header stripping
- cross-origin body replay denial
- redirect limit
- 20-second client timeout
- streaming response-size cap
- audit logging with query strings omitted

Residual SSRF exposure remains for explicitly allowed hostnames: DNS results are not restricted or pinned, so an attacker-controlled allowed hostname could potentially resolve or rebind to private or loopback addresses with a valid TLS configuration.

### Private KV store

The new per-package store supports:

- `get`
- `put`
- `put-new`
- `list`
- `delete`
- `delete-if-value`

Keys are effectively:

```text
<package-hash>/<declared-namespace>/<component-key>
```

The component cannot choose its package partition.

Secret namespaces require secret writes; ordinary namespaces reject secret writes. Runtime masks cannot downgrade secret classification.

Secret files are mode `0600` on Unix and ordinary files `0644`. Operations are serialized with a process-wide mutex, and `put-new` and compare-delete enable safer lock or credential patterns.

The main upgrade implication is that changing any package content changes the package hash and therefore creates a new store partition. No automatic state migration exists.

Residual local-filesystem risks include symlink following inside a pre-compromised store tree and predictable temporary filenames. On non-Unix platforms, secret mode does not receive equivalent ACL hardening.

### VFS access

Components can read, list, lookup, or write the live Bloom VFS when granted VFS capability.

The entire `/petals` subtree is denied to component VFS calls, preventing recursion and cross-app invocation.

Otherwise, access is broad: there is no manifest path-prefix allowlist. A VFS-capable component can reach wallet, chain, request, status, and other mounted surfaces, subject to downstream handlers' own authorization rules.

This is one of the larger residual authority planes and would benefit from VFS prefix policies analogous to network and store policies.

### Time and randomness

Components receive mediated current time and random bytes. Random requests are capped at 1 MiB. Install-time metadata evaluation substitutes deterministic zero values.

## 9. Signing is now package- and route-bound

The new signing interface accepts:

- wallet
- exactly 32 bytes
- a declared signing intent

Signing v0.2 returns either:

- a signature
- structured `approval-required` information containing action ID, ceremony URL, and expiry

The daemon rejects signing without trusted Petal route context.

It constructs a short-lived Sealed Action bound to:

- wallet
- hash
- signing intent
- app root
- package hash
- route ID
- operation
- requested path
- route parameters
- optional actor
- policy snapshot digest

Keys never enter the component.

New typed local-app attestation facts bind the grant, attestation, intent, Petal identity, digest, and action before signing.

This is a substantial improvement over a generic "plugin requested a signature" model: approvals are cryptographically and semantically tied to the installed package and route invocation.

## 10. Generic EVM transaction parity

The `bloom:tx/outbox` WIT interface adds:

- `stage`
- `confirm`
- `inspect`

Transaction requests include:

- wallet
- chain
- destination
- value
- calldata
- optional nonce
- optional EIP-1559 fee pair

The component never signs or broadcasts raw bytes directly. Requests go through `TxEngine`, its policy/review machinery, and Sealed Approval.

Execution origin is now persisted on staged transactions. It flows into:

- central outbox identity
- sealed EVM subject
- signing attestation
- executor matching
- confirm/inspect authorization

The daemon derives a route-specific origin from trusted package, route, operation, and path context. Another app or route cannot inspect or confirm an entry with a different persisted origin.

`TxEngine` also adds validated EIP-1559 fee overrides.

One important semantic point: `bloom:tx.outbox` is transaction-execution authority, not merely harmless staging. A component can call confirm and can set `acknowledge-warnings`. Wallet policy and Sealed Approval remain the true authorization boundary, but a tx-capable app can autonomously broadcast transactions permitted by current policy.

## 11. Chain reads are deliberately narrow

The component chain interface is not arbitrary JSON-RPC.

The daemon permits only:

- `eth_chainId`
- `eth_getBalance`
- `eth_call`

Inputs are parsed into typed addresses, quantities, and hex data. Calls use the latest block. Administrative, wallet, signing, write, and arbitrary RPC methods are rejected.

This gives apps enough chain-read capability for balances and contract calls without exposing the node's broader RPC attack surface.

## 12. GitHub source installation

The CLI can install from GitHub repositories owned by the hard-coded `bloom-directory` organization.

It:

- accepts repository-root GitHub URLs or SSH syntax
- rejects arbitrary owners
- rejects raw remote `.wasm`
- caches a bare repository
- resolves an explicit tag, branch, or SHA, or chooses the latest simple SemVer tag
- checks out a detached commit
- validates source provenance in `petal.toml`
- runs the declared build command
- validates the generated Petal package
- records owner, repo, requested ref, selected tag, resolved commit, and package hash

This is useful supply-chain provenance, but it is also the branch's largest security regression.

### High-risk issue: unsandboxed build execution

The repository-provided `[build].command` is launched directly with the equivalent of:

```text
Command::new(repository_command)
    .current_dir(checkout)
    .status()
```

Path validation only ensures the command is repository-relative.

The process inherits the Bloom CLI user's:

- filesystem authority
- home-directory access
- environment
- credentials and secrets
- network
- process privileges

It has no timeout or resource limit and runs before generated-package validation.

Trust is at the organization level: any repository under `bloom-directory`, or a compromise of its maintainers, tags, or dependencies, can execute native code as the user.

The build should be moved into a strong sandbox with a minimal environment, controlled filesystem mounts, explicit network policy, resource limits, and preferably signed/pinned immutable inputs.

## 13. Consent is currently informational, not an authorization gate

The CLI builds a useful summary containing:

- capabilities
- network hosts, methods, and paths
- signing intents
- store namespaces and secret status
- routes and supported operations
- side-effecting reads
- async writes
- cache TTLs

However:

- local directory/tar packages are installed before the summary is printed
- GitHub builds execute before the summary is printed
- GitHub packages are installed before the summary is printed
- no confirmation is required

Thus "consent" is display-only. The install command itself is treated as consent.

For high-authority capabilities such as signing, transaction outbox, VFS writes, and network, this should ideally be a pre-install confirmation step, with an explicit noninteractive flag for automation.

## 14. Content-addressed identity has a runtime integrity gap

Install and reinstall verify package contents thoroughly. Runtime dispatch, however, reads the stored route index and artifact without recalculating their hashes.

A process able to modify Bloom's local package store could substitute:

- route Wasm
- route metadata/index
- artifacts

and then execute the replacement under the original package hash and approval identity.

This normally requires same-user local access, but it weakens the content-addressed security claim and could matter for backups, sync tooling, permissive directory modes, or plugin-management tools.

Runtime loads or daemon startup should verify route-index/package and artifact hashes, or the installed store should be made immutable and owner-only.

## 15. Other code changes supporting Petal parity

Several adjacent changes support the new architecture:

- `bloom-polymarket` now has a `native-client` feature so lower-level signing/trade primitives can be reused without requiring native client behavior.
- Polymarket wallet names are standardized to 1-64 characters of `[A-Za-z0-9_-]`, eliminating dots and tightening path safety.
- POLY_1271 wrapping was separated from raw signing so a Wasm app can request a digest signature from the host and perform deterministic wrapping without key access.
- Polymarket onboarding is now allowed through the ordinary grant-gated write path instead of being treated as a raw cached-signer lane.
- CLI onboarding detection recognizes both native `/polymarket/...` and `/petals/polymarket/...` paths.
- Chain method-body paths gain an optional `@<nonce>` scope to avoid collisions between concurrently staged method bodies.
- Credential permission handling is made portable with Unix-only permission calls.
- CI installs the Wasm target and `wasm-tools` needed for package/component tests.
- Binary component fixtures cover HTTP, metadata, signing, executable rejection, package imports, and no-import routes.

## Compatibility consequences

This branch intentionally breaks the old operational model:

- raw Petal files cannot be installed through supported CLI/IPC
- Petals cannot be explicitly run with stdin/stdout
- petname management is removed from the CLI
- the `public/local` and `public/names` exposure disappears
- apps are invoked through VFS paths
- component routes must implement an exact versioned WIT interface
- unsupported imports fail closed
- package updates receive new hashes and isolated private-store partitions
- app mount names must be unique
- asynchronous writes change delivery/error semantics

The remaining legacy low-level APIs should be considered internal compatibility residue rather than the supported Petal contract.

## Overall security assessment

The new runtime security architecture is materially stronger:

- explicit versioned component ABI
- capability-derived imports
- default-deny host methods
- no raw key access
- no direct network, filesystem, or RPC access
- policy intersection rather than capability union
- deterministic install-time metadata checks
- route/package provenance in approvals
- origin-bound transaction outbox
- narrow chain RPC
- strict archive/path validation
- redirect and response-size hardening
- raw IPC execution removed

The attack surface is nevertheless much larger because Petals can now perform useful application work through `/petals`: network calls, persistence, VFS interaction, signing requests, and policy-constrained transaction execution.

The main residual concerns, in priority order, are:

1. Unsandboxed GitHub repository build commands.
2. Post-install, display-only consent.
3. No runtime verification of stored content-addressed artifacts.
4. Missing package/archive and general execution time/resource bounds.
5. Broad VFS capability without path policies.
6. DNS rebinding/private-IP residuals for allowed HTTP hosts.
7. Dynamic metadata double evaluation and best-effort async writes.
8. Private-store symlink/platform-permission residuals.
9. Minor ABI fidelity gaps around ignored metadata fields, optional size, and returned entry modes.

## Verification

No source files were changed during the review.

The code-only review was backed by successful test runs:

- `cargo test -p bloom-petals --lib`: **116 passed**
- `cargo test -p bloom-daemon --lib`: **48 passed**

The focused Petal and daemon test suites are green, including routing, composition, ABI validation, capability enforcement, package hashing, strict tar handling, store isolation, signing approvals, transaction-origin binding, HTTP policy, and daemon integration.
