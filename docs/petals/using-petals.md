# Using Petals

This guide is for people and agents operating a Bloom installation. A Petal
adds an application tree at `/petals/<name>/`; interact with that tree in the
mounted filesystem or through the equivalent `bloom vfs` commands.

## Install

Bloom accepts a package directory, a deterministic `.petal.tar`, or a trusted
GitHub source repository:

```sh
bloom petals install path/to/package
bloom petals install app.petal.tar
bloom petals install https://github.com/bloom-directory/bloom-petal-polymarket
bloom petals install https://github.com/bloom-directory/bloom-petal-polymarket --ref v0.1.0
```

GitHub installs are limited to repositories under `bloom-directory`. With no
`--ref`, Bloom selects the latest SemVer-like tag. An explicit ref may be a tag,
branch, or commit. Bloom records the resolved commit and package hash in install
metadata.

After installation, the command prints the package hash, app mount, route
count, and a consent summary describing the package's declared capabilities,
network access, signing intents, storage namespaces, and routes. In this
iteration the summary is informational: installation has already changed local
state when it is printed. A route may appear with a `write_async` flag in this
output. That flag is retained compatibility metadata only; Bloom does not use it
to detach the write.

## Trust model for source installs

A GitHub source Petal declares a `[build].command` in `petal.toml`. Bloom runs
that command natively as the current OS user before validating the resulting
Petal package. It is not confined by the WebAssembly capability boundary and
inherits the user's normal filesystem, environment, and network access.

Only install source repositories whose code, maintainers, and build
dependencies you trust. The `bloom-directory` owner restriction is the trust
boundary for this iteration, not a native-code sandbox. Tags are also mutable;
use an explicit commit SHA when reproducibility matters and retain the resolved
commit printed by Bloom.

Installed package files and the Bloom home are treated as trusted local state.
Bloom does not re-hash every artifact on every read. Protect the Bloom home with
the same OS-level controls as wallet and application state.

## Discover and use an installed Petal

List installed packages:

```sh
bloom petals ls
```

The output includes a short content hash and the app mount. If the Bloom daemon
is mounted at `/Volumes/bloom`, for example, a Petal named `polymarket` appears
at `/Volumes/bloom/petals/polymarket/`:

```sh
ls /Volumes/bloom/petals/polymarket
cat /Volumes/bloom/petals/polymarket/status.json
```

When a filesystem mount is unavailable, use the VFS fallback:

```sh
bloom vfs ls /petals/polymarket
bloom vfs cat /petals/polymarket/status.json
bloom vfs write /petals/polymarket/PATH --data 'DOCUMENTED_BODY'
```

The exact paths, accepted write bodies, and staged-confirm workflows belong to
the package. Read the package's required `AGENTS.md` from its source checkout or
package directory before operating it. (`README.md` and `AGENTS.md` are required
package files, but are not automatically mounted as routes.) Treat route
descriptions and `plan.md` files as instructions to inspect, not authority to
approve a transaction automatically.

### Write completion and errors

Petal writes execute synchronously in this iteration. A filesystem write or
`bloom vfs write` call waits for the route component to finish. If the route
returns an error, Bloom returns that error to the caller instead of reporting
success while work continues in a detached task.

Synchronous completion describes the route invocation, not every workflow the
route may initiate. For example, a successful route may have staged a
transaction that still needs approval, confirmation, broadcast, and receipt
inspection. Use the route's returned state and documented follow-up paths to
decide what completed.

The route ABI still contains `route-meta.write-async`, and installation consent
may print it as `write_async`. This field is reserved for format compatibility
and future design work. Whether it is `true` or `false`, current Bloom execution
remains synchronous.

### Agent operating sequence

An agent should:

1. read the Petal's `AGENTS.md` when it is available and list the relevant
   directory;
2. read current state and any package-specific prerequisites;
3. perform the narrow write requested by the user;
4. inspect the resulting status, plan, approval challenge, or receipt; and
5. ask for the required user ceremony or confirmation instead of treating a
   staged action as completed.

Signing and transaction calls remain daemon-mediated. A signing route must use
an intent declared by its package, and a transaction staged by one route is
available to the other routes in the same package. A daemon restart deliberately
forgets in-memory approval grants and may require the user to approve again.

Petals with `bloom:vfs.read` or `bloom:vfs.write` currently receive broad VFS
authority rather than manifest-declared path prefixes. The `/petals` subtree is
blocked from Petal VFS host access to prevent recursive Petal calls. Install a
Petal only when its declared capability set is appropriate for the package.

## Remove

Remove a Petal by its full hash, a unique hash prefix of at least 12 characters,
its app name, or its petname:

```sh
bloom petals uninstall polymarket
```

`bloom petals ls` should no longer show the package after removal. Application
private-store lifecycle and quota management are not yet a complete subsystem;
do not assume uninstall is a general secure-erasure mechanism for all data a
Petal may have written through mediated hosts.
