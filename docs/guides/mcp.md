# MCP server (`bloom mcp`)

`bloom mcp serve` exposes Bloom's virtual filesystem to Model Context Protocol
clients over stdio. It is a proxy, not a second API: every tool and resource
forwards to one of the five VFS commands the daemon already serves on its Unix
socket — the same commands `bloom vfs ls|cat|stat|write` use. Path parsing,
authorization, policy gates, confirmation, audit journalling, and error codes
all stay in `bloom-vfs`.

Use it when your agent client speaks MCP and you would rather not mount the
filesystem. If you can mount, mounting is still the richer surface: see
[Interaction Modes](../architecture/Interaction%20Modes.md).

## Enabling it

The server is disabled by default, and a config file that predates the `[mcp]`
block — or has no config file at all — also reads as disabled. Turning it on is
an explicit edit to `~/.bloom/config.toml`:

```toml
[mcp]
enabled = true
```

```sh
bloom mcp status
# enabled: true
# config: /home/you/.bloom/config.toml
# transport: stdio
# endpoint: unix:/home/you/.bloom/private-run/bloom.sock
# protocol: 2025-06-18
# tools: vfs_list, vfs_read, vfs_stat, vfs_write, vfs_write_then_stat
```

`bloom mcp serve` checks the flag before it reads a byte of stdin or touches
the daemon socket, so a disabled server fails with an explanation instead of
starting and then refusing calls.

## Connecting a client

Transport is stdio only: the client spawns `bloom mcp serve` as a child process
and owns its lifetime. Nothing listens on a network port, and the child runs as
the invoking user, which is the identity the daemon's peer-uid check sees.

```json
{
  "mcpServers": {
    "bloom": {
      "command": "bloom",
      "args": ["mcp", "serve"]
    }
  }
}
```

Diagnostics go to stderr; stdout carries protocol frames only.

Protocol revisions: `2025-06-18` (default), `2025-03-26`, and `2024-11-05`.
`initialize` echoes the client's revision when it is one of those and otherwise
answers with `2025-06-18`. The JSON-RPC batching `2025-03-26` permits on stdio
is implemented, so the claim holds for every revision listed.

## Tools

| Tool                  | VFS command         | CLI equivalent    | `readOnlyHint` |
| --------------------- | ------------------- | ----------------- | -------------- |
| `vfs_list`            | `list`              | `bloom vfs ls`    | true           |
| `vfs_read`            | `read`              | `bloom vfs cat`   | false          |
| `vfs_stat`            | `lookup`            | `bloom vfs stat`  | true           |
| `vfs_write`           | `write`             | `bloom vfs write` | false          |
| `vfs_write_then_stat` | `write_with_lookup` | (staging flows)   | false          |

`vfs_read` is not marked read-only on purpose. Most of the VFS is inert data,
but a few paths act when read — a wallet outbox `confirm`, `confirm.override`,
`replace`, or `cancel` file signs and broadcasts on read. `vfs_stat` reports
this per path as `read_side_effecting`, and is itself always inert, so a client
can stat before it reads and prompt when the answer is `true`.

Reads return UTF-8 as text and anything else as a base64 blob, so binary
artifacts survive byte-for-byte. Writes take either `text` or `bytes_b64`.

Each tool forwards a fixed set of arguments (`path`, plus `text`/`bytes_b64`
and `projection_path` where they apply) and rejects anything else before the
daemon is called. A parameter added to a daemon VFS method is therefore *not*
reachable from MCP until it is added to that allowlist too.

## Resources

VFS paths are also addressable as resources:

- `resources/list` returns the files at the VFS root.
- `resources/templates/list` advertises `bloom:///{+path}` for everything else.
- `resources/read` fetches one path.

Resource URIs are RFC 3986 URIs with an empty authority. Path segments are
percent-encoded, so a VFS name containing `%`, a space, `?`, or `#` round-trips
exactly:

```
/docs/README.md          →  bloom:///docs/README.md
/requests/odd name#1     →  bloom:///requests/odd%20name%231
```

A URI with a raw `?` or `#`, or with a `%2F` that would decode into an extra
separator, is rejected rather than read as some other path.

MCP clients treat resources as inert context and commonly fetch them without
asking a human. Bloom therefore refuses to serve a side-effecting path as a
resource: `resources/read` stats the path first and answers `-32010` if reading
it would act, naming `vfs_read` as the way to do it deliberately. No VFS
functionality is lost — the tool still performs the read.

## Error codes

Tool failures come back inside the result as `isError: true`, with the daemon's
own code and message in `structuredContent.error` (`-32004` not found, `-32007`
permission denied, and so on). That vocabulary is unchanged from `bloom vfs`.

The resource surface speaks MCP's vocabulary instead, because clients branch on
it. The daemon's code is always preserved in `error.data.daemonCode`.

| Condition                     | `resources/read` code | Notes                                  |
| ----------------------------- | --------------------- | -------------------------------------- |
| Path does not exist           | `-32002`              | MCP "Resource not found"               |
| Daemon unreachable            | `-32603`              | Start it with `bloom serve`            |
| Reading the path would act    | `-32010`              | Use the `vfs_read` tool instead        |
| Other daemon verdict          | daemon's code         | e.g. `-32007` permission denied        |
| Unknown URI scheme or shape   | `-32602`              | Not a `bloom:///…` URI                 |

## What it cannot do

The daemon also exposes `machine.execute`, `petals.*`, `confirm_batch`, and
`shutdown` on the same socket. None of them are tools here and there is no
generic pass-through, so an MCP client cannot name them — the proxy models the
five VFS methods as a closed enum rather than forwarding a method string.
