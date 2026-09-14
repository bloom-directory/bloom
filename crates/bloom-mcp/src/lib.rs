//! Model Context Protocol proxy over the Bloom VFS command surface.
//!
//! This crate adds no wallet semantics of its own. Every MCP tool and resource
//! is a thin adapter over one of the five canonical VFS commands the daemon
//! already exposes over its Unix-socket JSON-RPC endpoint — the same commands
//! `bloom vfs cat|ls|stat|write` use:
//!
//! | MCP tool              | VFS command         | CLI equivalent    |
//! | --------------------- | ------------------- | ----------------- |
//! | `vfs_list`            | `list`              | `bloom vfs ls`    |
//! | `vfs_read`            | `read`              | `bloom vfs cat`   |
//! | `vfs_stat`            | `lookup`            | `bloom vfs stat`  |
//! | `vfs_write`           | `write`             | `bloom vfs write` |
//! | `vfs_write_then_stat` | `write_with_lookup` | (staging flows)   |
//!
//! `resources/read` maps `bloom:///<path>` onto the same `read` command,
//! except for the few paths whose read *is* the action — those stay tool-only,
//! because MCP clients fetch resources without asking.
//!
//! Because the proxy delegates, path parsing, authorization, policy gates,
//! audit journalling, caching, and error codes all keep happening in
//! `bloom_vfs` and its handlers. New *paths* therefore appear here for free:
//! every subtree the daemon grows is immediately listable, readable, and
//! writable through these five tools. New *parameters* do not. Each tool
//! forwards a fixed argument allowlist (`tools::ToolSpec::accepted_arguments`)
//! and rejects anything else before the daemon is called, so adding an
//! argument to a daemon VFS method also means adding it here — which is the
//! trade for never letting an MCP client name a parameter this proxy has not
//! reviewed. Two tests keep that list honest against the rest of the surface:
//! `advertised_schema_matches_the_forwarded_argument_allowlist` (allowlist vs.
//! `tools/list` schema) and `every_advertised_argument_reaches_the_daemon` in
//! `tests/vfs_proxy.rs` (allowlist vs. a live daemon).
//!
//! The server is **disabled by default**. [`ensure_enabled`] is the single gate;
//! `bloom mcp serve` calls it before touching stdin, stdout, or the daemon
//! socket, so an operator must set `[mcp] enabled = true` in `config.toml`
//! before anything can start.

#![forbid(unsafe_code)]

mod backend;
mod server;
mod tools;

use std::path::Path;

use bloom_proto::McpConfig;
use thiserror::Error;

pub use backend::{
    DAEMON_NOT_FOUND_CODE, DAEMON_UNREACHABLE_CODE, IpcVfsCommands, VfsCommandError, VfsCommands,
    VfsMethod,
};
pub use server::{
    McpServer, PROTOCOL_VERSION, RESOURCE_IS_AN_ACTION_CODE, RESOURCE_NOT_FOUND_CODE, SERVER_NAME,
    SUPPORTED_PROTOCOL_VERSIONS,
};
pub use tools::{RESOURCE_SCHEME, TOOLS, ToolSpec};

/// Returned when the MCP server is asked to start without an explicit opt-in.
#[derive(Debug, Error)]
#[error(
    "the Bloom MCP server is disabled; set `enabled = true` under `[mcp]` in {config_path} to allow it to start"
)]
pub struct McpDisabled {
    pub config_path: String,
}

/// The only way to start an MCP server. Fails closed: a missing `[mcp]` block,
/// a missing config file, and `enabled = false` all mean disabled.
pub fn ensure_enabled(config: &McpConfig, config_path: &Path) -> Result<(), McpDisabled> {
    if config.enabled {
        return Ok(());
    }
    Err(McpDisabled {
        config_path: config_path.display().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_configuration_refuses_to_start() {
        let error = ensure_enabled(&McpConfig::default(), Path::new("/home/.bloom/config.toml"))
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("disabled"), "{message}");
        assert!(message.contains("[mcp]"), "{message}");
        assert!(message.contains("/home/.bloom/config.toml"), "{message}");
    }

    #[test]
    fn an_explicit_opt_in_starts() {
        ensure_enabled(
            &McpConfig { enabled: true },
            Path::new("/home/.bloom/config.toml"),
        )
        .unwrap();
    }
}
