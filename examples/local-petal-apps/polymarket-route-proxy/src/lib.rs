#![no_std]
#![allow(clippy::too_many_arguments)]

extern crate alloc;

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::bloom::route::types::EntryKind;
use crate::bloom::vfs::readwrite as vfs;

wit_bindgen::generate!({
    path: "wit",
    world: "route-file",
    generate_all
});

struct Route;

fn native_path(path: &str) -> String {
    if path.is_empty() {
        "polymarket".to_owned()
    } else {
        format!("polymarket/{path}")
    }
}

fn route_kind(path: &str) -> EntryKind {
    let leaf = path.rsplit('/').next().unwrap_or_default();
    if path.is_empty() || leaf == "$index" || leaf == "$list" || is_directory_path(path) {
        EntryKind::Dir
    } else {
        EntryKind::File
    }
}

fn is_directory_path(path: &str) -> bool {
    let segments = path.split('/').collect::<Vec<_>>();
    matches!(
        segments.as_slice(),
        ["markets"]
            | ["markets", _]
            | ["search"]
            | ["positions"]
            | ["positions", _]
            | ["onboard"]
            | ["onboard", _]
            | ["account"]
            | ["account", _]
            | ["fund"]
            | ["fund", _]
            | ["fund", _, _]
            | ["trade"]
            | ["trade", _]
            | ["trade", _, "drafts"]
            | ["trade", _, "drafts", _]
            | ["trade", _, "receipts"]
            | ["trade", _, "receipts", _]
    )
}

fn is_writable_path(path: &str) -> bool {
    path.ends_with("/new") || path.ends_with("/begin")
}

fn cache_ttl_ms(path: &str) -> Option<u64> {
    if path.starts_with("onboard/") {
        None
    } else if path.starts_with("account/") {
        Some(5_000)
    } else if path.ends_with("/book.json") || path.ends_with("/prices.json") {
        Some(2_000)
    } else if path.starts_with("positions/") {
        Some(10_000)
    } else {
        Some(30_000)
    }
}

fn metadata_for(path: &str) -> RouteMeta {
    let kind = route_kind(path);
    let writable = kind == EntryKind::File && is_writable_path(path);
    RouteMeta {
        kind,
        mode: match kind {
            EntryKind::Dir => 0o755,
            EntryKind::File if writable => 0o644,
            EntryKind::File => 0o444,
            EntryKind::Symlink => 0o777,
        },
        cache_ttl_ms: cache_ttl_ms(path),
        side_effecting_read: false,
        write_async: false,
        description: Some(format!("Proxy to native polymarket/{path} VFS path")),
        consent_summary: None,
        required_caps: if writable {
            vec!["bloom:vfs.read".to_owned(), "bloom:vfs.write".to_owned()]
        } else {
            vec!["bloom:vfs.read".to_owned()]
        },
        sign_intent: None,
        executable: false,
    }
}

fn entry_kind(kind: vfs::EntryKind) -> EntryKind {
    match kind {
        vfs::EntryKind::Dir => EntryKind::Dir,
        vfs::EntryKind::File => EntryKind::File,
        vfs::EntryKind::Symlink => EntryKind::Symlink,
    }
}

fn route_entry(entry: vfs::Entry) -> Entry {
    Entry {
        name: entry.name,
        kind: entry_kind(entry.kind),
        mode: entry.mode,
        size: entry.size,
        link_target: entry.link_target,
    }
}

fn route_error(message: String) -> RouteError {
    let lower = message.to_ascii_lowercase();
    if lower.contains("not found") {
        RouteError::NotFound(message)
    } else if lower.contains("not a dir") || lower.contains("notadir") {
        RouteError::NotADir(message)
    } else if lower.contains("denied") || lower.contains("permission") {
        RouteError::Denied(message)
    } else if lower.contains("invalid") {
        RouteError::Invalid(message)
    } else if lower.contains("unsupported") {
        RouteError::Unsupported(message)
    } else {
        RouteError::Backend(message)
    }
}

impl Guest for Route {
    fn metadata(ctx: Ctx) -> Result<RouteMeta, RouteError> {
        Ok(metadata_for(&ctx.path))
    }

    fn lookup(ctx: Ctx) -> Result<Entry, RouteError> {
        vfs::lookup(&native_path(&ctx.path))
            .map(route_entry)
            .map_err(route_error)
    }

    fn list(ctx: Ctx) -> Result<Vec<Entry>, RouteError> {
        vfs::list(&native_path(&ctx.path))
            .map(|entries| entries.into_iter().map(route_entry).collect())
            .map_err(route_error)
    }

    fn read(ctx: Ctx) -> Result<Vec<u8>, RouteError> {
        vfs::read(&native_path(&ctx.path)).map_err(route_error)
    }

    fn write(ctx: Ctx, body: Vec<u8>) -> Result<(), RouteError> {
        vfs::write(&native_path(&ctx.path), &body).map_err(route_error)
    }
}

export!(Route);
