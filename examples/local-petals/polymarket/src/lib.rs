//! Local-petal bridge for the existing native `polymarket/` VFS handler.
//!
//! This is a migration/coexistence petal: it exposes the native tree at
//! `apps/polymarket/` by using only public VFS host imports. It does not move
//! Polymarket credentials or signing into the petal.

use bloom_petal_sdk::{
    DispatchEntry, DispatchEntryKind, DispatchOp, DispatchRequest, DispatchResponse, HostStatus,
    SdkError,
};

const UPSTREAM_ROOT: &str = "polymarket";
const MAX_LIST_BYTES: usize = 256 * 1024;
const MAX_READ_BYTES: usize = 8 * 1024 * 1024;
const MARKET_FILES: [&str; 3] = ["market.json", "book.json", "prices.json"];
const POSITION_FILES: [&str; 3] = ["positions.json", "trades.json", "activity.json"];
const ONBOARD_FILES: [&str; 3] = ["status.json", "plan.md", "approvals.json"];
const ACCOUNT_FILES: [&str; 2] = ["portfolio.json", "orders.json"];
const FUND_FILES: [&str; 3] = ["plan.md", "request.json", "status.json"];
const DRAFT_FILES: [&str; 5] = [
    "plan.md",
    "order.json",
    "policy_check.json",
    "quote.json",
    "review_intent.json",
];

#[cfg_attr(target_family = "wasm", unsafe(link_section = "bloom_petal_manifest"))]
#[used]
pub static BLOOM_LOCAL_MANIFEST: [u8; include_bytes!("../Petal.toml").len()] =
    *include_bytes!("../Petal.toml");

bloom_petal_sdk::export_dispatch!(handle);

pub fn handle(req: DispatchRequest) -> DispatchResponse {
    let relative = match validate_relative_path(&req.path) {
        Ok(path) => path,
        Err(message) => return error(-3, message),
    };
    let upstream = match upstream_path(relative) {
        Ok(path) => path,
        Err(message) => return error(-3, message),
    };
    match req.op {
        DispatchOp::Lookup => lookup(relative),
        DispatchOp::List => list(relative, &upstream),
        DispatchOp::Read => read(relative, &upstream),
        DispatchOp::Write => write(relative, &upstream, &req.body),
    }
}

fn lookup(relative: &str) -> DispatchResponse {
    match path_kind(relative) {
        Some(kind) => DispatchResponse::Lookup(entry(entry_name(relative), kind)),
        None => error(-1, "not found"),
    }
}

fn list(relative: &str, upstream: &str) -> DispatchResponse {
    if path_kind(relative) != Some(DispatchEntryKind::Dir) {
        return error(-3, "not a directory");
    }
    let names = match bloom_petal_sdk::vfs_list(upstream, MAX_LIST_BYTES) {
        Ok(names) => names,
        Err(e) => return sdk_error(e),
    };
    let mut entries = Vec::with_capacity(names.len());
    for name in names {
        let child = child_relative(relative, &name);
        if let Some(kind) = path_kind(&child) {
            entries.push(entry(&name, kind));
        }
    }
    DispatchResponse::List(entries)
}

fn read(relative: &str, upstream: &str) -> DispatchResponse {
    if !matches!(
        path_kind(relative),
        Some(DispatchEntryKind::File | DispatchEntryKind::WritableFile)
    ) {
        return error(-3, "not a file");
    }
    match bloom_petal_sdk::vfs_read(upstream, MAX_READ_BYTES) {
        Ok(bytes) => DispatchResponse::Read(bytes),
        Err(e) => sdk_error(e),
    }
}

fn write(relative: &str, upstream: &str, body: &[u8]) -> DispatchResponse {
    if path_kind(relative) != Some(DispatchEntryKind::WritableFile) {
        return error(-2, "path is not writable through the polymarket bridge");
    }
    match bloom_petal_sdk::vfs_write(upstream, body) {
        Ok(()) => DispatchResponse::Write,
        Err(e) => sdk_error(e),
    }
}

fn validate_relative_path(relative: &str) -> Result<&str, String> {
    if relative.is_empty() {
        return Ok(relative);
    }
    for segment in relative.split('/') {
        if !is_safe_segment(segment) {
            return Err(format!("invalid path segment '{segment}'"));
        }
    }
    Ok(relative)
}

fn upstream_path(relative: &str) -> Result<String, String> {
    validate_relative_path(relative)?;
    if relative.is_empty() {
        return Ok(UPSTREAM_ROOT.into());
    }
    Ok(format!("{UPSTREAM_ROOT}/{relative}"))
}

fn child_relative(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        child.into()
    } else {
        format!("{parent}/{child}")
    }
}

fn is_safe_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && !segment.contains('\\')
        && !segment.bytes().any(|byte| byte == 0)
}

fn path_kind(relative: &str) -> Option<DispatchEntryKind> {
    let segs: Vec<&str> = if relative.is_empty() {
        Vec::new()
    } else {
        relative.split('/').collect()
    };
    match (segs.first().copied(), segs.len()) {
        (None, 0) => Some(DispatchEntryKind::Dir),
        (Some("markets"), 1) => Some(DispatchEntryKind::Dir),
        (Some("markets"), 2) => Some(DispatchEntryKind::Dir),
        (Some("markets"), 3) if MARKET_FILES.contains(&segs[2]) => Some(DispatchEntryKind::File),
        (Some("search"), 1) => Some(DispatchEntryKind::Dir),
        (Some("search"), 2) => Some(DispatchEntryKind::File),
        (Some("positions"), 1) => Some(DispatchEntryKind::Dir),
        (Some("positions"), 2) => Some(DispatchEntryKind::Dir),
        (Some("positions"), 3) if POSITION_FILES.contains(&segs[2]) => {
            Some(DispatchEntryKind::File)
        }
        (Some("onboard"), 1) => Some(DispatchEntryKind::Dir),
        (Some("onboard"), 2) => Some(DispatchEntryKind::Dir),
        (Some("onboard"), 3) if segs[2] == "begin" => Some(DispatchEntryKind::WritableFile),
        (Some("onboard"), 3) if ONBOARD_FILES.contains(&segs[2]) => Some(DispatchEntryKind::File),
        (Some("account"), 1) => Some(DispatchEntryKind::Dir),
        (Some("account"), 2) => Some(DispatchEntryKind::Dir),
        (Some("account"), 3) if ACCOUNT_FILES.contains(&segs[2]) => Some(DispatchEntryKind::File),
        (Some("fund"), 1) => Some(DispatchEntryKind::Dir),
        (Some("fund"), 2) => Some(DispatchEntryKind::Dir),
        (Some("fund"), 3) if segs[2] == "new" => Some(DispatchEntryKind::WritableFile),
        (Some("fund"), 3) => Some(DispatchEntryKind::Dir),
        (Some("fund"), 4) if FUND_FILES.contains(&segs[3]) => Some(DispatchEntryKind::File),
        (Some("trade"), 1) => Some(DispatchEntryKind::Dir),
        (Some("trade"), 2) => Some(DispatchEntryKind::Dir),
        (Some("trade"), 3) if segs[2] == "new" => Some(DispatchEntryKind::WritableFile),
        (Some("trade"), 3) if segs[2] == "drafts" || segs[2] == "receipts" => {
            Some(DispatchEntryKind::Dir)
        }
        (Some("trade"), 4) if segs[2] == "drafts" || segs[2] == "receipts" => {
            Some(DispatchEntryKind::Dir)
        }
        (Some("trade"), 5) if segs[2] == "drafts" && DRAFT_FILES.contains(&segs[4]) => {
            Some(DispatchEntryKind::File)
        }
        (Some("trade"), 5) if segs[2] == "receipts" && segs[4] == "receipt.json" => {
            Some(DispatchEntryKind::File)
        }
        _ => None,
    }
}

fn entry_name(relative: &str) -> &str {
    relative
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("")
}

fn entry(name: &str, kind: DispatchEntryKind) -> DispatchEntry {
    let mode = match kind {
        DispatchEntryKind::Dir => 0o755,
        DispatchEntryKind::WritableFile => 0o644,
        _ => 0o444,
    };
    DispatchEntry {
        name: name.into(),
        kind,
        size: 0,
        mode,
        ttl_hint_ms: None,
        link_target: None,
    }
}

fn sdk_error(e: SdkError) -> DispatchResponse {
    match e {
        SdkError::Host(HostStatus::NotFound) => error(-1, "not found"),
        SdkError::Host(HostStatus::Denied) => error(-2, "denied"),
        SdkError::Host(HostStatus::Invalid) => error(-3, "invalid"),
        SdkError::Host(HostStatus::Backend) => error(-4, "backend error"),
        SdkError::Host(HostStatus::BufferTooSmall { needed }) => {
            error(-5, format!("response too large: needs {needed} bytes"))
        }
        other => error(-4, other.message()),
    }
}

fn error(code: i32, message: impl Into<String>) -> DispatchResponse {
    DispatchResponse::Error {
        code,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_rewrite_rejects_escape_segments() {
        assert_eq!(upstream_path("").unwrap(), "polymarket");
        assert_eq!(
            upstream_path("markets/example/market.json").unwrap(),
            "polymarket/markets/example/market.json"
        );
        assert!(upstream_path("../wallets").is_err());
        assert!(upstream_path("markets//book.json").is_err());
        assert!(upstream_path("markets\\evil").is_err());
    }

    #[test]
    fn path_shapes_are_static_and_expected() {
        assert_eq!(path_kind(""), Some(DispatchEntryKind::Dir));
        assert_eq!(path_kind("markets/foo"), Some(DispatchEntryKind::Dir));
        assert_eq!(
            path_kind("markets/foo/book.json"),
            Some(DispatchEntryKind::File)
        );
        assert_eq!(
            path_kind("onboard/alice/begin"),
            Some(DispatchEntryKind::WritableFile)
        );
        assert_eq!(
            path_kind("trade/alice/drafts/0001/plan.md"),
            Some(DispatchEntryKind::File)
        );
        assert_eq!(
            path_kind("trade/alice/receipts/0001/receipt.json"),
            Some(DispatchEntryKind::File)
        );
        assert_eq!(path_kind("trade/alice/new/extra"), None);
    }

    #[test]
    fn writable_paths_are_exact() {
        assert_eq!(
            path_kind("onboard/alice/begin"),
            Some(DispatchEntryKind::WritableFile)
        );
        assert_eq!(
            path_kind("trade/alice/new"),
            Some(DispatchEntryKind::WritableFile)
        );
        assert_eq!(
            path_kind("fund/alice/new"),
            Some(DispatchEntryKind::WritableFile)
        );
        assert_eq!(
            path_kind("markets/foo/market.json"),
            Some(DispatchEntryKind::File)
        );
        assert_eq!(path_kind("trade/alice/new/extra"), None);
    }
}
