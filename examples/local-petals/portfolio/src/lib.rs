//! Example vfs.read-only local handler petal mounted at `apps/portfolio/`.

use bloom_petal_sdk::{
    DispatchEntry, DispatchEntryKind, DispatchOp, DispatchRequest, DispatchResponse,
};

const MAX_LIST_BYTES: usize = 64 * 1024;
const MAX_READ_BYTES: usize = 64 * 1024;

#[cfg_attr(target_family = "wasm", unsafe(link_section = "bloom_petal_manifest"))]
#[used]
pub static BLOOM_LOCAL_MANIFEST: [u8; include_bytes!("../Petal.toml").len()] =
    *include_bytes!("../Petal.toml");

bloom_petal_sdk::export_dispatch!(handle);

pub fn handle(req: DispatchRequest) -> DispatchResponse {
    match req.op {
        DispatchOp::Lookup => lookup(&req.path),
        DispatchOp::List => list(&req.path),
        DispatchOp::Read => read(&req.path),
        DispatchOp::Write => DispatchResponse::Error {
            code: -2,
            message: "portfolio is read-only".into(),
        },
    }
}

fn lookup(path: &str) -> DispatchResponse {
    match path {
        "" => DispatchResponse::Lookup(dir("portfolio")),
        "summary.md" => DispatchResponse::Lookup(file("summary.md")),
        _ => not_found(path),
    }
}

fn list(path: &str) -> DispatchResponse {
    match path {
        "" => DispatchResponse::List(vec![file("summary.md")]),
        _ => not_found(path),
    }
}

fn read(path: &str) -> DispatchResponse {
    match path {
        "summary.md" => match build_summary() {
            Ok(summary) => DispatchResponse::Read(summary.into_bytes()),
            Err(message) => DispatchResponse::Error { code: -4, message },
        },
        _ => not_found(path),
    }
}

fn build_summary() -> Result<String, String> {
    let wallets = bloom_petal_sdk::vfs_list("wallets", MAX_LIST_BYTES)
        .map_err(|e| format!("list wallets: {}", e.message()))?;
    let mut rows = Vec::new();
    for wallet in wallets {
        if !is_safe_segment(&wallet) || wallet == "new" {
            continue;
        }
        let address = read_text(&format!("wallets/{wallet}/address"))?;
        let chains = bloom_petal_sdk::vfs_list(&format!("wallets/{wallet}/chains"), MAX_LIST_BYTES)
            .map_err(|e| format!("list chains for {wallet}: {}", e.message()))?;
        for chain in chains {
            if !is_safe_segment(&chain) {
                continue;
            }
            let balance = read_text(&format!("wallets/{wallet}/chains/{chain}/balance.eth"))
                .or_else(|_| read_text(&format!("wallets/{wallet}/chains/{chain}/balance")))?;
            rows.push(PortfolioRow {
                wallet: wallet.clone(),
                chain,
                address: address.clone(),
                balance,
            });
        }
    }
    Ok(render_markdown(&rows))
}

fn read_text(path: &str) -> Result<String, String> {
    let bytes = bloom_petal_sdk::vfs_read(path, MAX_READ_BYTES)
        .map_err(|e| format!("read {path}: {}", e.message()))?;
    let s = String::from_utf8(bytes).map_err(|_| format!("read {path}: invalid utf-8"))?;
    Ok(s.trim().to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PortfolioRow {
    wallet: String,
    chain: String,
    address: String,
    balance: String,
}

fn render_markdown(rows: &[PortfolioRow]) -> String {
    let mut out = String::from("| wallet | chain | address | balance |\n");
    out.push_str("| --- | --- | --- | --- |\n");
    for row in rows {
        out.push_str("| ");
        out.push_str(&escape_cell(&row.wallet));
        out.push_str(" | ");
        out.push_str(&escape_cell(&row.chain));
        out.push_str(" | ");
        out.push_str(&escape_cell(&row.address));
        out.push_str(" | ");
        out.push_str(&escape_cell(&row.balance));
        out.push_str(" |\n");
    }
    out
}

fn escape_cell(s: &str) -> String {
    s.replace('|', "\\|")
}

fn is_safe_segment(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value.contains('/')
        && !value.contains('\\')
        && !value.bytes().any(|byte| byte == 0)
}

fn dir(name: &str) -> DispatchEntry {
    DispatchEntry {
        name: name.into(),
        kind: DispatchEntryKind::Dir,
        size: 0,
        mode: 0o755,
        ttl_hint_ms: None,
        link_target: None,
    }
}

fn file(name: &str) -> DispatchEntry {
    DispatchEntry {
        name: name.into(),
        kind: DispatchEntryKind::File,
        size: 0,
        mode: 0o444,
        ttl_hint_ms: None,
        link_target: None,
    }
}

fn not_found(path: &str) -> DispatchResponse {
    DispatchResponse::Error {
        code: -1,
        message: path.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_markdown_escapes_cells() {
        let rendered = render_markdown(&[PortfolioRow {
            wallet: "ali|ce".into(),
            chain: "base".into(),
            address: "0xabc".into(),
            balance: "1.0 ETH".into(),
        }]);
        assert!(rendered.contains("ali\\|ce"));
        assert!(rendered.contains("| wallet | chain | address | balance |"));
    }

    #[test]
    fn segment_validation_rejects_path_escape() {
        assert!(is_safe_segment("alice"));
        assert!(!is_safe_segment("../alice"));
        assert!(!is_safe_segment("a/b"));
        assert!(!is_safe_segment(".."));
    }
}
