//! Example local handler petal mounted at `apps/misc-tools/`.

use bloom_petal_sdk::{
    DispatchEntry, DispatchEntryKind, DispatchOp, DispatchRequest, DispatchResponse,
};

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
            message: "misc-tools is read-only".into(),
        },
    }
}

fn lookup(path: &str) -> DispatchResponse {
    match path {
        "" | "echo" | "hash" => DispatchResponse::Lookup(dir(name_for(path))),
        "gas-now" => DispatchResponse::Lookup(file("gas-now", gas_now().len() as u64)),
        _ if path.starts_with("echo/") => {
            let input = path.trim_start_matches("echo/");
            if !is_safe_dynamic_leaf(input) {
                return not_found(path);
            }
            DispatchResponse::Lookup(file(input, input.len() as u64 + 1))
        }
        _ if path.starts_with("hash/") => {
            let input = path.trim_start_matches("hash/");
            if !is_safe_dynamic_leaf(input) {
                return not_found(path);
            }
            DispatchResponse::Lookup(file(input, 19))
        }
        _ => not_found(path),
    }
}

fn list(path: &str) -> DispatchResponse {
    match path {
        "" => DispatchResponse::List(vec![
            dir("echo"),
            dir("hash"),
            file("gas-now", gas_now().len() as u64),
        ]),
        "echo" | "hash" => DispatchResponse::List(Vec::new()),
        _ => not_found(path),
    }
}

fn read(path: &str) -> DispatchResponse {
    if let Some(input) = path.strip_prefix("echo/") {
        if !is_safe_dynamic_leaf(input) {
            return not_found(path);
        }
        return DispatchResponse::Read(format!("{input}\n").into_bytes());
    }
    if let Some(input) = path.strip_prefix("hash/") {
        if !is_safe_dynamic_leaf(input) {
            return not_found(path);
        }
        return DispatchResponse::Read(format!("0x{:016x}\n", fnv1a64(input.as_bytes())).into());
    }
    if path == "gas-now" {
        return DispatchResponse::Read(gas_now().as_bytes().to_vec());
    }
    not_found(path)
}

fn name_for(path: &str) -> &str {
    if path.is_empty() { "misc-tools" } else { path }
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

fn file(name: &str, size: u64) -> DispatchEntry {
    DispatchEntry {
        name: name.into(),
        kind: DispatchEntryKind::File,
        size,
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

fn gas_now() -> &'static str {
    "{\"slow_gwei\":15,\"standard_gwei\":20,\"fast_gwei\":30,\"source\":\"local-petal-example\"}\n"
}

fn is_safe_dynamic_leaf(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value.contains('/')
        && !value.contains('\\')
        && !value.bytes().any(|byte| byte == 0)
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_path(path: &str) -> Vec<u8> {
        match handle(DispatchRequest {
            op: DispatchOp::Read,
            path: path.into(),
            body: Vec::new(),
            ctx: Vec::new(),
        }) {
            DispatchResponse::Read(bytes) => bytes,
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn echo_reads_input_from_path() {
        assert_eq!(read_path("echo/hello"), b"hello\n");
    }

    #[test]
    fn hash_is_stable() {
        assert_eq!(
            String::from_utf8(read_path("hash/hello")).unwrap(),
            "0xa430d84680aabd0b\n"
        );
    }

    #[test]
    fn dynamic_tools_reject_multi_segment_inputs() {
        assert!(matches!(
            handle(DispatchRequest {
                op: DispatchOp::Lookup,
                path: "echo/a/b".into(),
                body: Vec::new(),
                ctx: Vec::new(),
            }),
            DispatchResponse::Error { code: -1, .. }
        ));
        assert!(matches!(
            handle(DispatchRequest {
                op: DispatchOp::Read,
                path: "hash/a/b".into(),
                body: Vec::new(),
                ctx: Vec::new(),
            }),
            DispatchResponse::Error { code: -1, .. }
        ));
    }

    #[test]
    fn root_lists_three_tools() {
        match handle(DispatchRequest {
            op: DispatchOp::List,
            path: String::new(),
            body: Vec::new(),
            ctx: Vec::new(),
        }) {
            DispatchResponse::List(entries) => {
                let names: Vec<_> = entries.into_iter().map(|entry| entry.name).collect();
                assert_eq!(names, ["echo", "hash", "gas-now"]);
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }
}
