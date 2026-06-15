//! Scripted HTTP test server shared by the crate's unit tests.
//!
//! Extends the single-request "canned server" pattern (see the bloom-vfs
//! polymarket handler tests) to a multi-request server: it accepts connections
//! in a loop, routes each request to the first matching [`Rule`] by method +
//! path substring, and records every request so tests can assert *what was not
//! called* (idempotency) as precisely as what was.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A response rule: the first rule whose `method` (empty = any) and
/// `path_contains` both match the request wins.
pub struct Rule {
    pub method: &'static str,
    pub path_contains: &'static str,
    pub status: u16,
    pub body: String,
}

impl Rule {
    pub fn get(path_contains: &'static str, body: impl Into<String>) -> Self {
        Self {
            method: "GET",
            path_contains,
            status: 200,
            body: body.into(),
        }
    }
    pub fn post(path_contains: &'static str, body: impl Into<String>) -> Self {
        Self {
            method: "POST",
            path_contains,
            status: 200,
            body: body.into(),
        }
    }
}

/// One observed request (method, path incl. query, headers, body).
#[derive(Debug, Clone)]
pub struct SeenRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl SeenRequest {
    /// Case-insensitive header lookup.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

pub struct ScriptedServer {
    pub addr: SocketAddr,
    seen: Arc<Mutex<Vec<SeenRequest>>>,
    handle: tokio::task::JoinHandle<()>,
}

impl ScriptedServer {
    pub async fn start(rules: Vec<Rule>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen: Arc<Mutex<Vec<SeenRequest>>> = Arc::default();
        let seen_w = seen.clone();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let Some(req) = read_request(&mut sock).await else {
                    continue;
                };
                let (status, body) = rules
                    .iter()
                    .find(|r| {
                        (r.method.is_empty() || r.method == req.method)
                            && req.path.contains(r.path_contains)
                    })
                    .map(|r| (r.status, r.body.clone()))
                    .unwrap_or((404, format!("no rule for {} {}", req.method, req.path)));
                seen_w.lock().unwrap().push(req);
                let resp = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len(),
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        Self { addr, seen, handle }
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn seen(&self) -> Vec<SeenRequest> {
        self.seen.lock().unwrap().clone()
    }

    /// Requests whose path contains `frag`.
    pub fn seen_paths_containing(&self, frag: &str) -> Vec<SeenRequest> {
        self.seen()
            .into_iter()
            .filter(|r| r.path.contains(frag))
            .collect()
    }
}

impl Drop for ScriptedServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Minimal HTTP/1.1 request reader: head until `\r\n\r\n`, then
/// `Content-Length` bytes of body.
async fn read_request(sock: &mut tokio::net::TcpStream) -> Option<SeenRequest> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        let n = sock.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.lines();
    let mut req_line = lines.next()?.split_whitespace();
    let method = req_line.next()?.to_string();
    let path = req_line.next()?.to_string();
    let headers: Vec<(String, String)> = lines
        .clone()
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let content_length: usize = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0);
    let mut body = buf[head_end..].to_vec();
    while body.len() < content_length {
        let n = sock.read(&mut tmp).await.ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    Some(SeenRequest {
        method,
        path,
        headers,
        body: String::from_utf8_lossy(&body).to_string(),
    })
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
