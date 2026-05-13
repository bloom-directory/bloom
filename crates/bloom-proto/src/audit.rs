//! Hash-chained append-only audit log.
//!
//! Every entry references the prior entry's blake3 digest. Tampering
//! with any line breaks the chain.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("audit chain broken at line {line}: prev hash mismatch")]
    Broken { line: usize },
}

/// One audit record. Always serialized as a single JSON line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Unix epoch milliseconds.
    pub ts_ms: u128,
    /// What happened. e.g. "wallet.create", "tx.stage", "tx.broadcast".
    pub kind: String,
    /// Optional wallet name (when relevant).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet: Option<String>,
    /// Optional chain name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<String>,
    /// Free-form details.
    #[serde(default)]
    pub data: serde_json::Value,
    /// Hex of the blake3 digest of the previous record's full line. Empty
    /// for the first record.
    pub prev: String,
    /// Hex of the blake3 digest of *this* record minus the `digest` field
    /// itself — i.e. the digest binds the (timestamp, kind, … prev) tuple.
    pub digest: String,
}

#[derive(Clone)]
pub struct AuditLog {
    inner: Arc<Mutex<AuditInner>>,
}

struct AuditInner {
    path: PathBuf,
    last_digest: String,
}

impl AuditLog {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, AuditError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let last_digest = if path.exists() {
            tail_digest(&path)?
        } else {
            String::new()
        };
        Ok(Self {
            inner: Arc::new(Mutex::new(AuditInner { path, last_digest })),
        })
    }

    pub fn append(&self, mut record: AuditRecord) -> Result<AuditRecord, AuditError> {
        let mut g = self.inner.lock();
        record.prev = g.last_digest.clone();
        record.ts_ms = now_ms();
        record.digest = String::new();
        let body = serde_json::to_string(&record)?;
        let digest = blake3::hash(body.as_bytes()).to_hex().to_string();
        record.digest = digest.clone();
        let mut f = OpenOptions::new().create(true).append(true).open(&g.path)?;
        let line = serde_json::to_string(&record)?;
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
        g.last_digest = digest;
        Ok(record)
    }

    /// Hex of the most recently appended record's digest (empty if log is empty).
    pub fn head_hash(&self) -> String {
        self.inner.lock().last_digest.clone()
    }

    /// On-disk path of the audit log file.
    pub fn path(&self) -> PathBuf {
        self.inner.lock().path.clone()
    }

    /// Total number of entries currently persisted on disk. Lines that
    /// fail to parse are skipped (consistent with `verify`'s tolerance of
    /// blank lines). Returns 0 if the file does not exist.
    pub fn count(&self) -> Result<usize, AuditError> {
        let g = self.inner.lock();
        if !g.path.exists() {
            return Ok(0);
        }
        let f = std::fs::File::open(&g.path)?;
        let mut n = 0usize;
        for line in BufReader::new(f).lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }
            n += 1;
        }
        Ok(n)
    }

    /// Read up to the last `n` records from the log, oldest-first. Empty
    /// vec if the log is missing.
    pub fn tail(&self, n: usize) -> Result<Vec<AuditRecord>, AuditError> {
        let g = self.inner.lock();
        if !g.path.exists() || n == 0 {
            return Ok(Vec::new());
        }
        let f = std::fs::File::open(&g.path)?;
        let mut buf: std::collections::VecDeque<AuditRecord> =
            std::collections::VecDeque::with_capacity(n);
        for (line_no, line) in BufReader::new(f).lines().enumerate() {
            let line = line?;
            if line.is_empty() {
                continue;
            }
            let rec: AuditRecord = match serde_json::from_str(&line) {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!(line = line_no + 1, error = %e, "audit.tail.skip_unparsable");
                    continue;
                }
            };
            if buf.len() == n {
                buf.pop_front();
            }
            buf.push_back(rec);
        }
        Ok(buf.into_iter().collect())
    }

    /// Walk the log and return Ok(()) iff the hash chain is intact.
    pub fn verify(path: &Path) -> Result<(), AuditError> {
        if !path.exists() {
            return Ok(());
        }
        let f = std::fs::File::open(path)?;
        let mut prev = String::new();
        for (i, line) in BufReader::new(f).lines().enumerate() {
            let line = line?;
            if line.is_empty() {
                continue;
            }
            let mut rec: AuditRecord = serde_json::from_str(&line)?;
            if rec.prev != prev {
                return Err(AuditError::Broken { line: i + 1 });
            }
            let saved = std::mem::take(&mut rec.digest);
            let body = serde_json::to_string(&rec)?;
            let digest = blake3::hash(body.as_bytes()).to_hex().to_string();
            if digest != saved {
                return Err(AuditError::Broken { line: i + 1 });
            }
            prev = saved;
        }
        Ok(())
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn tail_digest(path: &Path) -> Result<String, AuditError> {
    let f = std::fs::File::open(path)?;
    let mut last = String::new();
    for line in BufReader::new(f).lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        last = line;
    }
    if last.is_empty() {
        return Ok(String::new());
    }
    let rec: AuditRecord = serde_json::from_str(&last)?;
    Ok(rec.digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_verify() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&p).unwrap();
        for i in 0..5 {
            log.append(AuditRecord {
                ts_ms: 0,
                kind: "test".into(),
                wallet: None,
                chain: None,
                data: serde_json::json!({"i": i}),
                prev: String::new(),
                digest: String::new(),
            })
            .unwrap();
        }
        AuditLog::verify(&p).unwrap();
    }

    #[test]
    fn detects_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&p).unwrap();
        log.append(AuditRecord {
            ts_ms: 0,
            kind: "a".into(),
            wallet: None,
            chain: None,
            data: serde_json::json!({}),
            prev: String::new(),
            digest: String::new(),
        })
        .unwrap();
        log.append(AuditRecord {
            ts_ms: 0,
            kind: "b".into(),
            wallet: None,
            chain: None,
            data: serde_json::json!({}),
            prev: String::new(),
            digest: String::new(),
        })
        .unwrap();
        // Corrupt the first line.
        let s = std::fs::read_to_string(&p).unwrap();
        let mut lines: Vec<&str> = s.lines().collect();
        let mut tampered: AuditRecord = serde_json::from_str(lines[0]).unwrap();
        tampered.kind = "evil".into();
        let new_first = serde_json::to_string(&tampered).unwrap();
        lines[0] = &new_first;
        let body = lines.join("\n") + "\n";
        std::fs::write(&p, body).unwrap();
        assert!(AuditLog::verify(&p).is_err());
    }
}
