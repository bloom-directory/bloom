use std::{
    fs,
    path::Path,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use uuid::Uuid;

use crate::Envelope;

#[derive(Clone, Debug)]
pub struct ReplayStore {
    connection: Arc<Mutex<Connection>>,
}

impl ReplayStore {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if !path.exists() {
            let mut options = fs::OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(path)?;
        }
        let connection = Connection::open(path)
            .with_context(|| format!("open peer state {}", path.display()))?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS seen_nonces (
               sender_endpoint TEXT NOT NULL,
               nonce TEXT NOT NULL,
               message_id TEXT NOT NULL UNIQUE,
               expires_at_ms INTEGER NOT NULL,
               PRIMARY KEY(sender_endpoint, nonce)
             );
             CREATE TABLE IF NOT EXISTS messages (
               message_id TEXT PRIMARY KEY,
               correlation_id TEXT,
               peer_endpoint TEXT NOT NULL,
               direction TEXT NOT NULL,
               kind TEXT NOT NULL,
               state TEXT NOT NULL,
               payload_digest TEXT NOT NULL,
               envelope_json BLOB NOT NULL,
               expires_at_ms INTEGER NOT NULL
             );",
        )?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    pub fn memory() -> Result<Self> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "CREATE TABLE seen_nonces (
               sender_endpoint TEXT NOT NULL,
               nonce TEXT NOT NULL,
               message_id TEXT NOT NULL UNIQUE,
               expires_at_ms INTEGER NOT NULL,
               PRIMARY KEY(sender_endpoint, nonce)
             );
             CREATE TABLE messages (
               message_id TEXT PRIMARY KEY,
               correlation_id TEXT,
               peer_endpoint TEXT NOT NULL,
               direction TEXT NOT NULL,
               kind TEXT NOT NULL,
               state TEXT NOT NULL,
               payload_digest TEXT NOT NULL,
               envelope_json BLOB NOT NULL,
               expires_at_ms INTEGER NOT NULL
             );",
        )?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    /// Atomically reserves a nonce. False means the message is a replay.
    pub fn reserve(
        &self,
        sender: &str,
        nonce: Uuid,
        message_id: Uuid,
        expires_at_ms: u64,
    ) -> Result<bool> {
        let connection = self.connection.lock().expect("replay store mutex poisoned");
        let changed = connection.execute(
            "INSERT OR IGNORE INTO seen_nonces(sender_endpoint, nonce, message_id, expires_at_ms)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                sender,
                nonce.to_string(),
                message_id.to_string(),
                expires_at_ms as i64
            ],
        )?;
        Ok(changed == 1)
    }

    pub fn record_envelope(
        &self,
        envelope: &Envelope,
        peer_endpoint: &str,
        direction: &str,
        state: &str,
    ) -> Result<()> {
        let connection = self.connection.lock().expect("replay store mutex poisoned");
        connection.execute(
            "INSERT INTO messages(
               message_id, correlation_id, peer_endpoint, direction, kind,
               state, payload_digest, envelope_json, expires_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(message_id) DO UPDATE SET state=excluded.state",
            params![
                envelope.message_id.to_string(),
                envelope.correlation_id.map(|id| id.to_string()),
                peer_endpoint,
                direction,
                envelope.kind.to_string(),
                state,
                envelope.payload_digest,
                serde_json::to_vec(envelope)?,
                envelope.expires_at_ms as i64,
            ],
        )?;
        Ok(())
    }

    pub fn purge_expired(&self, current_ms: u64) -> Result<usize> {
        let connection = self.connection.lock().expect("replay store mutex poisoned");
        let messages = connection.execute(
            "DELETE FROM messages WHERE expires_at_ms < ?1",
            params![current_ms as i64],
        )?;
        connection.execute(
            "DELETE FROM seen_nonces WHERE expires_at_ms < ?1",
            params![current_ms as i64],
        )?;
        Ok(messages)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_reservation_is_atomic_and_rejects_replay() {
        let store = ReplayStore::memory().unwrap();
        let nonce = Uuid::new_v4();
        let message = Uuid::new_v4();
        assert!(store.reserve("peer", nonce, message, 42).unwrap());
        assert!(!store.reserve("peer", nonce, Uuid::new_v4(), 43).unwrap());
        assert!(!store.reserve("other", Uuid::new_v4(), message, 43).unwrap());
    }
}
