//! SQLite index: `height → (state_root, blob_hash)`.
//!
//! Backed by `<bloom_home>/chain/state_index.sqlite`.

use std::path::Path;

use anyhow::{Context, Result};
use bloom_chain_types::types::Hash32;
use rusqlite::{Connection, params};
use tracing::debug;

/// SQLite-backed index from block height to state root + blob hash.
pub struct StateIndex {
    conn: parking_lot::Mutex<Connection>,
}

impl StateIndex {
    /// Open (or create) the index at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("open state_index.sqlite: {}", path.display()))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS state_index (
                height      INTEGER PRIMARY KEY,
                state_root  BLOB NOT NULL,
                blob_hash   BLOB NOT NULL
            );",
        )
        .context("create state_index table")?;

        Ok(StateIndex {
            conn: parking_lot::Mutex::new(conn),
        })
    }

    /// Insert or replace an entry.
    pub fn put(&self, height: u64, state_root: &Hash32, blob_hash: &Hash32) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO state_index (height, state_root, blob_hash) VALUES (?1, ?2, ?3)",
            params![height as i64, &state_root.0[..], &blob_hash.0[..]],
        )
        .context("insert state_index")?;
        debug!(height, "state_index.put");
        Ok(())
    }

    /// Look up state root and blob hash by height.
    pub fn get(&self, height: u64) -> Result<Option<(Hash32, Hash32)>> {
        let conn = self.conn.lock();
        let mut stmt =
            conn.prepare_cached("SELECT state_root, blob_hash FROM state_index WHERE height = ?1")?;
        let mut rows = stmt.query(params![height as i64])?;
        if let Some(row) = rows.next()? {
            let sr_bytes: Vec<u8> = row.get(0)?;
            let bh_bytes: Vec<u8> = row.get(1)?;
            if sr_bytes.len() != 32 || bh_bytes.len() != 32 {
                return Err(anyhow::anyhow!("corrupt state_index at height {height}"));
            }
            let mut sr = [0u8; 32];
            let mut bh = [0u8; 32];
            sr.copy_from_slice(&sr_bytes);
            bh.copy_from_slice(&bh_bytes);
            Ok(Some((Hash32(sr), Hash32(bh))))
        } else {
            Ok(None)
        }
    }

    /// Return the highest indexed height, or `None` if empty.
    pub fn latest_height(&self) -> Result<Option<u64>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached("SELECT MAX(height) FROM state_index")?;
        let h: Option<i64> = stmt.query_row([], |row| row.get(0))?;
        Ok(h.map(|v| v as u64))
    }

    /// Return the lowest indexed height, or `None` if empty.
    pub fn oldest_height(&self) -> Result<Option<u64>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached("SELECT MIN(height) FROM state_index")?;
        let h: Option<i64> = stmt.query_row([], |row| row.get(0))?;
        Ok(h.map(|v| v as u64))
    }

    /// Delete rows that point at blobs removed from the content-addressed store.
    pub fn delete_blob_hashes(&self, blob_hashes: &[Hash32]) -> Result<usize> {
        if blob_hashes.is_empty() {
            return Ok(0);
        }

        let mut conn = self.conn.lock();
        let tx = conn.transaction().context("begin state_index prune")?;
        let mut deleted = 0usize;
        for blob_hash in blob_hashes {
            deleted += tx
                .execute(
                    "DELETE FROM state_index WHERE blob_hash = ?1",
                    params![&blob_hash.0[..]],
                )
                .context("delete pruned state_index rows")?;
        }
        tx.commit().context("commit state_index prune")?;
        debug!(deleted, "state_index.prune_pruned_blobs");
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delete_blob_hashes_updates_oldest_height() {
        let tmp = tempfile::tempdir().unwrap();
        let index = StateIndex::open(&tmp.path().join("state_index.sqlite")).unwrap();
        let root1 = Hash32([0x11; 32]);
        let root2 = Hash32([0x22; 32]);
        let blob1 = Hash32([0xAA; 32]);
        let blob2 = Hash32([0xBB; 32]);

        index.put(1, &root1, &blob1).unwrap();
        index.put(2, &root2, &blob2).unwrap();
        assert_eq!(index.oldest_height().unwrap(), Some(1));

        assert_eq!(index.delete_blob_hashes(&[blob1]).unwrap(), 1);
        assert_eq!(index.get(1).unwrap(), None);
        assert_eq!(index.oldest_height().unwrap(), Some(2));
    }
}
