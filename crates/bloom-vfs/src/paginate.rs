//! Bounded projection / pagination primitive (spec §3.1, §8).
//!
//! `ls` over a VFS collection must return a **bounded** set of
//! affordances — a directory that fans out to thousands of children
//! would otherwise swamp the NFS `READDIR` path and any agent reading
//! it. The convention this module enshrines:
//!
//! - A collection with at most [`PAGE_SIZE`] entries lists them
//!   directly.
//! - A larger collection projects as a set of `page/<NNNNNN>`
//!   sub-directories. `ls collection/` returns the `page` directory;
//!   `ls collection/page` returns `000000`, `000001`, …; and
//!   `ls collection/page/<NNNNNN>` returns that page's slice.
//!
//! The page index is a zero-padded six-digit decimal so lexical sort
//! (which is all NFS `READDIR` and `ls` give) matches numeric order up
//! to a million pages — far past anything the DeFi demo exercises.
//!
//! Spec §8 calls this "added now, lightly exercised": the DeFi front
//! door barely needs it, but Bloombook (feeds / votes) leans on it
//! later, so the primitive lives in the protocol layer from the start.

use crate::handler::Entry;

/// Maximum number of entries a single page (or a direct, un-paged
/// listing) may contain. Chosen to stay comfortably under typical NFS
/// `READDIR` reply sizing while still letting most listings render in
/// one page.
pub const PAGE_SIZE: usize = 256;

/// Width of the zero-padded page-index segment (`page/000000`).
pub const PAGE_INDEX_WIDTH: usize = 6;

/// Render a page index as its zero-padded `page/` child name
/// (`0 -> "000000"`, `42 -> "000042"`).
pub fn page_name(index: usize) -> String {
    format!("{index:0width$}", width = PAGE_INDEX_WIDTH)
}

/// Parse a `page/` child name (`"000042"`) back into its numeric index.
/// Returns `None` if the name is not a valid zero-padded page index of
/// the canonical width.
pub fn parse_page_name(name: &str) -> Option<usize> {
    if name.len() != PAGE_INDEX_WIDTH || !name.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    name.parse::<usize>().ok()
}

/// Number of pages a collection of `total` entries projects into. A
/// collection that fits in [`PAGE_SIZE`] is *not* paged (returns the
/// number of direct entries' container is the caller's concern); this
/// helper is only meaningful once `total > PAGE_SIZE`.
pub fn page_count(total: usize) -> usize {
    total.div_ceil(PAGE_SIZE)
}

/// `true` if a collection of `total` entries should project as `page/`
/// sub-directories rather than listing its children directly.
pub fn is_paged(total: usize) -> bool {
    total > PAGE_SIZE
}

/// The result of projecting a collection for a `ls` at the collection
/// root.
#[derive(Debug, Clone)]
pub enum Projection {
    /// The collection fits in a single page: list these entries
    /// directly.
    Direct(Vec<Entry>),
    /// The collection is large: list these `page/` container directory
    /// entry instead. The caller surfaces a single `page` dir; reading
    /// `page/` then yields one entry per page index.
    Paged {
        /// Number of pages (`page/000000` .. `page/<count-1>`).
        page_count: usize,
    },
}

/// Project a collection's entries for an `ls` at the collection root.
///
/// Small collections list directly; large ones collapse to a single
/// `page` directory (whose children the caller renders via
/// [`page_indices`] / [`page_slice`]).
pub fn project(entries: Vec<Entry>) -> Projection {
    if is_paged(entries.len()) {
        Projection::Paged {
            page_count: page_count(entries.len()),
        }
    } else {
        Projection::Direct(entries)
    }
}

/// The `page/` directory listing for a collection of `total` entries:
/// one [`Entry::dir`] per page index, named via [`page_name`].
pub fn page_indices(total: usize) -> Vec<Entry> {
    (0..page_count(total))
        .map(|i| Entry::dir(&page_name(i)))
        .collect()
}

/// The slice of `entries` belonging to page `index` (0-based). Returns
/// an empty slice for an out-of-range page so a stale `ls` of a page
/// that no longer exists degrades to "empty", not an error.
pub fn page_slice<T>(entries: &[T], index: usize) -> &[T] {
    let start = index.saturating_mul(PAGE_SIZE);
    if start >= entries.len() {
        return &[];
    }
    let end = (start + PAGE_SIZE).min(entries.len());
    &entries[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::EntryKind;

    fn entries(n: usize) -> Vec<Entry> {
        (0..n).map(|i| Entry::file(&format!("e{i}"))).collect()
    }

    #[test]
    fn page_name_is_zero_padded_six_digits() {
        assert_eq!(page_name(0), "000000");
        assert_eq!(page_name(1), "000001");
        assert_eq!(page_name(42), "000042");
        assert_eq!(page_name(123_456), "123456");
    }

    #[test]
    fn parse_page_name_round_trips_and_rejects_junk() {
        assert_eq!(parse_page_name("000000"), Some(0));
        assert_eq!(parse_page_name("000042"), Some(42));
        // Wrong width / non-numeric → None (fails closed).
        assert_eq!(parse_page_name("42"), None);
        assert_eq!(parse_page_name("0000042"), None);
        assert_eq!(parse_page_name("00x000"), None);
        assert_eq!(parse_page_name(""), None);
    }

    #[test]
    fn small_collection_lists_directly() {
        let proj = project(entries(PAGE_SIZE));
        match proj {
            Projection::Direct(es) => assert_eq!(es.len(), PAGE_SIZE),
            other => panic!("expected Direct, got {other:?}"),
        }
    }

    #[test]
    fn large_collection_projects_as_pages() {
        // PAGE_SIZE + 1 just tips over into two pages.
        let proj = project(entries(PAGE_SIZE + 1));
        match proj {
            Projection::Paged { page_count } => assert_eq!(page_count, 2),
            other => panic!("expected Paged, got {other:?}"),
        }
    }

    #[test]
    fn page_count_rounds_up() {
        assert_eq!(page_count(0), 0);
        assert_eq!(page_count(PAGE_SIZE), 1);
        assert_eq!(page_count(PAGE_SIZE + 1), 2);
        assert_eq!(page_count(PAGE_SIZE * 3), 3);
        assert_eq!(page_count(PAGE_SIZE * 3 + 1), 4);
    }

    #[test]
    fn page_indices_are_named_and_bounded() {
        let total = PAGE_SIZE * 2 + 5; // 3 pages
        let idx = page_indices(total);
        assert_eq!(idx.len(), 3);
        assert_eq!(idx[0].name, "000000");
        assert_eq!(idx[1].name, "000001");
        assert_eq!(idx[2].name, "000002");
        assert!(idx.iter().all(|e| e.kind == EntryKind::Dir));
    }

    #[test]
    fn page_slice_bounds_each_page() {
        let es = entries(PAGE_SIZE * 2 + 5);
        // First page is full.
        assert_eq!(page_slice(&es, 0).len(), PAGE_SIZE);
        // Second page is full.
        assert_eq!(page_slice(&es, 1).len(), PAGE_SIZE);
        // Third page has the remainder.
        assert_eq!(page_slice(&es, 2).len(), 5);
        // Out-of-range page → empty (not an error).
        assert!(page_slice(&es, 3).is_empty());
        assert!(page_slice(&es, 999).is_empty());
    }

    #[test]
    fn every_ls_is_bounded_by_page_size() {
        // A collection larger than one page projects as page/000000,
        // page/000001, … and each page's slice is <= PAGE_SIZE: no
        // single `ls` ever returns more than PAGE_SIZE entries.
        let es = entries(PAGE_SIZE * 4 + 7);
        match project(es.clone()) {
            Projection::Paged { page_count } => {
                assert_eq!(page_count, 5);
                for p in 0..page_count {
                    assert!(page_slice(&es, p).len() <= PAGE_SIZE);
                }
                // The page-index listing is itself tiny / bounded.
                assert_eq!(page_indices(es.len()).len(), 5);
            }
            other => panic!("expected Paged, got {other:?}"),
        }
    }
}
