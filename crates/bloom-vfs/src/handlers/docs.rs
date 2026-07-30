//! `docs/` — vendored markdown docs about how to use the FS.

use async_trait::async_trait;
use std::sync::Arc;

use crate::handler::{Entry, Handler, HandlerError};
use crate::path::VfsPath;

#[derive(Clone)]
pub struct DocsHandler {
    readme: String,
    examples: String,
    petals: Arc<dyn Fn() -> Vec<u8> + Send + Sync>,
}

impl Default for DocsHandler {
    fn default() -> Self {
        Self {
            readme: include_str!("../docs/README.md").to_string(),
            examples: include_str!("../docs/examples.md").to_string(),
            petals: Arc::new(|| {
                b"# Installed Petals\n\nNo Petals are currently installed.\n".to_vec()
            }),
        }
    }
}

impl DocsHandler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_petals_renderer(
        mut self,
        renderer: Arc<dyn Fn() -> Vec<u8> + Send + Sync>,
    ) -> Self {
        self.petals = renderer;
        self
    }
}

#[async_trait]
impl Handler for DocsHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let r = self.lookup_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "docs.lookup_err");
        }
        r
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let r = self.read_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "docs.read_err");
        }
        r
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let r = self.list_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "docs.list_err");
        }
        r
    }
}

impl DocsHandler {
    async fn lookup_inner(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        match path.segments() {
            [] => Ok(Entry::dir("")),
            [s] if s == "README.md" => Ok(Entry::file("README.md")),
            [s] if s == "examples.md" => Ok(Entry::file("examples.md")),
            [s] if s == "petals.md" => Ok(Entry::file("petals.md")),
            _ => Err(HandlerError::not_found(path.to_string_path())),
        }
    }

    async fn read_inner(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        match path.segments() {
            [s] if s == "README.md" => Ok(self.readme.as_bytes().to_vec()),
            [s] if s == "examples.md" => Ok(self.examples.as_bytes().to_vec()),
            [s] if s == "petals.md" => Ok((self.petals)()),
            _ => Err(HandlerError::NotAFile(path.to_string_path())),
        }
    }

    async fn list_inner(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        if path.is_root() {
            Ok(vec![
                Entry::file("README.md"),
                Entry::file("examples.md"),
                Entry::file("petals.md"),
            ])
        } else {
            Err(HandlerError::NotADir(path.to_string_path()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::EntryKind;

    #[tokio::test]
    async fn root_lists_embedded_and_dynamic_docs() {
        let h = DocsHandler::new();
        let entries = h.list(&VfsPath::root()).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["README.md", "examples.md", "petals.md"]);
        for e in &entries {
            assert_eq!(e.kind, EntryKind::File);
            // Entry::file => read-only mode.
            assert_eq!(e.mode, 0o444);
        }
    }

    #[tokio::test]
    async fn list_on_subpath_is_not_a_dir() {
        let h = DocsHandler::new();
        let p = VfsPath::parse("/README.md").unwrap();
        let err = h.list(&p).await.unwrap_err();
        assert!(
            matches!(err, HandlerError::NotADir(_)),
            "expected NotADir, got {err:?}"
        );
    }

    #[tokio::test]
    async fn lookup_root_is_dir() {
        let h = DocsHandler::new();
        let e = h.lookup(&VfsPath::root()).await.unwrap();
        assert_eq!(e.kind, EntryKind::Dir);
    }

    #[tokio::test]
    async fn lookup_known_files_are_files() {
        let h = DocsHandler::new();
        for name in ["README.md", "examples.md", "petals.md"] {
            let p = VfsPath::parse(&format!("/{name}")).unwrap();
            let e = h.lookup(&p).await.unwrap();
            assert_eq!(e.kind, EntryKind::File);
            assert_eq!(e.name, name);
        }
    }

    #[tokio::test]
    async fn agent_guidance_is_not_exposed_under_docs() {
        let h = DocsHandler::new();
        let path = VfsPath::parse("/agent-guidance.md").unwrap();

        assert!(matches!(
            h.lookup(&path).await,
            Err(HandlerError::NotFound(_))
        ));
        assert!(matches!(
            h.read(&path).await,
            Err(HandlerError::NotAFile(_))
        ));
    }

    #[tokio::test]
    async fn lookup_missing_doc_is_not_found() {
        let h = DocsHandler::new();
        let p = VfsPath::parse("/missing.md").unwrap();
        let err = h.lookup(&p).await.unwrap_err();
        match err {
            HandlerError::NotFound(s) => assert!(s.contains("missing.md")),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_returns_embedded_bytes() {
        let h = DocsHandler::new();

        let readme = h
            .read(&VfsPath::parse("/README.md").unwrap())
            .await
            .unwrap();
        assert!(!readme.is_empty(), "README.md must have content");
        let s = std::str::from_utf8(&readme).expect("README.md is utf-8");
        // Sanity-check a phrase from the vendored README header.
        assert!(
            s.contains("bloom"),
            "README.md should mention bloom: {s:.80}..."
        );

        let examples = h
            .read(&VfsPath::parse("/examples.md").unwrap())
            .await
            .unwrap();
        assert!(!examples.is_empty(), "examples.md must have content");
        assert!(std::str::from_utf8(&examples).is_ok());
    }

    #[tokio::test]
    async fn petals_doc_is_rendered_at_read_time() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let renderer_calls = calls.clone();
        let h = DocsHandler::new().with_petals_renderer(Arc::new(move || {
            let call = renderer_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            format!("# Installed Petals\n\nrender {call}\n").into_bytes()
        }));
        let path = VfsPath::parse("/petals.md").unwrap();

        let first = String::from_utf8(h.read(&path).await.unwrap()).unwrap();
        let second = String::from_utf8(h.read(&path).await.unwrap()).unwrap();
        assert!(first.contains("render 1"));
        assert!(second.contains("render 2"));
    }

    #[tokio::test]
    async fn read_missing_doc_is_not_a_file() {
        let h = DocsHandler::new();
        let p = VfsPath::parse("/nope.md").unwrap();
        let err = h.read(&p).await.unwrap_err();
        match err {
            HandlerError::NotAFile(s) => assert!(s.contains("nope.md")),
            other => panic!("expected NotAFile, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_root_dir_is_not_a_file() {
        let h = DocsHandler::new();
        let err = h.read(&VfsPath::root()).await.unwrap_err();
        assert!(matches!(err, HandlerError::NotAFile(_)));
    }

    /// Documentation assertion (plan:
    /// docs/plans/2026-07-21-async-vfs-passkey-registration.md): embedded
    /// docs must describe the asynchronous registration path and must never
    /// describe plain `/wallets/new` as creating a local wallet.
    #[tokio::test]
    async fn wallet_creation_docs_describe_async_registration_not_local_wallet() {
        let h = DocsHandler::new();
        for name in ["README.md", "examples.md"] {
            let bytes = h
                .read(&VfsPath::parse(&format!("/{name}")).unwrap())
                .await
                .unwrap();
            let s = String::from_utf8(bytes).unwrap();
            assert!(
                s.contains("wallets/registrations/") && s.contains("status.json"),
                "{name} must document wallets/registrations/<name>/status.json"
            );
            assert!(
                !(s.contains("plain name") && s.contains("creates a local wallet")),
                "{name} must not describe a plain /wallets/new write as creating a local wallet"
            );
        }
    }
}
