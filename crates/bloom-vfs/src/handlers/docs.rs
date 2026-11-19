//! `docs/` — vendored markdown docs about how to use the FS.

use async_trait::async_trait;
use std::sync::Arc;

use crate::handler::{Entry, Handler, HandlerError};
use crate::path::VfsPath;

/// One short file per topic. The names are the index an agent sees in
/// `ls docs`, so each says what its file answers.
const TOPICS: &[(&str, &str)] = &[
    (
        "cancel-replace-and-unknown-signing.md",
        include_str!("../docs/topics/cancel-replace-and-unknown-signing.md"),
    ),
    (
        "confirm-denied-or-failed.md",
        include_str!("../docs/topics/confirm-denied-or-failed.md"),
    ),
    (
        "error-meanings.md",
        include_str!("../docs/topics/error-meanings.md"),
    ),
    (
        "paid-http-requests.md",
        include_str!("../docs/topics/paid-http-requests.md"),
    ),
    (
        "pay-with-a-saved-card.md",
        include_str!("../docs/topics/pay-with-a-saved-card.md"),
    ),
    (
        "policy-change.md",
        include_str!("../docs/topics/policy-change.md"),
    ),
    (
        "report-a-bloom-problem.md",
        include_str!("../docs/topics/report-a-bloom-problem.md"),
    ),
    (
        "what-the-owner-sees.md",
        include_str!("../docs/topics/what-the-owner-sees.md"),
    ),
    (
        "which-wallet-account-chain.md",
        include_str!("../docs/topics/which-wallet-account-chain.md"),
    ),
];

fn topic(name: &str) -> Option<&'static str> {
    TOPICS
        .iter()
        .find(|(topic, _)| *topic == name)
        .map(|(_, text)| *text)
}

/// A long doc is served as a directory with one file per `## ` section,
/// named after its heading, so a reader takes only the part it needs.
/// `intro` keeps the text before the first section in every file; the
/// examples define `$BLOOM` there.
fn sections(source: &str, intro: bool) -> Vec<(String, String)> {
    let mut parts = source.split("\n## ");
    let preamble = parts.next().unwrap_or_default();
    let preamble = preamble
        .split_once('\n')
        .map_or("", |(_, rest)| rest.trim());
    parts
        .map(|part| {
            let (title, body) = part.split_once('\n').unwrap_or((part, ""));
            let slug = title
                .to_ascii_lowercase()
                .split(|c: char| !c.is_ascii_alphanumeric())
                .filter(|word| !word.is_empty())
                .collect::<Vec<_>>()
                .join("-");
            let text = if intro {
                format!("# {title}\n\n{preamble}\n\n{}\n", body.trim())
            } else {
                format!("# {title}\n\n{}\n", body.trim())
            };
            (format!("{slug}.md"), text)
        })
        .collect()
}

type Sections = Arc<Vec<(String, String)>>;

#[derive(Clone)]
pub struct DocsHandler {
    readme: String,
    examples: Sections,
    wallets: Sections,
    petals: Arc<dyn Fn() -> Vec<u8> + Send + Sync>,
}

impl Default for DocsHandler {
    fn default() -> Self {
        Self {
            readme: include_str!("../docs/README.md").to_string(),
            examples: Arc::new(sections(include_str!("../docs/examples.md"), true)),
            wallets: Arc::new(sections(include_str!("../docs/wallets.md"), false)),
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
    fn dir(&self, name: &str) -> Option<&Sections> {
        match name {
            "examples" => Some(&self.examples),
            "wallets" => Some(&self.wallets),
            _ => None,
        }
    }

    /// `examples.md` and `wallets.md` were single long files before they
    /// became directories. The old names still read, unlisted, as the list
    /// of files that replaced them, so a published skill or Petal README
    /// that names one does not hit "not found".
    fn moved(&self, name: &str) -> Option<String> {
        let dir = name.strip_suffix(".md")?;
        let files: Vec<String> = self
            .dir(dir)?
            .iter()
            .map(|(file, _)| format!("- {file}\n"))
            .collect();
        Some(format!(
            "# Moved\n\nThis is now one file per section in `docs/{dir}/`:\n\n{}",
            files.concat()
        ))
    }

    fn section(&self, dir: &str, file: &str) -> Option<&str> {
        let found = self.dir(dir)?.iter().find(|(name, _)| name == file)?;
        Some(&found.1)
    }

    async fn lookup_inner(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        match path.segments() {
            [] => Ok(Entry::dir("")),
            [s] if s == "README.md" => Ok(Entry::file("README.md")),
            [s] if s == "petals.md" => Ok(Entry::file("petals.md")),
            [s] if topic(s).is_some() || self.moved(s).is_some() => Ok(Entry::file(s)),
            [dir] if self.dir(dir).is_some() => Ok(Entry::dir(dir)),
            [dir, file] if self.section(dir, file).is_some() => Ok(Entry::file(file)),
            _ => Err(HandlerError::not_found(path.to_string_path())),
        }
    }

    async fn read_inner(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        match path.segments() {
            [s] if s == "README.md" => Ok(self.readme.as_bytes().to_vec()),
            [s] if s == "petals.md" => Ok((self.petals)()),
            [dir, file] if self.section(dir, file).is_some() => Ok(self
                .section(dir, file)
                .unwrap_or_default()
                .as_bytes()
                .to_vec()),
            [s] if topic(s).is_some() => Ok(topic(s).unwrap_or_default().as_bytes().to_vec()),
            [s] if self.moved(s).is_some() => Ok(self.moved(s).unwrap_or_default().into_bytes()),
            _ => Err(HandlerError::NotAFile(path.to_string_path())),
        }
    }

    async fn list_inner(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        if path.is_root() {
            let mut entries = vec![
                Entry::file("README.md"),
                Entry::dir("examples"),
                Entry::dir("wallets"),
                Entry::file("petals.md"),
            ];
            entries.extend(TOPICS.iter().map(|(name, _)| Entry::file(name)));
            Ok(entries)
        } else if let [dir] = path.segments()
            && let Some(sections) = self.dir(dir)
        {
            Ok(sections.iter().map(|(name, _)| Entry::file(name)).collect())
        } else {
            Err(HandlerError::NotADir(path.to_string_path()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::EntryKind;

    /// The body forms the guide and the outbox doc list are one list, and
    /// every form in it parses, so neither drifts from the parser.
    #[test]
    fn the_listed_send_tx_forms_match_and_parse() {
        let forms = |doc: &str| -> String {
            let (_, after) = doc
                .split_once("Write a body to `send.tx`")
                .expect("lists forms");
            let (_, block) = after.split_once("```text\n").expect("a text block");
            block.split_once("```").expect("closed").0.to_owned()
        };
        let guide = forms(include_str!("../docs/agent-guidance.md"));
        assert_eq!(guide, forms(include_str!("../docs/outbox-evm.md")));
        let to = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
        for line in guide.lines() {
            // A JSON form is followed by a note on its units.
            let body = match line.rfind('}') {
                Some(end) => &line[..=end],
                None => line,
            };
            bloom_tx::intent_parser::parse(&body.replace("0x...", to))
                .unwrap_or_else(|error| panic!("{line}: {error}"));
        }
    }

    #[tokio::test]
    async fn root_lists_embedded_and_dynamic_docs() {
        let h = DocsHandler::new();
        let entries = h.list(&VfsPath::root()).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names[..4],
            ["README.md", "examples", "wallets", "petals.md"]
        );
        assert_eq!(names.len(), 4 + TOPICS.len());
        for (name, text) in TOPICS {
            let path = VfsPath::parse(&format!("/{name}")).unwrap();
            assert_eq!(h.read(&path).await.unwrap(), text.as_bytes());
        }
        for e in &entries {
            if matches!(e.name.as_str(), "examples" | "wallets") {
                assert_eq!(e.kind, EntryKind::Dir);
                continue;
            }
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
        for name in ["README.md", "petals.md"] {
            let p = VfsPath::parse(&format!("/{name}")).unwrap();
            let e = h.lookup(&p).await.unwrap();
            assert_eq!(e.kind, EntryKind::File);
            assert_eq!(e.name, name);
        }
    }

    /// Every section of a long doc, read back through the handler.
    async fn whole(h: &DocsHandler, dir: &str) -> String {
        let root = VfsPath::parse(&format!("/{dir}")).unwrap();
        let mut text = String::new();
        for entry in h.list(&root).await.unwrap() {
            let path = VfsPath::parse(&format!("/{dir}/{}", entry.name)).unwrap();
            assert_eq!(h.lookup(&path).await.unwrap().kind, EntryKind::File);
            text += std::str::from_utf8(&h.read(&path).await.unwrap()).unwrap();
        }
        text
    }

    /// The long docs are directories of sections named after their headings.
    #[tokio::test]
    async fn long_docs_are_served_one_section_per_file() {
        let h = DocsHandler::new();
        let names = |dir: &'static str| {
            let h = h.clone();
            async move {
                let listed = h.list(&VfsPath::parse(dir).unwrap()).await.unwrap();
                listed.into_iter().map(|e| e.name).collect::<Vec<_>>()
            }
        };
        let examples = names("/examples").await;
        assert!(
            examples.contains(&"deploying-an-evm-contract.md".to_owned()),
            "{examples:?}"
        );
        assert!(
            examples.contains(&"updating-wallet-policy.md".to_owned()),
            "{examples:?}"
        );
        let wallets = names("/wallets").await;
        assert!(
            wallets.contains(&"creating-a-wallet.md".to_owned()),
            "{wallets:?}"
        );
        // Each example carries the setup its commands rely on.
        let deploy = VfsPath::parse("/examples/deploying-an-evm-contract.md").unwrap();
        let deploy = String::from_utf8(h.read(&deploy).await.unwrap()).unwrap();
        assert!(deploy.starts_with("# Deploying an EVM contract\n"));
        assert!(deploy.contains("BLOOM=\"<bloom-vfs-mount>\""));
        // The old single-file names still read, as the list of their parts.
        let moved = VfsPath::parse("/examples.md").unwrap();
        assert!(h.lookup(&moved).await.is_ok());
        let moved = String::from_utf8(h.read(&moved).await.unwrap()).unwrap();
        assert!(
            moved.contains("docs/examples/") && moved.contains("- deploying-an-evm-contract.md")
        );
        assert!(
            h.read(&VfsPath::parse("/wallets.md").unwrap())
                .await
                .is_ok()
        );
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
            s.contains("Bloom"),
            "README.md should mention bloom: {s:.80}..."
        );

        assert!(!whole(&h, "examples").await.is_empty());
    }

    #[tokio::test]
    async fn mounted_help_uses_canonical_sealed_approval_vocabulary() {
        let help = String::from_utf8(
            DocsHandler::new()
                .read(&VfsPath::parse("/README.md").unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(!help.contains(concat!("policy-", "session")), "{help}");
        // The policy-update rules are in AGENTS.md (tested in `router`); the
        // route reference only has to name the routes.
        assert!(help.contains("sealed-approvals"), "{help}");
        assert!(help.contains("policy.json"), "{help}");
        for stale in ["policy.toml", "host signer", "the grant", "a grant"] {
            assert!(
                !help.contains(stale),
                "mounted help retains stale Machine-authority vocabulary {stale:?}"
            );
        }
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
        for name in ["wallets", "examples"] {
            let s = whole(&h, name).await;
            let normalized = s.to_ascii_lowercase();
            assert!(
                s.contains("wallets/registrations/") && s.contains("status.json"),
                "{name} must document petname-keyed registration status"
            );
            assert!(
                normalized.contains("requested_name") && normalized.contains("petname"),
                "{name} must document the petname-keyed registration projection"
            );
            assert!(
                !(s.contains("plain name") && s.contains("creates a local wallet")),
                "{name} must not describe a plain /wallets/new write as creating a local wallet"
            );
        }
    }
}
