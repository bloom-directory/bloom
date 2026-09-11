//! `views/...` — read-only HTML pages meant for a person, not an agent.
//!
//! Paths handled:
//! - `views/`              — list the available pages
//! - `views/receive.html`  — receiving addresses grouped by wallet and family
//! - `views/bloom.css`     — the shared Bloom stylesheet (compiled in)
//! - `views/AGENTS.md`     — how an agent should use these pages
//!
//! These pages observe. Nothing here stages, approves, or executes an action,
//! and they carry no script: the mount serves them as ordinary files, so a
//! browser opens one straight off the filesystem. Matching Bloom's visual
//! language does not make a page a trusted authorization surface — passkeys
//! and private input stay in Broker's own page.
//!
//! A page always renders. An unavailable source becomes visible prose or an
//! "Unavailable" cell, never a fabricated zero and never an `EIO` that makes
//! `cat` of the whole page fail.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bloom_evm::ChainRegistry;
use bloom_machine_client::{ProjectionFreshness, WalletProjection, WalletProjectionReader};

use crate::handler::{Entry, Handler, HandlerError};
use crate::path::VfsPath;

const BLOOM_CSS: &str = include_str!("../assets/bloom.css");
const VIEWS_AGENTS_MD: &str = include_str!("../docs/views-agents.md");

const RECEIVE_HTML: &str = "receive.html";
const BLOOM_CSS_NAME: &str = "bloom.css";
const AGENTS_MD_NAME: &str = "AGENTS.md";

/// The mount re-reads on every browser access (`actimeo=0`), so a short
/// router TTL keeps a reload burst from re-reading projections per request.
/// The compiled-in assets need no cache entry at all.
const PAGE_TTL: Duration = Duration::from_secs(5);

/// Content-Security-Policy for every page. `style-src 'self'` is what lets a
/// page link the sibling `bloom.css` instead of inlining a copy that drifts;
/// `img-src 'self'` lets it show a QR code the VFS already renders. There is
/// deliberately no `script-src`: these pages must work with no script at all.
const CSP: &str = "default-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self'; \
                   base-uri 'none'; form-action 'none'";

#[derive(Clone)]
pub struct ViewsHandler {
    projections: Arc<dyn WalletProjectionReader>,
    chains: ChainRegistry,
}

impl ViewsHandler {
    pub fn new(projections: Arc<dyn WalletProjectionReader>, chains: ChainRegistry) -> Self {
        Self {
            projections,
            chains,
        }
    }
}

#[async_trait]
impl Handler for ViewsHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let r = self.lookup_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "views.lookup_err");
        }
        r
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let r = self.read_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "views.read_err");
        }
        r
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let r = self.list_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "views.list_err");
        }
        r
    }

    fn cache_ttl(&self, path: &VfsPath) -> Option<Duration> {
        match path.segments() {
            [s] if s == RECEIVE_HTML => Some(PAGE_TTL),
            _ => None,
        }
    }
}

impl ViewsHandler {
    async fn lookup_inner(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        match path.segments() {
            [] => Ok(Entry::dir("")),
            [s] if s == RECEIVE_HTML => Ok(Entry::file(RECEIVE_HTML)),
            [s] if s == BLOOM_CSS_NAME => Ok(css_entry()),
            [s] if s == AGENTS_MD_NAME => Ok(agents_entry()),
            _ => Err(HandlerError::not_found(path.to_string_path())),
        }
    }

    async fn read_inner(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        match path.segments() {
            [s] if s == RECEIVE_HTML => Ok(self.render_receive().await.into_bytes()),
            [s] if s == BLOOM_CSS_NAME => Ok(BLOOM_CSS.as_bytes().to_vec()),
            [s] if s == AGENTS_MD_NAME => Ok(VIEWS_AGENTS_MD.as_bytes().to_vec()),
            _ => Err(HandlerError::NotAFile(path.to_string_path())),
        }
    }

    async fn list_inner(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        if path.is_root() {
            // `ls -l` does not render children, so give the static assets a
            // real size hint here; pages are sized by the mount at getattr.
            Ok(vec![agents_entry(), css_entry(), Entry::file(RECEIVE_HTML)])
        } else {
            Err(HandlerError::NotADir(path.to_string_path()))
        }
    }

    /// Wallet projections, degrading the way `/next.md` does: live read first,
    /// then the cache, then an explicit "unavailable" flag. Enumerating
    /// wallets is navigation, not an authority decision, so it never errors.
    async fn wallet_projections(&self) -> (Vec<WalletProjection>, bool) {
        match self.projections.list_wallets().await {
            Ok(wallets) => (wallets, false),
            Err(error) => {
                tracing::debug!(error = %error, "views.projections_live_unavailable");
                match self.projections.cached_wallets() {
                    Ok(wallets) => (wallets, false),
                    Err(error) => {
                        tracing::debug!(error = %error, "views.projections_unavailable");
                        (Vec::new(), true)
                    }
                }
            }
        }
    }

    /// Human label for a configured chain: its own display name when the spec
    /// carries one, otherwise the path segment the VFS uses.
    fn network_label(&self, chain: &str) -> String {
        self.chains
            .get(chain)
            .and_then(|client| client.spec().display_name.clone())
            .unwrap_or_else(|| chain.to_owned())
    }

    async fn render_receive(&self) -> String {
        let (wallets, unavailable) = self.wallet_projections().await;

        let mut networks: Vec<String> = self.chains.list_names();
        networks.sort();
        let (mainnets, testnets): (Vec<String>, Vec<String>) = networks
            .into_iter()
            .partition(|name| !is_test_network(name));

        let mut body = String::new();

        if unavailable {
            body.push_str(
                "<section class=\"callout warn\"><strong>Receiving addresses unavailable</strong>\
                 <p>Broker is offline and no cached wallet projection is available, so no \
                 receiving address can be shown. Nothing about your wallets has changed.</p>\
                 </section>",
            );
        } else if wallets.is_empty() {
            body.push_str(
                "<section class=\"callout\"><strong>No wallets yet</strong>\
                 <p>Register a wallet first; a receiving address appears here once one \
                 exists.</p></section>",
            );
        }

        let mut stale = false;
        for wallet in &wallets {
            if wallet.freshness == ProjectionFreshness::Stale {
                stale = true;
            }
            body.push_str(&self.render_wallet_section(wallet, &mainnets, &testnets));
        }

        if stale {
            body.push_str(
                "<section class=\"callout warn\"><strong>Some projections are stale</strong>\
                 <p>At least one address below comes from cached data rather than a live \
                 Broker read. Confirm the address in Bloom before sharing it.</p></section>",
            );
        }

        page(
            "Receive",
            "Receive.",
            "Scan a wallet's address, or copy it. Select the matching network in the \
             sending wallet: the code encodes an address, not a network.",
            &body,
        )
    }

    fn render_wallet_section(
        &self,
        wallet: &WalletProjection,
        mainnets: &[String],
        testnets: &[String],
    ) -> String {
        let id = wallet.wallet_id().as_str();
        let (card, addresses) = match wallet.primary_address() {
            Ok(address) => (
                self.render_address_card(id, address, mainnets, testnets),
                1usize,
            ),
            Err(error) => {
                tracing::debug!(wallet = %id, error = %error, "views.address_unavailable");
                (
                    format!(
                        "<article class=\"card receiving-card\"><p class=\"eyebrow\">{} · \
                         receiving address</p><h3>Unavailable</h3><p>This wallet's projection \
                         carries no receiving address. Nothing can be received until it does.\
                         </p></article>",
                        html_escape(id)
                    ),
                    0usize,
                )
            }
        };
        // One EVM address per wallet today. The plural arm is what a wallet
        // with distinct Solana accounts will use, once `accounts.json` exists.
        let subtitle = match addresses {
            0 => "No receiving address".to_owned(),
            1 => "1 receiving address".to_owned(),
            n => format!("{n} receiving addresses"),
        };
        format!(
            "<section class=\"receiving-wallet\" aria-label=\"{id_attr} receiving addresses\">\
             <div class=\"section-head\"><h2>{id_text}</h2><p>{subtitle}</p></div>\
             <div class=\"grid\">{card}</div></section>",
            id_attr = html_escape(id),
            id_text = html_escape(id),
            subtitle = html_escape(&subtitle),
            card = card,
        )
    }

    fn render_address_card(
        &self,
        wallet: &str,
        address: &str,
        mainnets: &[String],
        testnets: &[String],
    ) -> String {
        let mut chips = String::new();
        for name in mainnets {
            chips.push_str(&format!(
                "<li><span class=\"asset-label\"><span>{}</span></span></li>",
                html_escape(&self.network_label(name))
            ));
        }
        let networks = if chips.is_empty() {
            "<p class=\"receiving-network\">No networks are configured for this address \
             yet.</p>"
                .to_owned()
        } else {
            format!(
                "<ul class=\"receiving-networks\">{chips}</ul>\
                 <p class=\"receiving-network\">One address across these networks. Funds stay \
                 on the network the sender chooses.</p>"
            )
        };

        let testing = if testnets.is_empty() {
            String::new()
        } else {
            let items: String = testnets
                .iter()
                .map(|name| format!("<li>{}</li>", html_escape(name)))
                .collect();
            format!(
                "<details><summary>Test networks · {count}</summary><p>The same address is \
                 also configured on these test networks. Test funds are not main-network \
                 funds.</p><ul class=\"receiving-networks\">{items}</ul></details>",
                count = testnets.len(),
            )
        };

        // The QR image is the leaf the wallets handler already renders, reached
        // by relative path on the mount. `img-src 'self'` permits it, and there
        // is no second QR encoder to keep in step with the first.
        format!(
            "<article class=\"card receiving-card\"><p class=\"eyebrow\">{wallet} · receiving \
             address</p><h3>Ethereum &amp; EVM</h3><figure class=\"receiving-qr\"><div>\
             <img src=\"../wallets/{wallet_path}/address.qr.svg\" width=\"222\" height=\"222\" \
             alt=\"{wallet} receiving address as a QR code\"></div>\
             <figcaption>Scan this address</figcaption></figure>\
             <code class=\"address\">{address}</code><div class=\"receiving-network-list\">\
             <p class=\"label\">Networks for this address</p>{networks}{testing}</div></article>",
            wallet = html_escape(wallet),
            wallet_path = html_escape(wallet),
            address = html_escape(address),
            networks = networks,
            testing = testing,
        )
    }
}

fn css_entry() -> Entry {
    Entry::file(BLOOM_CSS_NAME).with_size(BLOOM_CSS.len() as u64)
}

fn agents_entry() -> Entry {
    Entry::file(AGENTS_MD_NAME).with_size(VIEWS_AGENTS_MD.len() as u64)
}

/// A test network is named as one. No chain spec carries a testnet flag, so
/// the name is the only signal available — the same rule the design prototype
/// used. Being wrong in the safe direction means a main network is disclosed
/// as a test one, never the reverse.
fn is_test_network(chain: &str) -> bool {
    let name = chain.to_ascii_lowercase();
    name.contains("devnet") || name.contains("testnet")
}

/// Escape text for HTML body and attribute contexts. `&` first, so an escape
/// is never double-escaped.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// The shared page shell: one stylesheet link, no script, and a masthead that
/// says plainly that this is an observation.
fn page(title: &str, heading: &str, lede: &str, body: &str) -> String {
    format!(
        "<!doctype html>\n\
         <html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <meta name=\"referrer\" content=\"no-referrer\">\
         <meta http-equiv=\"Content-Security-Policy\" content=\"{csp}\">\
         <title>{title} · Bloom</title>\
         <link rel=\"stylesheet\" href=\"bloom.css\"></head>\
         <body class=\"personal-dashboard\">\
         <a class=\"skip\" href=\"#main\">Skip to content</a>\
         <div class=\"demo snapshot-banner\"><strong>YOUR WALLET</strong>\
         <span>Read-only view · no automatic refresh</span>\
         <span>This page observes; it never approves or executes an action.</span></div>\
         <div class=\"shell\"><header class=\"masthead\">\
         <a class=\"brand\" href=\"receive.html\"><strong>/bloom</strong></a>\
         <span class=\"edition\">Personal wallet views</span></header>\
         <main id=\"main\"><div class=\"intro\"><div>\
         <p class=\"eyebrow\">Your place in the ecosystem</p><h1>{heading}</h1></div>\
         <p class=\"lede\">{lede}</p></div>{body}</main>\
         <footer><span>Read-only projection</span>\
         <span><a href=\"AGENTS.md\">How to use these pages</a></span></footer>\
         </div></body></html>\n",
        csp = CSP,
        title = html_escape(title),
        heading = html_escape(heading),
        lede = html_escape(lede),
        body = body,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::EntryKind;

    const ADDRESS: &str = "0x000000000000000000000000000000000000dEaD";

    /// Write the rendered page to `$VIEWS_DUMP` for visual review. Ignored: a
    /// development aid for looking at the page, not an assertion.
    #[tokio::test]
    #[ignore]
    async fn dump_receive_page() {
        let Ok(out) = std::env::var("VIEWS_DUMP") else {
            return;
        };
        let chains = ChainRegistry::new();
        for (name, chain_id, display) in [
            ("arbitrum", 42161u64, "Arbitrum One"),
            ("base", 8453, "Base"),
            ("ethereum", 1, "Ethereum"),
            ("robinhood", 4663, "Robinhood Chain"),
            ("sepolia-testnet", 11155111, "Sepolia"),
        ] {
            let spec = bloom_proto::ChainSpec {
                name: name.into(),
                chain_id,
                rpc_urls: vec!["http://127.0.0.1:1".into()],
                rpc_endpoints: Vec::new(),
                allow_broadcast: false,
                etherscan_api_url: None,
                display_name: Some(display.to_owned()),
                native_symbol: "ETH".into(),
                native_decimals: 18,
                legacy_tx: false,
                op_stack: false,
            };
            chains.add(bloom_evm::ChainClient::new(spec).unwrap());
        }
        let h = ViewsHandler::new(
            crate::test_support::wallet_projection_reader("everyday", ADDRESS),
            chains,
        );
        let html = receive_page(&h).await;
        std::fs::write(&out, html).unwrap();
    }

    fn handler() -> ViewsHandler {
        ViewsHandler::new(
            crate::test_support::wallet_projection_reader("alice", ADDRESS),
            ChainRegistry::default(),
        )
    }

    async fn receive_page(h: &ViewsHandler) -> String {
        String::from_utf8(
            h.read(&VfsPath::parse(RECEIVE_HTML).unwrap())
                .await
                .unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn root_lists_pages_and_assets() {
        let entries = handler().list(&VfsPath::root()).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, [AGENTS_MD_NAME, BLOOM_CSS_NAME, RECEIVE_HTML]);
        for e in &entries {
            assert_eq!(e.kind, EntryKind::File);
            assert_eq!(e.mode, 0o444, "views pages must be read-only");
        }
    }

    #[tokio::test]
    async fn static_assets_report_a_real_size_for_ls() {
        // READDIRPLUS does not render children, so `ls -l` shows this hint.
        let entries = handler().list(&VfsPath::root()).await.unwrap();
        let css = entries
            .iter()
            .find(|e| e.name == BLOOM_CSS_NAME)
            .expect("bloom.css listed");
        assert_eq!(css.size, BLOOM_CSS.len() as u64);
        assert!(css.size > 0, "an empty stylesheet would render unstyled");
    }

    #[tokio::test]
    async fn stylesheet_is_served_and_reaches_for_nothing_external() {
        let css = String::from_utf8(
            handler()
                .read(&VfsPath::parse(BLOOM_CSS_NAME).unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(css.contains(":root"), "stylesheet must define its tokens");
        // `default-src 'none'` blocks every fetch, silently. A stylesheet that
        // reaches for a font or an image would simply render wrong.
        for forbidden in ["url(", "@import", "@font-face", "http"] {
            assert!(
                !css.contains(forbidden),
                "stylesheet must not reference {forbidden:?}"
            );
        }
    }

    #[tokio::test]
    async fn receive_page_shows_the_address_and_links_the_rendered_qr() {
        let html = receive_page(&handler()).await;
        assert!(html.starts_with("<!doctype html>"), "{html:.40}");
        assert!(
            html.contains(ADDRESS),
            "the address itself must be readable"
        );
        assert!(
            html.contains("<img src=\"../wallets/alice/address.qr.svg\""),
            "the QR must reuse the wallets leaf, not a second encoder"
        );
        assert!(html.contains("<link rel=\"stylesheet\" href=\"bloom.css\">"));
        assert!(html.contains("alice"));
        assert!(
            html.contains("1 receiving address"),
            "the section head counts addresses rather than repeating the family name"
        );
    }

    #[tokio::test]
    async fn receive_page_carries_no_script_and_declares_its_policy() {
        let html = receive_page(&handler()).await;
        assert!(html.contains("Content-Security-Policy"));
        assert!(
            html.contains("style-src 'self'"),
            "an external stylesheet needs 'self' in style-src"
        );
        assert!(
            !html.contains("script-src"),
            "these pages must not permit script at all"
        );
        assert!(!html.contains("<script"), "no script may be emitted");
    }

    #[tokio::test]
    async fn receive_page_says_so_when_no_network_is_configured() {
        let html = receive_page(&handler()).await;
        assert!(
            html.contains("No networks are configured"),
            "an empty registry must be stated, not implied"
        );
        assert!(
            !html.contains("Test networks ·"),
            "no test-network disclosure without a test network"
        );
    }

    #[tokio::test]
    async fn unknown_page_is_not_found_and_a_page_is_not_a_dir() {
        let h = handler();
        let missing = VfsPath::parse("markets.html").unwrap();
        assert!(matches!(
            h.lookup(&missing).await,
            Err(HandlerError::NotFound(_))
        ));
        assert!(matches!(
            h.read(&missing).await,
            Err(HandlerError::NotAFile(_))
        ));
        assert!(matches!(
            h.list(&VfsPath::parse(RECEIVE_HTML).unwrap()).await,
            Err(HandlerError::NotADir(_))
        ));
    }

    #[tokio::test]
    async fn lookup_root_is_a_dir_that_lists() {
        let h = handler();
        let root = h.lookup(&VfsPath::root()).await.unwrap();
        assert_eq!(root.kind, EntryKind::Dir);
        // If lookup calls it a directory, list must agree or mounts emit
        // ENOTDIR for every `find` over the tree.
        assert!(h.list(&VfsPath::root()).await.is_ok());
    }

    #[tokio::test]
    async fn pages_are_cached_briefly_and_assets_are_not() {
        let h = handler();
        assert_eq!(
            h.cache_ttl(&VfsPath::parse(RECEIVE_HTML).unwrap()),
            Some(PAGE_TTL)
        );
        assert_eq!(h.cache_ttl(&VfsPath::parse(BLOOM_CSS_NAME).unwrap()), None);
        assert_eq!(h.cache_ttl(&VfsPath::root()), None);
    }

    #[tokio::test]
    async fn agents_doc_is_served_beside_the_pages() {
        let doc = String::from_utf8(
            handler()
                .read(&VfsPath::parse(AGENTS_MD_NAME).unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(doc.contains("receive.html"));
        assert!(
            doc.contains("never"),
            "the doc must state what these pages do not do"
        );
    }

    #[test]
    fn test_networks_are_recognised_by_name() {
        for name in ["solana-devnet", "sepolia-testnet", "Base-Devnet"] {
            assert!(is_test_network(name), "{name} is a test network");
        }
        for name in ["ethereum", "base", "arbitrum", "solana-mainnet"] {
            assert!(!is_test_network(name), "{name} is a main network");
        }
    }

    #[test]
    fn escaping_neutralises_markup_and_never_double_escapes() {
        assert_eq!(
            html_escape("<script src='x'>\"&"),
            "&lt;script src=&#39;x&#39;&gt;&quot;&amp;"
        );
        // `&` is replaced first, so an escape is not re-escaped.
        assert_eq!(html_escape("a&b"), "a&amp;b");
    }
}
