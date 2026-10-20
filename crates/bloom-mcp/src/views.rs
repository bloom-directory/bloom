//! MCP Apps adapters for the canonical read-only dashboard under `/views`.
//!
//! The daemon remains the only renderer. These tools read its finished HTML
//! and local presentation assets through the inert VFS command, then place
//! them in tool-result metadata that only the sandboxed App receives. Clients
//! without MCP Apps support get the same tools without UI metadata and a
//! useful browser-path fallback in ordinary tool content.

use std::sync::LazyLock;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};

use crate::backend::{VfsCommandError, VfsCommands, VfsMethod};
use crate::tools::{ToolError, error_result, read_bytes};

/// Claude serves its host font from here; nothing else may load.
const CLAUDE_FONT_ORIGIN: &str = "https://assets.claude.ai";
pub const APP_MIME_TYPE: &str = "text/html;profile=mcp-app";
const APP_TEMPLATE: &str = include_str!("../assets/dashboard-widget.html");
const SKIN_CSS_PATH: &str = "/views/skin.css";

#[derive(Clone, Copy, Debug)]
pub struct ViewToolSpec {
    pub name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub page: &'static str,
}

pub const VIEW_TOOLS: [ViewToolSpec; 8] = [
    ViewToolSpec {
        name: "show_bloom_wallets",
        title: "Show Bloom wallets",
        description: "Use this tool whenever the person asks to see Bloom wallets or balances. It opens the read-only Wallets widget directly in MCP Apps hosts; do not reconstruct the view with VFS reads. Other hosts are pointed to a text summary.",
        page: "wallets.html",
    },
    ViewToolSpec {
        name: "show_bloom_receive",
        title: "Show Bloom receive addresses",
        description: "Use this tool whenever the person asks for Bloom receiving addresses or QR codes. It opens the read-only Receive widget directly in MCP Apps hosts; do not reconstruct the view with VFS reads. Other hosts are pointed to a text summary.",
        page: "receive.html",
    },
    ViewToolSpec {
        name: "show_bloom_activity",
        title: "Show Bloom activity",
        description: "Use this tool whenever the person asks for Bloom activity or wallet history. It opens the read-only Activity widget directly in MCP Apps hosts; do not reconstruct the view with VFS reads. Other hosts are pointed to a text summary.",
        page: "activity.html",
    },
    ViewToolSpec {
        name: "show_bloom_next_moves",
        title: "Show Bloom next moves",
        description: "Use this tool whenever the person asks what Bloom operations need attention. It opens the read-only Next moves widget directly in MCP Apps hosts; do not reconstruct the view with VFS reads. Other hosts are pointed to a text summary.",
        page: "next-moves.html",
    },
    ViewToolSpec {
        name: "show_bloom_contacts",
        title: "Show Bloom contacts",
        description: "Use this tool whenever the person asks for Bloom contacts or recipient suggestions. It opens the read-only Contacts widget directly in MCP Apps hosts; do not reconstruct the view with VFS reads. Other hosts are pointed to a text summary.",
        page: "contacts.html",
    },
    ViewToolSpec {
        name: "show_bloom_policy",
        title: "Show Bloom policy",
        description: "Use this tool whenever the person asks about Bloom wallet policy or approval scope. It opens the read-only Policy widget directly in MCP Apps hosts; do not reconstruct the view with VFS reads. Other hosts are pointed to a text summary.",
        page: "policy.html",
    },
    ViewToolSpec {
        name: "show_bloom_networks",
        title: "Show Bloom networks",
        description: "Use this tool whenever the person asks for Bloom networks or fees. It opens the read-only Networks widget directly in MCP Apps hosts; do not reconstruct the view with VFS reads. Other hosts are pointed to a text summary.",
        page: "chains.html",
    },
    ViewToolSpec {
        name: "show_bloom_markets",
        title: "Show Bloom markets",
        description: "Use this tool whenever the person asks for Bloom markets or market movers. It opens the read-only Markets widget directly in MCP Apps hosts; do not reconstruct the view with VFS reads. Other hosts are pointed to a text summary.",
        page: "markets.html",
    },
];

pub fn find(name: &str) -> Option<&'static ViewToolSpec> {
    VIEW_TOOLS.iter().find(|tool| tool.name == name)
}

impl ViewToolSpec {
    pub fn resource_uri(&self) -> String {
        format!("ui://bloom/{}-v9.html", self.page.trim_end_matches(".html"))
    }

    pub fn descriptor(&self) -> Value {
        let resource_uri = self.resource_uri();
        json!({
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false,
            },
            "outputSchema": {
                "type": "object",
                "properties": {
                    "view": { "type": "string" },
                    "title": { "type": "string" },
                    "path": { "type": "string" },
                    "note": { "type": "string" },
                },
                "required": ["view", "title", "path"],
                "additionalProperties": false,
            },
            "annotations": {
                "title": self.title,
                "readOnlyHint": true,
                "destructiveHint": false,
                "idempotentHint": true,
                "openWorldHint": true,
            },
            "_meta": {
                "ui": {
                    "resourceUri": resource_uri,
                    "visibility": ["model", "app"],
                },
                "openai/outputTemplate": resource_uri,
                "openai/widgetAccessible": true,
            },
        })
    }
}

pub fn find_by_resource_uri(uri: &str) -> Option<&'static ViewToolSpec> {
    VIEW_TOOLS.iter().find(|tool| tool.resource_uri() == uri)
}

/// `apps_declared` is whether the client announced the MCP Apps extension at
/// initialize. ChatGPT renders widgets without announcing it, so the text
/// route for other clients stays conditional. It is also placed in
/// `structuredContent`, because Claude Code shows the model only that.
pub async fn call(
    commands: &dyn VfsCommands,
    tool: &ViewToolSpec,
    arguments: &Value,
    apps_declared: bool,
) -> Result<Value, ToolError> {
    validate_arguments(arguments)?;
    let page_path = format!("/views/{}", tool.page);
    let html = match read_utf8(commands, &page_path).await {
        Ok(html) => html,
        Err(error) => return Ok(error_result(&error)),
    };
    let skin_css = match read_utf8(commands, SKIN_CSS_PATH).await {
        Ok(css) => css,
        Err(error) => return Ok(error_result(&error)),
    };
    let browser_path = format!("views/{}", tool.page);
    let view = tool.title.trim_start_matches("Show ");
    let note = if apps_declared {
        format!("The read-only {view} widget is shown to the person.")
    } else {
        format!(
            "This client did not declare MCP Apps support, so the {view} widget may not display. \
             Open `{browser_path}` in a browser. The text below is this page, not the Today briefing.\n\n\
             {}",
            page_text(&html)
        )
    };

    Ok(json!({
        "content": [{ "type": "text", "text": note }],
        "structuredContent": {
            "view": tool.page.trim_end_matches(".html"),
            "title": tool.title,
            "path": browser_path,
            "note": note,
        },
        "isError": false,
        "_meta": {
            "bloom/view": {
                "html": html,
                "skinCss": skin_css,
            },
        },
    }))
}

const PAGE_TEXT_LIMIT: usize = 16_000;

/// Words of a rendered page, for a host that cannot show the widget.
/// Scripts, styles, and QR artwork are dropped. The canonical HTML stays
/// the only renderer; this is that page's text, not a second view.
fn page_text(html: &str) -> String {
    let mut text = String::new();
    let mut rest = html;
    while !rest.is_empty() {
        let Some(start) = rest.find('<') else {
            text.push_str(rest);
            break;
        };
        text.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        if after.is_empty() {
            text.push('<');
            break;
        }
        if let Some(name) = ignored_block(after) {
            if let Some(next) = skip_block(after, name) {
                rest = next;
                continue;
            }
        }
        let end = after
            .find('>')
            .map(|index| index + 1)
            .unwrap_or(after.len());
        let tag = &after[..end.saturating_sub(1)];
        let name = tag
            .trim_start_matches('/')
            .split_whitespace()
            .next()
            .unwrap_or("");
        if name.eq_ignore_ascii_case("br") || (tag.starts_with('/') && is_block_end(name)) {
            text.push('\n');
        }
        rest = &after[end..];
    }
    let text = decode_entities(&text);
    let mut lines = Vec::new();
    for line in text.split('\n') {
        let line = line.split_whitespace().collect::<Vec<_>>().join(" ");
        if !line.is_empty() {
            lines.push(line);
        }
    }
    let mut joined = lines.join("\n");
    if joined.len() > PAGE_TEXT_LIMIT {
        let mut end = PAGE_TEXT_LIMIT;
        while end > 0 && !joined.is_char_boundary(end) {
            end -= 1;
        }
        if let Some(boundary) = joined[..end]
            .rfind('\n')
            .or_else(|| joined[..end].rfind(' '))
        {
            end = boundary;
        }
        joined.truncate(end);
        joined.push_str("\n\n[Page text truncated. Open the browser path for the rest.]");
    }
    joined
}

fn ignored_block(after: &str) -> Option<&'static str> {
    for name in ["script", "style", "svg", "noscript"] {
        if after.len() >= name.len()
            && after[..name.len()].eq_ignore_ascii_case(name)
            && after[name.len()..]
                .chars()
                .next()
                .is_none_or(|c| !c.is_ascii_alphanumeric())
        {
            return Some(name);
        }
    }
    None
}

fn skip_block<'a>(after: &'a str, name: &str) -> Option<&'a str> {
    let close = format!("</{name}");
    let end = after.to_ascii_lowercase().find(&close)?;
    let rest = &after[end + close.len()..];
    let gt = rest.find('>')?;
    Some(&rest[gt + 1..])
}

fn is_block_end(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "p" | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "li"
            | "tr"
            | "section"
            | "article"
            | "div"
            | "summary"
            | "dt"
            | "dd"
            | "caption"
            | "header"
            | "footer"
    )
}

fn decode_entities(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
}

fn validate_arguments(arguments: &Value) -> Result<(), ToolError> {
    match arguments {
        Value::Null => Ok(()),
        Value::Object(arguments) if arguments.is_empty() => Ok(()),
        Value::Object(arguments) => Err(ToolError::InvalidArguments(format!(
            "unexpected argument `{}`",
            arguments.keys().next().unwrap()
        ))),
        _ => Err(ToolError::InvalidArguments(
            "`arguments` must be an object".into(),
        )),
    }
}

async fn read_utf8(commands: &dyn VfsCommands, path: &str) -> Result<String, VfsCommandError> {
    let reply = commands
        .call(VfsMethod::ReadInert, json!({ "path": path }))
        .await?;
    let bytes = read_bytes(&reply)?;
    String::from_utf8(bytes).map_err(|error| {
        VfsCommandError::new(
            crate::backend::DAEMON_UNREACHABLE_CODE,
            format!("Bloom view {path} is not valid UTF-8: {error}"),
        )
    })
}

/// The App document with the stylesheet and icons every view shares built
/// in, so each tool result carries only its page. Hosts fetch the resource
/// once; Claude stops delivering results inline beyond about 150k characters.
static APP_HTML: LazyLock<String> = LazyLock::new(|| {
    let icons = bloom_vfs::handlers::views::bundled_icons()
        .map(|(path, bytes)| {
            let uri = format!(
                "data:{};base64,{}",
                asset_mime_type(bytes),
                B64.encode(bytes)
            );
            (path, Value::String(uri))
        })
        .collect::<serde_json::Map<_, _>>();
    APP_TEMPLATE
        .replace("/*BLOOM_CSS*/", bloom_vfs::handlers::views::bundled_css())
        .replace("/*BLOOM_ICONS*/", &Value::Object(icons).to_string())
});

/// Several bundled icons carry another format's extension, so trust the bytes.
fn asset_mime_type(bytes: &[u8]) -> &'static str {
    match bytes {
        [0x89, b'P', b'N', b'G', ..] => "image/png",
        [0xff, 0xd8, ..] => "image/jpeg",
        [
            b'R',
            b'I',
            b'F',
            b'F',
            _,
            _,
            _,
            _,
            b'W',
            b'E',
            b'B',
            b'P',
            ..,
        ] => "image/webp",
        _ => "application/octet-stream",
    }
}

pub fn app_resource(tool: &ViewToolSpec) -> Value {
    let resource_uri = tool.resource_uri();
    json!({
        "uri": resource_uri,
        "mimeType": APP_MIME_TYPE,
        "text": APP_HTML.as_str(),
        "_meta": {
            "ui": {
                "prefersBorder": false,
                "csp": {
                    "connectDomains": [],
                    "resourceDomains": [CLAUDE_FONT_ORIGIN],
                    "frameDomains": [],
                },
            },
            "openai/ui": {
                "availableDisplayModes": ["inline", "fullscreen"],
            },
            "openai/widgetDescription": format!("Bloom's read-only {} view.", tool.title),
            "openai/widgetPrefersBorder": true,
        },
    })
}

pub fn app_resource_descriptor(tool: &ViewToolSpec) -> Value {
    json!({
        "uri": tool.resource_uri(),
        "name": format!("bloom-{}-app", tool.page.trim_end_matches(".html")),
        "title": tool.title,
        "description": format!("Sandboxed renderer for Bloom's read-only {} view.", tool.title),
        "mimeType": APP_MIME_TYPE,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn app_document_embeds_shared_assets() {
        assert!(!APP_HTML.contains("/*BLOOM_CSS*/"));
        assert!(APP_HTML.contains(bloom_vfs::handlers::views::bundled_css()));
        let icons = APP_HTML
            .split("<script type=\"application/json\" id=\"bloom-icons\">")
            .nth(1)
            .and_then(|rest| rest.split("</script>").next())
            .unwrap();
        let icons: serde_json::Map<String, Value> = serde_json::from_str(icons).unwrap();
        assert_eq!(
            icons.len(),
            bloom_vfs::handlers::views::bundled_icons().count()
        );
        assert!(
            icons
                .values()
                .all(|uri| uri.as_str().unwrap().starts_with("data:image/"))
        );
    }

    #[test]
    fn widget_tools_advertise_standard_and_chatgpt_ui_metadata() {
        let app = VIEW_TOOLS[0].descriptor();
        assert_eq!(
            app["_meta"]["ui"]["resourceUri"],
            VIEW_TOOLS[0].resource_uri()
        );
        assert_eq!(
            app["_meta"]["openai/outputTemplate"],
            VIEW_TOOLS[0].resource_uri()
        );
        assert_eq!(app["_meta"]["openai/widgetAccessible"], true);
        assert_eq!(app["annotations"]["readOnlyHint"], true);
    }

    #[test]
    fn page_text_keeps_the_words_and_drops_artwork() {
        let html = "<main><h1>Receive</h1><svg><text>drop</text></svg>\
                    <p>Address 0xabc &amp; more</p><script>alert(1)</script></main>";
        let text = page_text(html);
        assert!(text.contains("Receive"), "{text}");
        assert!(text.contains("Address 0xabc & more"), "{text}");
        assert!(!text.contains("drop"), "{text}");
        assert!(!text.contains("alert"), "{text}");
        assert!(!text.contains('<'), "{text}");
    }

    #[test]
    fn receive_widget_keeps_unavailable_address_evidence() {
        assert!(APP_TEMPLATE.contains("receiving-unavailable"));
        assert!(
            !APP_TEMPLATE.contains("receiving-unavailable\").forEach((card) => card.remove())")
        );
        assert!(APP_TEMPLATE.contains("classList.contains(\"receiving-unavailable\")"));
    }

    #[test]
    fn every_view_has_its_own_resource() {
        let uris = VIEW_TOOLS
            .iter()
            .map(ViewToolSpec::resource_uri)
            .collect::<BTreeSet<_>>();
        assert_eq!(uris.len(), VIEW_TOOLS.len());
        assert!(!uris.iter().any(|uri| uri.contains("index")));
    }
}
