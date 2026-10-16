//! MCP Apps adapters for the canonical read-only dashboard under `/views`.
//!
//! The daemon remains the only renderer. These tools read its finished HTML
//! and local presentation assets through the inert VFS command, then place
//! them in tool-result metadata that only the sandboxed App receives. Clients
//! without MCP Apps support get the same tools without UI metadata and a
//! useful browser-path fallback in ordinary tool content.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};

use crate::backend::{VfsCommandError, VfsCommands, VfsMethod};
use crate::tools::{ToolError, error_result, read_bytes};

pub const APP_MIME_TYPE: &str = "text/html;profile=mcp-app";
pub const APP_RESOURCE_URI: &str = "ui://bloom/dashboard-v1.html";
pub const APP_EXTENSION_ID: &str = "io.modelcontextprotocol/ui";

const APP_HTML: &str = include_str!("../assets/dashboard-widget.html");
const BASE_CSS_PATH: &str = "/views/bloom.css";
const SKIN_CSS_PATH: &str = "/views/skin.css";

#[derive(Clone, Copy, Debug)]
pub struct ViewToolSpec {
    pub name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub page: &'static str,
}

pub const VIEW_TOOLS: [ViewToolSpec; 9] = [
    ViewToolSpec {
        name: "show_bloom_today",
        title: "Show Bloom Today",
        description: "Show the person's Bloom Today dashboard: holdings, items needing attention, app positions, and recent activity. Prefer this tool when the person asks to see their Bloom overview; MCP Apps hosts render it inline and other hosts receive a browser fallback.",
        page: "index.html",
    },
    ViewToolSpec {
        name: "show_bloom_wallets",
        title: "Show Bloom wallets",
        description: "Show the person's read-only Bloom wallet dashboard. Prefer this tool when the person asks to see wallets or balances; MCP Apps hosts render it inline and other hosts receive a browser fallback.",
        page: "wallets.html",
    },
    ViewToolSpec {
        name: "show_bloom_receive",
        title: "Show Bloom receive addresses",
        description: "Show the person's receiving addresses and QR codes grouped by wallet. Prefer this tool when the person asks where to receive funds; MCP Apps hosts render it inline and other hosts receive a browser fallback.",
        page: "receive.html",
    },
    ViewToolSpec {
        name: "show_bloom_activity",
        title: "Show Bloom activity",
        description: "Show the person's recorded Bloom activity and transaction links. Prefer this tool when the person asks to see wallet history; MCP Apps hosts render it inline and other hosts receive a browser fallback.",
        page: "activity.html",
    },
    ViewToolSpec {
        name: "show_bloom_next_moves",
        title: "Show Bloom next moves",
        description: "Show staged Bloom operations awaiting review and their policy status. Prefer this tool when the person asks what needs attention; MCP Apps hosts render it inline and other hosts receive a browser fallback.",
        page: "next-moves.html",
    },
    ViewToolSpec {
        name: "show_bloom_contacts",
        title: "Show Bloom contacts",
        description: "Show the person's saved Bloom contacts and recipient suggestions. Prefer this tool when the person asks to see contacts; MCP Apps hosts render it inline and other hosts receive a browser fallback.",
        page: "contacts.html",
    },
    ViewToolSpec {
        name: "show_bloom_policy",
        title: "Show Bloom policy",
        description: "Show the person's read-only Bloom wallet policy summary. Prefer this tool when the person asks to inspect policy or approval scope; MCP Apps hosts render it inline and other hosts receive a browser fallback.",
        page: "policy.html",
    },
    ViewToolSpec {
        name: "show_bloom_networks",
        title: "Show Bloom networks",
        description: "Show Bloom's sortable Networks dashboard with public market activity, fees, and the person's holdings by network. Prefer this tool for network or fee views; MCP Apps hosts render it inline and other hosts receive a browser fallback.",
        page: "chains.html",
    },
    ViewToolSpec {
        name: "show_bloom_markets",
        title: "Show Bloom markets",
        description: "Show Bloom's public market-movers dashboard and its sample coverage. Prefer this tool when the person asks to see markets; MCP Apps hosts render it inline and other hosts receive a browser fallback.",
        page: "markets.html",
    },
];

pub fn find(name: &str) -> Option<&'static ViewToolSpec> {
    VIEW_TOOLS.iter().find(|tool| tool.name == name)
}

pub fn client_supports_app(params: &Value) -> bool {
    params["capabilities"]["extensions"][APP_EXTENSION_ID]["mimeTypes"]
        .as_array()
        .is_some_and(|types| types.iter().any(|kind| kind == APP_MIME_TYPE))
}

impl ViewToolSpec {
    pub fn descriptor(&self, app_enabled: bool) -> Value {
        let mut descriptor = json!({
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
        });
        if app_enabled {
            descriptor["_meta"] = json!({
                "ui": {
                    "resourceUri": APP_RESOURCE_URI,
                    "visibility": ["model", "app"],
                },
            });
        }
        descriptor
    }
}

pub async fn call(
    commands: &dyn VfsCommands,
    tool: &ViewToolSpec,
    arguments: &Value,
) -> Result<Value, ToolError> {
    validate_arguments(arguments)?;
    let page_path = format!("/views/{}", tool.page);
    let html = match read_utf8(commands, &page_path).await {
        Ok(html) => html,
        Err(error) => return Ok(error_result(&error)),
    };
    let css = match read_utf8(commands, BASE_CSS_PATH).await {
        Ok(css) => css,
        Err(error) => return Ok(error_result(&error)),
    };
    let skin_css = match read_utf8(commands, SKIN_CSS_PATH).await {
        Ok(css) => css,
        Err(error) => return Ok(error_result(&error)),
    };
    let assets = collect_assets(commands, &html).await;
    let browser_path = format!("views/{}", tool.page);

    Ok(json!({
        "content": [{
            "type": "text",
            "text": format!(
                "{} is ready. If this client cannot display MCP Apps, open `{browser_path}` from the Bloom mount in a browser.",
                tool.title
            ),
        }],
        "structuredContent": {
            "view": tool.page.trim_end_matches(".html"),
            "title": tool.title,
            "path": browser_path,
        },
        "isError": false,
        "_meta": {
            "bloom/view": {
                "html": html,
                "css": css,
                "skinCss": skin_css,
                "assets": assets,
            },
        },
    }))
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

async fn collect_assets(commands: &dyn VfsCommands, html: &str) -> Value {
    let mut assets = BTreeMap::new();
    for source in local_sources(html) {
        let path = format!("/views/{source}");
        let Ok(reply) = commands
            .call(VfsMethod::ReadInert, json!({ "path": path }))
            .await
        else {
            continue;
        };
        let Ok(bytes) = read_bytes(&reply) else {
            continue;
        };
        assets.insert(
            source.clone(),
            format!(
                "data:{};base64,{}",
                asset_mime_type(&source),
                B64.encode(bytes)
            ),
        );
    }
    json!(assets)
}

fn local_sources(html: &str) -> BTreeSet<String> {
    let mut sources = BTreeSet::new();
    for part in html.split("src=\"").skip(1) {
        let Some(source) = part.split('"').next() else {
            continue;
        };
        if !source.is_empty()
            && !source.starts_with(['/', '#'])
            && !source.contains(':')
            && source != "bloom.js"
            && !source.split('/').any(|segment| segment == "..")
        {
            sources.insert(source.to_owned());
        }
    }
    sources
}

fn asset_mime_type(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("webp") => "image/webp",
        _ => "application/octet-stream",
    }
}

pub fn app_resource() -> Value {
    json!({
        "uri": APP_RESOURCE_URI,
        "mimeType": APP_MIME_TYPE,
        "text": APP_HTML,
        "_meta": {
            "ui": {
                "prefersBorder": true,
                "csp": {
                    "connectDomains": [],
                    "resourceDomains": [],
                    "frameDomains": [],
                },
            },
        },
    })
}

pub fn app_resource_descriptor() -> Value {
    json!({
        "uri": APP_RESOURCE_URI,
        "name": "bloom-dashboard-app",
        "title": "Bloom dashboard",
        "description": "Sandboxed renderer for Bloom's read-only dashboard views.",
        "mimeType": APP_MIME_TYPE,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_support_requires_the_registered_mime_type() {
        assert!(client_supports_app(&json!({
            "capabilities": { "extensions": {
                (APP_EXTENSION_ID): { "mimeTypes": [APP_MIME_TYPE] }
            }}
        })));
        assert!(!client_supports_app(&json!({
            "capabilities": { "extensions": {
                (APP_EXTENSION_ID): { "mimeTypes": ["text/html"] }
            }}
        })));
        assert!(!client_supports_app(&json!({ "capabilities": {} })));
    }

    #[test]
    fn only_safe_local_sources_are_collected() {
        let sources = local_sources(concat!(
            "<img src=\"icons/a.png\"><script src=\"bloom.js\"></script>",
            "<img src=\"https://example/a.png\"><img src=\"../secret\">",
            "<img src=\"data:image/png;base64,x\"><img src=\"/absolute\">",
        ));
        assert_eq!(sources, BTreeSet::from(["icons/a.png".to_owned()]));
    }

    #[test]
    fn widget_tools_only_gain_ui_metadata_for_capable_hosts() {
        let plain = VIEW_TOOLS[0].descriptor(false);
        let app = VIEW_TOOLS[0].descriptor(true);
        assert!(plain.get("_meta").is_none());
        assert_eq!(app["_meta"]["ui"]["resourceUri"], APP_RESOURCE_URI);
        assert_eq!(app["annotations"]["readOnlyHint"], true);
    }
}
