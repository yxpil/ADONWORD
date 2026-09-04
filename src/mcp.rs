//! MCP (Model Context Protocol) server over Streamable HTTP — hand-rolled
//! JSON-RPC 2.0 on axum, wire-compatible with BIT's MCP client (the same
//! contract SECFORGE, PANOPTES, Neton and MemoryPool speak). Tool calls route
//! into the shared action funnel in `serve::dispatch_action`, so the MCP
//! surface and `POST /invoke` always agree.
//!
//! Contract (verified against BIT's client):
//! - `initialize` → result `{protocolVersion, capabilities:{tools:{listChanged:false}}, serverInfo}`
//!   plus an `Mcp-Session-Id` response header (echoed back by clients).
//! - `notifications/*` (or any id-less message) → HTTP 202, empty body.
//! - `tools/list` → `{tools:[{name, description, inputSchema}]}` (single page).
//! - `tools/call` → `{content:[{type:"text", text:<json string>}], isError}` —
//!   failures are 200 + `isError:true`, never transport errors.
//! - unknown method → JSON-RPC error -32601; `ping` → empty result.
//!
//! A configured bearer token protects the MCP endpoints exactly like
//! `/invoke` (per-request check, matching the rest of `serve`). Sessions are
//! issued for spec compliance but not tracked server-side.

use std::sync::atomic::{AtomicU64, Ordering};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};

use crate::serve::{authorized, dispatch_action, ActionError, AppState};

/// Protocol versions we can speak; we echo the client's choice when possible.
const MCP_VERSIONS: [&str; 3] = ["2024-11-05", "2025-03-26", "2025-06-18"];

static SESSION_SEQ: AtomicU64 = AtomicU64::new(0);

/// One adonword capability exposed over MCP.
pub struct ToolDef {
    /// MCP tool name = the action name.
    pub name: &'static str,
    /// English description surfaced in `tools/list`.
    pub description: &'static str,
    /// JSON Schema for the `arguments` object.
    pub input_schema: Value,
}

fn empty_schema() -> Value {
    json!({ "type": "object", "properties": {} })
}

/// All tools adonword exposes, in stable order.
pub fn tools() -> &'static [ToolDef] {
    static TOOLS: std::sync::OnceLock<Vec<ToolDef>> = std::sync::OnceLock::new();
    TOOLS.get_or_init(|| {
        vec![
            ToolDef {
                name: "scan",
                description: "Run one full inspection now: file-integrity check against the \
                              baseline, suspicious process lookups and listening-port alerts. \
                              Observation + alerting only — never kills processes. Also stores \
                              the report for later `report` calls.",
                input_schema: empty_schema(),
            },
            ToolDef {
                name: "baseline_check",
                description: "Compare the current watched files against the stored sha256 \
                              baseline. status is clean | changed | missing (no baseline yet).",
                input_schema: empty_schema(),
            },
            ToolDef {
                name: "report",
                description: "Fetch the most recent stored scan report (from the last `scan` \
                              call or watch round); no_report before the first scan.",
                input_schema: empty_schema(),
            },
        ]
    })
}

/// Mirror BIT's `gen_mcp_session_id`: monotonic, unique per process.
fn gen_session_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = SESSION_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("mcp-{nanos:x}-{:x}-{seq:x}", std::process::id())
}

fn negotiate_version(client: &str) -> &'static str {
    MCP_VERSIONS
        .iter()
        .find(|v| **v == client)
        .copied()
        .unwrap_or(MCP_VERSIONS[MCP_VERSIONS.len() - 1])
}

fn rpc_ok(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn rpc_err(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn json_response(status: StatusCode, body: Option<Value>, session: Option<&str>) -> Response {
    let mut builder = Response::builder().status(status);
    if let Some(sid) = session {
        builder = builder.header("Mcp-Session-Id", sid);
    }
    match body {
        Some(v) => builder
            .header("content-type", "application/json")
            .body(axum::body::Body::from(v.to_string()))
            .expect("static response"),
        None => builder
            .body(axum::body::Body::empty())
            .expect("static response"),
    }
    .into_response()
}

/// MCP JSON-RPC entry point, mounted on both `/` (BIT discovery probes the root)
/// and `/mcp` (the canonical Streamable HTTP path).
async fn rpc_entry(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if !authorized(&headers, &state) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "missing or invalid bearer token" })),
        )
            .into_response();
    }
    let msg: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return json_response(
                StatusCode::OK,
                Some(rpc_err(Value::Null, -32700, &format!("parse error: {e}"))),
                None,
            );
        }
    };

    let method = msg
        .get("method")
        .and_then(|m| m.as_str())
        .unwrap_or_default()
        .to_string();
    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    let is_notification = msg.get("id").is_none() || method.starts_with("notifications/");
    let params = msg.get("params").cloned().unwrap_or(Value::Null);

    if is_notification {
        return json_response(StatusCode::ACCEPTED, None, None);
    }

    match method.as_str() {
        "initialize" => {
            let client_ver = params
                .get("protocolVersion")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let session = gen_session_id();
            let result = json!({
                "protocolVersion": negotiate_version(client_ver),
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": {
                    "name": "adonword",
                    "version": env!("CARGO_PKG_VERSION"),
                },
            });
            json_response(StatusCode::OK, Some(rpc_ok(id, result)), Some(&session))
        }
        "ping" => json_response(StatusCode::OK, Some(rpc_ok(id, json!({}))), None),
        "tools/list" => {
            let tools: Vec<Value> = tools()
                .iter()
                .map(|t| {
                    json!({
                        "name": t.name,
                        "description": t.description,
                        "inputSchema": t.input_schema,
                    })
                })
                .collect();
            json_response(
                StatusCode::OK,
                Some(rpc_ok(id, json!({ "tools": tools }))),
                None,
            )
        }
        "tools/call" => {
            let name = params
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if !tools().iter().any(|t| t.name == name) {
                return json_response(
                    StatusCode::OK,
                    Some(rpc_err(id, -32602, &format!("tool not found: '{name}'"))),
                    None,
                );
            }
            let outcome = dispatch_action(&state, name).await;
            let (text, is_error) = match outcome {
                Ok(value) => (value.to_string(), false),
                Err(ActionError::Bad(message)) | Err(ActionError::Internal(message)) => {
                    (message, true)
                }
            };
            json_response(
                StatusCode::OK,
                Some(rpc_ok(
                    id,
                    json!({ "content": [{ "type": "text", "text": text }], "isError": is_error }),
                )),
                None,
            )
        }
        other => json_response(
            StatusCode::OK,
            Some(rpc_err(id, -32601, &format!("method not found: '{other}'"))),
            None,
        ),
    }
}

/// MCP JSON-RPC routes to merge into the serve router: POST `/` and `/mcp`.
/// Bearer-token protection is enforced inside `rpc_entry`, matching the
/// per-handler auth of the other endpoints.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", post(rpc_entry))
        .route("/mcp", post(rpc_entry))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_three_parameterless_tools() {
        let tools = tools();
        assert_eq!(tools.len(), 3);
        let names: Vec<&str> = tools.iter().map(|t| t.name).collect();
        assert_eq!(names, vec!["scan", "baseline_check", "report"]);
        for tool in tools {
            assert_eq!(tool.input_schema["type"], "object");
            assert!(!tool.description.is_empty());
        }
    }

    #[test]
    fn negotiate_echoes_supported_client_versions() {
        assert_eq!(negotiate_version("2024-11-05"), "2024-11-05");
        assert_eq!(negotiate_version("2025-03-26"), "2025-03-26");
        assert_eq!(negotiate_version("1999-01-01"), "2025-06-18");
        assert_eq!(negotiate_version(""), "2025-06-18");
    }
}
