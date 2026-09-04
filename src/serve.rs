use crate::baseline::{self, CheckReport};
use crate::config::Config;
use crate::state;
use anyhow::{Context, Result};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;

type ApiError = (StatusCode, Json<Value>);

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub data_dir: Arc<PathBuf>,
    pub token: Option<Arc<String>>,
}

/// Start the HTTP API (BIT Remote tool compatible) plus MCP.
pub async fn run(
    cfg: Config,
    data_dir: PathBuf,
    host: String,
    port: u16,
    token: Option<String>,
) -> Result<()> {
    let state = AppState {
        cfg: Arc::new(cfg),
        data_dir: Arc::new(data_dir),
        token: token.map(Arc::new),
    };
    let app = Router::new()
        .route("/health", get(health))
        .route("/report", get(report))
        .route("/invoke", post(invoke))
        .merge(crate::mcp::routes())
        .with_state(state);
    let addr = format!("{host}:{port}");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("failed to bind {addr}"))?;
    eprintln!(
        "adonword serve listening on http://{} (POST /invoke, POST /mcp MCP)",
        listener.local_addr()?
    );
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> impl IntoResponse {
    Json(json!({"ok": true}))
}

pub(crate) fn authorized(headers: &HeaderMap, state: &AppState) -> bool {
    match &state.token {
        None => true,
        Some(token) => headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value == format!("Bearer {token}")),
    }
}

fn unauthorized() -> ApiError {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "missing or invalid bearer token"})),
    )
}

fn stored_report(state: &AppState) -> Value {
    match state::load_scan(&state.data_dir) {
        Ok(Some(result)) => json!({"status": "ok", "report": result}),
        Ok(None) => json!({"status": "no_report", "report": Value::Null}),
        Err(e) => json!({"status": "error", "error": e.to_string()}),
    }
}

async fn report(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    if !authorized(&headers, &state) {
        return Err(unauthorized());
    }
    Ok(Json(stored_report(&state)))
}

/// Why an action call failed. `Bad` maps to HTTP 400, `Internal` to 500; the
/// MCP surface flattens both into `isError` results.
pub enum ActionError {
    Bad(String),
    Internal(String),
}

/// Shared action routing used by `POST /invoke` and the MCP `tools/call`.
/// The three actions take no parameters; the action name alone selects the
/// behavior, so results and authorization agree across both protocols.
pub async fn dispatch_action(
    state: &AppState,
    action: &str,
) -> std::result::Result<Value, ActionError> {
    match action {
        "scan" => {
            let cfg = state.cfg.clone();
            let data_dir = state.data_dir.clone();
            let result =
                tokio::task::spawn_blocking(move || crate::watch::scan_once(&cfg, &data_dir))
                    .await
                    .map_err(|e| ActionError::Internal(e.to_string()))?
                    .map_err(|e| ActionError::Internal(e.to_string()))?;
            serde_json::to_value(&result).map_err(|e| ActionError::Internal(e.to_string()))
        }
        "baseline_check" => {
            let cfg = state.cfg.clone();
            let data_dir = state.data_dir.clone();
            let report = tokio::task::spawn_blocking(move || -> Result<CheckReport> {
                match baseline::load(&data_dir)? {
                    Some(b) => Ok(baseline::check(&cfg, &b)),
                    None => Ok(CheckReport {
                        status: "missing".to_string(),
                        ..CheckReport::default()
                    }),
                }
            })
            .await
            .map_err(|e| ActionError::Internal(e.to_string()))?
            .map_err(|e| ActionError::Internal(e.to_string()))?;
            serde_json::to_value(&report).map_err(|e| ActionError::Internal(e.to_string()))
        }
        "report" => Ok(stored_report(state)),
        other => Err(ActionError::Bad(format!(
            "unknown action '{other}' — expected one of: scan, baseline_check, report"
        ))),
    }
}

/// BIT Remote protocol entry point. Payload:
/// `{"tool_id": "...", "tool": "...", "invoked_by": "...", "params": {...}}`.
/// Routed on `params.action` (fallback `params.tool`):
/// `scan` | `baseline_check` | `report`.
async fn invoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    if !authorized(&headers, &state) {
        return Err(unauthorized());
    }
    let payload: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => json!({}),
    };
    let params = payload.get("params").cloned().unwrap_or_else(|| json!({}));
    let action = params
        .get("action")
        .and_then(Value::as_str)
        .or_else(|| params.get("tool").and_then(Value::as_str))
        .unwrap_or_default()
        .to_string();

    match dispatch_action(&state, &action).await {
        Ok(value) => Ok(Json(value)),
        Err(ActionError::Bad(message)) => {
            Err((StatusCode::BAD_REQUEST, Json(json!({"error": message}))))
        }
        Err(ActionError::Internal(message)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": message})),
        )),
    }
}
