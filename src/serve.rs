use crate::baseline::{self, CheckReport};
use crate::config::Config;
use crate::state;
use anyhow::{Context, Result};
use axum::extract::{rejection::JsonRejection, State};
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

/// Start the HTTP API (BIT Remote tool compatible).
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
        .with_state(state);
    let addr = format!("{host}:{port}");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("failed to bind {addr}"))?;
    eprintln!(
        "adonword serve listening on http://{}",
        listener.local_addr()?
    );
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> impl IntoResponse {
    Json(json!({"ok": true}))
}

fn authorized(headers: &HeaderMap, state: &AppState) -> bool {
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

fn internal(e: anyhow::Error) -> ApiError {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": e.to_string()})),
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

/// BIT Remote protocol entry point. Payload:
/// `{"tool_id": "...", "tool": "...", "invoked_by": "...", "params": {...}}`.
/// Routed on `params.action` (fallback `params.tool`):
/// `scan` | `baseline_check` | `report`.
async fn invoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<Value>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    if !authorized(&headers, &state) {
        return Err(unauthorized());
    }
    let params = match body {
        Ok(Json(value)) => value.get("params").cloned().unwrap_or_else(|| json!({})),
        Err(_) => json!({}),
    };
    let action = params
        .get("action")
        .and_then(Value::as_str)
        .or_else(|| params.get("tool").and_then(Value::as_str))
        .unwrap_or_default()
        .to_string();

    match action.as_str() {
        "scan" => {
            let st = state.clone();
            let result =
                tokio::task::spawn_blocking(move || crate::watch::scan_once(&st.cfg, &st.data_dir))
                    .await
                    .map_err(|e| internal(anyhow::anyhow!(e.to_string())))?
                    .map_err(internal)?;
            Ok(Json(
                serde_json::to_value(&result).map_err(|e| internal(e.into()))?,
            ))
        }
        "baseline_check" => {
            let st = state.clone();
            let report = tokio::task::spawn_blocking(move || -> Result<CheckReport> {
                match baseline::load(&st.data_dir)? {
                    Some(b) => Ok(baseline::check(&st.cfg, &b)),
                    None => Ok(CheckReport {
                        status: "missing".to_string(),
                        ..CheckReport::default()
                    }),
                }
            })
            .await
            .map_err(|e| internal(anyhow::anyhow!(e.to_string())))?
            .map_err(internal)?;
            Ok(Json(
                serde_json::to_value(&report).map_err(|e| internal(e.into()))?,
            ))
        }
        "report" => Ok(Json(stored_report(&state))),
        other => Err((
            StatusCode::BAD_REQUEST,
            Json(
                json!({"error": format!("unknown action '{other}' — expected one of: scan, baseline_check, report")}),
            ),
        )),
    }
}
