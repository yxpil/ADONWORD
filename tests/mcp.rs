//! Integration tests for the MCP surface of `adonword serve` (Streamable
//! HTTP JSON-RPC on `/` and `/mcp`). Runs the real binary against an isolated
//! data dir + watch dir, exercising the full baseline -> scan -> report chain,
//! protocol errors and bearer-token protection.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::{json, Value};

struct TestEnv {
    data_dir: PathBuf,
    watch_dir: PathBuf,
    _guards: (tempfile::TempDir, tempfile::TempDir),
}

fn toml_path(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

/// Isolated data dir + watch dir; the config watches the watch dir with an
/// EMPTY port allowlist (so the serve socket itself alerts as unlisted_port).
fn setup(files: &[(&str, &[u8])]) -> TestEnv {
    let data = tempfile::tempdir().unwrap();
    let watch = tempfile::tempdir().unwrap();
    for (name, content) in files {
        let path = watch.path().join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, content).unwrap();
    }
    let config = format!(
        "[watch]\npaths = [\"{}\"]\n\n[ports]\nallowed = []\nalert_unlisted = true\n",
        toml_path(watch.path())
    );
    std::fs::write(data.path().join("adonword.toml"), config).unwrap();
    TestEnv {
        data_dir: data.path().to_path_buf(),
        watch_dir: watch.path().to_path_buf(),
        _guards: (data, watch),
    }
}

struct ServeHandle {
    child: Child,
    addr: String,
}

impl Drop for ServeHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_serve(env: &TestEnv, extra: &[&str]) -> ServeHandle {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_adonword"))
        .args(["serve", "--port", &port.to_string()])
        .args(extra)
        .env("ADONWORD_DATA_DIR", &env.data_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn adonword serve");
    let stderr = child.stderr.take().expect("serve stderr");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufRead::lines(std::io::BufReader::new(stderr)) {
            let Ok(line) = line else { break };
            if let Some(addr) = line
                .trim()
                .strip_prefix("adonword serve listening on http://")
                .and_then(|rest| rest.split_whitespace().next())
            {
                let _ = tx.send(addr.to_string());
                break;
            }
        }
    });
    let addr = rx
        .recv_timeout(Duration::from_secs(20))
        .expect("serve did not print its listening address in time");
    ServeHandle { child, addr }
}

/// POST a JSON-RPC message; returns (status, Mcp-Session-Id?, body).
fn rpc(
    addr: &str,
    session: Option<&str>,
    token: Option<&str>,
    message: Value,
) -> (u16, Option<String>, Value) {
    let mut request = ureq::post(&format!("http://{addr}/mcp")).timeout(Duration::from_secs(30));
    if let Some(sid) = session {
        request = request.set("Mcp-Session-Id", sid);
    }
    if let Some(t) = token {
        request = request.set("Authorization", &format!("Bearer {t}"));
    }
    match request.send_string(&message.to_string()) {
        Ok(resp) => (
            resp.status(),
            resp.header("Mcp-Session-Id").map(str::to_string),
            resp.into_json().unwrap_or(Value::Null),
        ),
        Err(ureq::Error::Status(status, resp)) => (
            status,
            resp.header("Mcp-Session-Id").map(str::to_string),
            resp.into_json().unwrap_or(Value::Null),
        ),
        Err(e) => panic!("http request failed: {e}"),
    }
}

fn initialize(addr: &str) -> String {
    let (status, sid, body) = rpc(
        addr,
        None,
        None,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": { "name": "test", "version": "0" }
            }
        }),
    );
    assert_eq!(status, 200);
    assert_eq!(body["result"]["serverInfo"]["name"], "adonword");
    assert_eq!(body["result"]["protocolVersion"], "2025-03-26");
    sid.expect("initialize must issue an Mcp-Session-Id")
}

fn call(addr: &str, sid: &str, id: i64, name: &str, args: Value) -> Value {
    let (_, _, body) = rpc(
        addr,
        Some(sid),
        None,
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": { "name": name, "arguments": args }
        }),
    );
    body["result"].clone()
}

fn payload(result: &Value) -> Value {
    serde_json::from_str(result["content"][0]["text"].as_str().expect("text content"))
        .expect("tool payload is JSON")
}

fn run_cli(args: &[&str], env: &TestEnv) {
    let child = Command::new(env!("CARGO_BIN_EXE_adonword"))
        .args(args)
        .env("ADONWORD_DATA_DIR", &env.data_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn adonword");
    let out = child.wait_with_output().expect("failed to wait");
    assert_eq!(
        out.status.code(),
        Some(0),
        "cli {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn handshake_tools_list_and_full_baseline_scan_report_chain() {
    let env = setup(&[("a.txt", b"v1".as_slice())]);
    run_cli(&["baseline", "update", "--json"], &env);

    let server = spawn_serve(&env, &[]);
    let addr = server.addr.clone();
    let sid = initialize(&addr);

    // Notifications are accepted silently.
    let (status, _, body) = rpc(
        &addr,
        Some(&sid),
        None,
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    );
    assert_eq!(status, 202);
    assert_eq!(body, Value::Null);

    // tools/list: three parameterless tools with schemas.
    let (_, _, body) = rpc(
        &addr,
        Some(&sid),
        None,
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }),
    );
    let tools = body["result"]["tools"].as_array().expect("tools");
    let names: Vec<&str> = tools
        .iter()
        .map(|t| t["name"].as_str().expect("name"))
        .collect();
    assert_eq!(names, vec!["scan", "baseline_check", "report"]);
    for tool in tools {
        assert_eq!(tool["inputSchema"]["type"], "object");
        assert!(!tool["description"].as_str().unwrap().is_empty());
    }

    // report before any scan -> no_report
    let result = call(&addr, &sid, 3, "report", json!({}));
    assert_eq!(result["isError"], false);
    assert_eq!(payload(&result)["status"], "no_report");

    // baseline_check on an untouched tree -> clean
    let result = call(&addr, &sid, 4, "baseline_check", json!({}));
    assert_eq!(result["isError"], false);
    assert_eq!(payload(&result)["status"], "clean");

    // scan -> findings include the serve socket itself (empty allowlist)
    let result = call(&addr, &sid, 5, "scan", json!({}));
    assert_eq!(result["isError"], false, "{}", result);
    let v = payload(&result);
    assert!(v["scanned_at"].is_string());
    assert!(
        v["findings"]
            .as_array()
            .expect("findings")
            .iter()
            .any(|f| f["kind"] == "unlisted_port"),
        "response: {v}"
    );

    // report now reflects the persisted scan
    let result = call(&addr, &sid, 6, "report", json!({}));
    assert_eq!(result["isError"], false);
    let v = payload(&result);
    assert_eq!(v["status"], "ok");
    assert!(v["report"]["findings"].as_array().is_some());

    // tamper the watched tree -> baseline_check drifts to changed/modified
    std::fs::write(env.watch_dir.join("a.txt"), b"tampered").unwrap();
    let result = call(&addr, &sid, 7, "baseline_check", json!({}));
    assert_eq!(result["isError"], false);
    let v = payload(&result);
    assert_eq!(v["status"], "changed");
    assert_eq!(v["modified"], json!(["a.txt"]));

    // unknown action name via tools/call -> isError result
    let (_, _, body) = rpc(
        &addr,
        Some(&sid),
        None,
        json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": { "name": "kill_process", "arguments": {} }
        }),
    );
    assert_eq!(body["error"]["code"], -32602);
}

#[test]
fn protocol_errors_and_argument_tolerance() {
    let env = setup(&[]);
    let server = spawn_serve(&env, &[]);
    let addr = server.addr.clone();
    let sid = initialize(&addr);

    // Unknown method -> -32601; ping -> {}.
    let (_, _, body) = rpc(
        &addr,
        Some(&sid),
        None,
        json!({ "jsonrpc": "2.0", "id": 10, "method": "resources/list" }),
    );
    assert_eq!(body["error"]["code"], -32601);
    let (_, _, body) = rpc(
        &addr,
        Some(&sid),
        None,
        json!({ "jsonrpc": "2.0", "id": 11, "method": "ping" }),
    );
    assert_eq!(body["result"], json!({}));

    // The tools are parameterless: junk arguments are tolerated and ignored.
    let result = call(&addr, &sid, 12, "scan", json!({"bogus": 1, "target": "x"}));
    assert_eq!(result["isError"], false, "{}", result);
    assert!(payload(&result)["scanned_at"].is_string());

    // baseline_check without a baseline -> status "missing", not an error.
    let result = call(&addr, &sid, 13, "baseline_check", json!({}));
    assert_eq!(result["isError"], false);
    assert_eq!(payload(&result)["status"], "missing");
}

#[test]
fn token_protects_mcp_endpoint_too() {
    let env = setup(&[]);
    let server = spawn_serve(&env, &["--token", "sekrit"]);
    let addr = server.addr.clone();

    // Without the bearer token the MCP endpoint answers 401 like /invoke.
    let response = ureq::post(&format!("http://{addr}/mcp"))
        .timeout(Duration::from_secs(5))
        .set("Content-Type", "application/json")
        .send_string(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#);
    match response {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401 without token, got {other:?}"),
    }

    // With the token the handshake succeeds and a call works.
    let (status, sid, body) = rpc(
        &addr,
        None,
        Some("sekrit"),
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "protocolVersion": "2025-03-26", "capabilities": {} }
        }),
    );
    assert_eq!(status, 200);
    assert_eq!(body["result"]["serverInfo"]["name"], "adonword");
    let sid = sid.expect("session id");

    let result = call_with_token(&addr, &sid, "sekrit", 2, "baseline_check", json!({}));
    assert_eq!(result["isError"], false);
    assert_eq!(payload(&result)["status"], "missing");
}

fn call_with_token(addr: &str, sid: &str, token: &str, id: i64, name: &str, args: Value) -> Value {
    let (_, _, body) = rpc(
        addr,
        Some(sid),
        Some(token),
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": { "name": name, "arguments": args }
        }),
    );
    body["result"].clone()
}

#[test]
fn root_endpoint_serves_mcp_too() {
    let env = setup(&[]);
    let server = spawn_serve(&env, &[]);
    // BIT discovery probes the root: initialize must work on POST / as well.
    let response = ureq::post(&format!("http://{}/", server.addr))
        .timeout(Duration::from_secs(5))
        .set("Content-Type", "application/json")
        .send_string(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{}}}"#,
        )
        .expect("root request succeeds");
    assert_eq!(response.status(), 200);
    let body: Value = response.into_json().expect("json");
    assert_eq!(body["result"]["serverInfo"]["name"], "adonword");
}
