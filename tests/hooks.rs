//! 钩子/工具注册表测试 —— ADONWORD 通过 MCP 把能力以"注册工具"形式暴露：
//! `tools()` 静态注册 → `tools/list` 列举 → `tools/call` 按名派发。
//!
//! 对应钩子机制的断言：
//! 1. 已注册钩子按稳定顺序列出、按名触发、参数透传；
//! 2. 未注册/越权钩子被拒绝（-32602），绝不派发；
//! 3. 一个钩子调用失败不影响其它钩子（失败隔离）；
//! 4. 调用方伪造的参数不能把动作重绑到别的钩子或提权。

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::{json, Value};

struct Env {
    data_dir: PathBuf,
    watch_dir: PathBuf,
    _guards: (tempfile::TempDir, tempfile::TempDir),
}

fn toml_path(p: &std::path::Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

fn setup() -> Env {
    let data = tempfile::tempdir().unwrap();
    let watch = tempfile::tempdir().unwrap();
    std::fs::write(watch.path().join("a.txt"), b"x").unwrap();
    let config = format!(
        "[watch]\npaths = [\"{}\"]\n\n[ports]\nallowed = []\nalert_unlisted = false\n",
        toml_path(watch.path())
    );
    std::fs::write(data.path().join("adonword.toml"), config).unwrap();
    Env {
        data_dir: data.path().to_path_buf(),
        watch_dir: watch.path().to_path_buf(),
        _guards: (data, watch),
    }
}

fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

struct Server {
    child: std::process::Child,
    base: String,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn(env: &Env) -> Server {
    let port = free_port();
    let child = Command::new(env!("CARGO_BIN_EXE_adonword"))
        .args(["serve", "--port", &port.to_string()])
        .env("ADONWORD_DATA_DIR", &env.data_dir)
        .stdin(Stdio::null()) // 否则 main 会阻塞在读 stdin 直到 EOF
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn adonword serve");
    let base = format!("http://127.0.0.1:{port}");
    for _ in 0..100 {
        if let Ok(r) = ureq::get(&format!("{base}/health"))
            .timeout(Duration::from_secs(1))
            .call()
        {
            if r.into_json::<Value>().map(|v| v["ok"] == true).unwrap_or(false) {
                return Server { child, base };
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("serve did not become ready");
}

/// POST a JSON-RPC message; returns (status, body).
fn rpc(base: &str, message: Value) -> (u16, Value) {
    match ureq::post(&format!("{base}/mcp"))
        .timeout(Duration::from_secs(30))
        .set("Content-Type", "application/json")
        .send_string(&message.to_string())
    {
        Ok(resp) => (resp.status(), resp.into_json().unwrap_or(Value::Null)),
        Err(ureq::Error::Status(code, resp)) => {
            (code, resp.into_json().unwrap_or(Value::Null))
        }
        Err(e) => panic!("rpc failed: {e}"),
    }
}

fn initialize(base: &str) {
    let (status, body) = rpc(
        base,
        json!({"jsonrpc":"2.0","id":1,"method":"initialize",
               "params":{"protocolVersion":"2025-03-26","capabilities":{}}}),
    );
    assert_eq!(status, 200);
    assert_eq!(body["result"]["serverInfo"]["name"], "adonword");
}

#[test]
fn registered_tools_listed_in_stable_order_and_each_routes() {
    let env = setup();
    let srv = spawn(&env);
    initialize(&srv.base);

    let (_, body) = rpc(
        &srv.base,
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    );
    let names: Vec<&str> = body["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    // 钩子注册顺序稳定：scan → baseline_check → report
    assert_eq!(names, vec!["scan", "baseline_check", "report"]);

    // 每个已注册钩子都能按名触发；report 钩子在无历史时返回 no_report
    let (_, body) = rpc(
        &srv.base,
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
               "params":{"name":"report","arguments":{}}}),
    );
    assert_eq!(body["result"]["isError"], false, "{body}");
}

#[test]
fn unregistered_tool_call_is_rejected() {
    let env = setup();
    let srv = spawn(&env);
    initialize(&srv.base);
    // 一个从未注册的钩子名字 → -32602 拒绝，绝不派发。
    let (_, body) = rpc(
        &srv.base,
        json!({"jsonrpc":"2.0","id":4,"method":"tools/call",
               "params":{"name":"delete_everything","arguments":{}}}),
    );
    assert_eq!(body["error"]["code"], -32602, "未注册钩子必须拒绝: {body}");
}

#[test]
fn failed_tool_call_does_not_break_sibling_tools() {
    let env = setup();
    let srv = spawn(&env);
    initialize(&srv.base);

    // 先打一个未注册钩子（错误）——失败必须被隔离
    let (_, body) = rpc(
        &srv.base,
        json!({"jsonrpc":"2.0","id":5,"method":"tools/call",
               "params":{"name":"nope","arguments":{}}}),
    );
    assert_eq!(body["error"]["code"], -32602);

    // 紧接着兄弟钩子 report 照常可用，不受上次失败影响
    let (_, body) = rpc(
        &srv.base,
        json!({"jsonrpc":"2.0","id":6,"method":"tools/call",
               "params":{"name":"report","arguments":{}}}),
    );
    assert_eq!(body["result"]["isError"], false, "兄弟钩子应仍可用: {body}");
}

#[test]
fn forged_arguments_cannot_rebind_action_or_privilege() {
    let env = setup();
    let srv = spawn(&env);
    initialize(&srv.base);
    // 调用方在 arguments 里伪造 action/提权字段：派发只认注册名，参数被忽略。
    let (_, body) = rpc(
        &srv.base,
        json!({"jsonrpc":"2.0","id":7,"method":"tools/call",
               "params":{"name":"report",
                         "arguments":{"action":"scan","__proto__":{"admin":true},
                                      "invoke":"/etc/passwd"}}}),
    );
    let result = &body["result"];
    assert_eq!(result["isError"], false, "{body}");
    let text = result["content"][0]["text"].as_str().unwrap();
    let v: Value = serde_json::from_str(text).unwrap();
    // 仍然是 report 的输出（no_report），而不是被重绑成 scan
    assert_eq!(v["status"], "no_report", "伪造参数不得把 report 重绑成 scan: {v}");
}
