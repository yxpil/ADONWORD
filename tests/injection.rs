//! 不可信输入注入安全测试 —— ADONWORD 的 HTTP/MCP/CLI 表面都吃外部喂进来的 JSON。
//!
//! 攻击面：`POST /invoke`（BIT Remote）、`POST /mcp`（JSON-RPC）、stdin JSON（BIT exec）。
//! 这里断言：畸形/恶意载荷被拒绝或安全忽略、不 panic、不打到 shell、
//! 错误响应始终是合法 JSON（XSS 载荷被困在字符串里，不破坏结构）。

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

fn post_body(base: &str, path: &str, raw: &str) -> (u16, String) {
    match ureq::post(&format!("{base}{path}"))
        .timeout(Duration::from_secs(10))
        .set("Content-Type", "application/json")
        .send_string(raw)
    {
        Ok(resp) => (resp.status(), resp.into_json::<Value>().map(|v| v.to_string()).unwrap_or_default()),
        Err(ureq::Error::Status(code, resp)) => {
            (code, resp.into_json::<Value>().map(|v| v.to_string()).unwrap_or_default())
        }
        Err(e) => panic!("request failed: {e}"),
    }
}

#[test]
fn malformed_body_to_invoke_is_400_not_a_crash() {
    let env = setup();
    let srv = spawn(&env);
    // 不是 JSON 的垃圾请求体 → 解析失败按空 params → 空 action → 未知 action 400，绝不 panic。
    let (status, body) = post_body(&srv.base, "/invoke", "this is { not json]]]");
    assert_eq!(status, 400, "body: {body}");
    // 服务仍存活
    let health = ureq::get(&format!("{}/health", srv.base))
        .timeout(Duration::from_secs(3))
        .call()
        .unwrap();
    assert_eq!(health.status(), 200);
}

#[test]
fn malformed_body_to_mcp_is_parse_error_32700() {
    let env = setup();
    let srv = spawn(&env);
    let (status, body) = post_body(&srv.base, "/mcp", "{{{ not json");
    assert_eq!(status, 200);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["error"]["code"], -32700, "malformed JSON-RPC must be -32700: {v}");
}

#[test]
fn command_like_action_name_is_rejected_as_unknown_not_shelled() {
    let env = setup();
    let before = std::fs::read_dir(&env.data_dir).unwrap().count();
    let srv = spawn(&env);
    // action 长得像命令注入：服务绝不 spawn shell，只按名字路由。
    let (status, body) = post_body(
        &srv.base,
        "/invoke",
        r#"{"params":{"action":"scan; touch /tmp/pwned-adonword; #"}}"#,
    );
    assert_eq!(status, 400, "未知 action 必须 400: {body}");
    assert!(body.contains("unknown action"));
    // 没有任何副作用文件被写进 data_dir
    let after = std::fs::read_dir(&env.data_dir).unwrap().count();
    assert_eq!(before, after, "action 注入不得产生文件写入");
    assert!(!std::path::Path::new("/tmp/pwned-adonword").exists());
}

#[test]
fn xss_tool_name_is_safely_embedded_in_json_error() {
    let env = setup();
    let srv = spawn(&env);
    // tools/call 名字里塞 XSS：必须 -32602 拒绝，且载荷被安全地放进 JSON 字符串。
    let raw = json!({
        "jsonrpc":"2.0","id":7,"method":"tools/call",
        "params":{"name":"<script>alert(document.cookie)</script>","arguments":{}}
    })
    .to_string();
    let (status, body) = post_body(&srv.base, "/mcp", &raw);
    assert_eq!(status, 200);
    // 关键：整段响应是合法 JSON（尖括号被转义在 message 字符串里，不逃出结构）
    let v: Value = serde_json::from_str(&body).expect("错误响应必须仍是合法 JSON");
    assert_eq!(v["error"]["code"], -32602, "{v}");
    let msg = v["error"]["message"].as_str().unwrap();
    assert!(msg.contains("alert"), "回显的工具名应作为数据出现在 message: {msg}");
    assert!(!msg.contains("</script><script"), "不得破坏 JSON 结构");
}

#[test]
fn garbage_and_typed_wrong_stdin_does_not_crash_cli() {
    let env = setup();
    let run = |stdin: &str| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_adonword"))
            .args(["scan", "--json"])
            .env("ADONWORD_DATA_DIR", &env.data_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write;
        child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap();
        out
    };
    // 1) 垃圾 JSON → 进程干净退出（0 或非 0），绝不 panic/hang
    let o = run("{{{ garbage not json");
    assert!(o.status.code().is_some(), "进程必须正常退出而非崩溃");
    // 2) 类型错误的 paths → 干净报错退出，stderr 不是 panic backtrace
    let o = run(r#"{"watch":{"paths":12345}}"#);
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(
        !stderr.contains("panicked"),
        "类型错误的 stdin 不得 panic: {stderr}"
    );
}
