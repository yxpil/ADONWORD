use serde_json::Value;
use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

struct TestEnv {
    data_dir: PathBuf,
    watch_dir: PathBuf,
    _guards: (tempfile::TempDir, tempfile::TempDir),
}

fn toml_path(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

/// Create an isolated data dir + watch dir and a config that watches the
/// watch dir with an EMPTY port allowlist (so any listening socket alerts).
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

struct RunOutcome {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str], env: &TestEnv, stdin: Option<&str>) -> RunOutcome {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_adonword"));
    cmd.args(args)
        .env("ADONWORD_DATA_DIR", &env.data_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if stdin.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    let mut child = cmd.spawn().expect("failed to spawn adonword");
    if let Some(payload) = stdin {
        let mut pipe = child.stdin.take().unwrap();
        pipe.write_all(payload.as_bytes()).unwrap();
    }
    let out = child
        .wait_with_output()
        .expect("failed to wait for adonword");
    RunOutcome {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    }
}

fn parse_json(out: &RunOutcome) -> Value {
    serde_json::from_str(&out.stdout)
        .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {}", out.stdout))
}

#[test]
fn baseline_update_then_check_detects_modified() {
    let env = setup(&[
        ("a.txt", b"hello".as_slice()),
        ("sub/b.txt", b"world".as_slice()),
    ]);

    let out = run(&["baseline", "update", "--json"], &env, None);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let v = parse_json(&out);
    assert_eq!(v["status"], "updated");
    assert_eq!(v["files"], 2);

    // tamper with a file
    std::fs::write(env.watch_dir.join("a.txt"), b"tampered").unwrap();

    let out = run(&["baseline", "check", "--json"], &env, None);
    assert_eq!(
        out.code, 1,
        "changed tree must exit 1; stderr: {}",
        out.stderr
    );
    let v = parse_json(&out);
    assert_eq!(v["status"], "changed");
    let modified = v["modified"].as_array().unwrap();
    assert!(
        modified.contains(&Value::String("a.txt".into())),
        "{modified:?}"
    );
    assert!(!modified.contains(&Value::String("sub/b.txt".into())));

    // restore -> clean again, exit 0
    std::fs::write(env.watch_dir.join("a.txt"), b"hello").unwrap();
    let out = run(&["baseline", "check"], &env, None);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    assert!(out.stdout.contains("clean"), "stdout: {}", out.stdout);
}

#[test]
fn baseline_check_detects_added_and_removed() {
    let env = setup(&[("a.txt", b"x".as_slice())]);

    let out = run(&["baseline", "update", "--json"], &env, None);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);

    std::fs::write(env.watch_dir.join("new.txt"), b"newcomer").unwrap();
    let out = run(&["baseline", "check", "--json"], &env, None);
    assert_eq!(out.code, 1);
    let v = parse_json(&out);
    let added = v["added"].as_array().unwrap();
    assert!(
        added.contains(&Value::String("new.txt".into())),
        "{added:?}"
    );

    std::fs::remove_file(env.watch_dir.join("a.txt")).unwrap();
    let out = run(&["baseline", "check", "--json"], &env, None);
    assert_eq!(out.code, 1);
    let v = parse_json(&out);
    let removed = v["removed"].as_array().unwrap();
    assert!(
        removed.contains(&Value::String("a.txt".into())),
        "{removed:?}"
    );
}

#[test]
fn baseline_check_without_baseline_exits_two() {
    let env = setup(&[("a.txt", b"x".as_slice())]);
    let out = run(&["baseline", "check", "--json"], &env, None);
    assert_eq!(out.code, 2);
    let v = parse_json(&out);
    assert_eq!(v["status"], "missing");
}

#[test]
fn stdin_json_overrides_config_watch_paths() {
    // BIT exec contract: config has no watch paths; the piped JSON supplies them.
    let data = tempfile::tempdir().unwrap();
    let watch = tempfile::tempdir().unwrap();
    std::fs::write(watch.path().join("only.txt"), b"1").unwrap();
    std::fs::write(data.path().join("adonword.toml"), "[watch]\npaths = []\n").unwrap();
    let env = TestEnv {
        data_dir: data.path().to_path_buf(),
        watch_dir: watch.path().to_path_buf(),
        _guards: (data, watch),
    };

    let payload = format!(
        "{{\"watch\":{{\"paths\":[\"{}\"]}}}}",
        toml_path(&env.watch_dir)
    );
    let out = run(&["baseline", "update", "--json"], &env, Some(&payload));
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let v = parse_json(&out);
    assert_eq!(v["files"], 1);
}

#[test]
fn scan_reports_unlisted_port_finding() {
    let env = setup(&[("a.txt", b"x".as_slice())]);
    // Guarantee at least one listening TCP socket during the scan.
    let _listener = TcpListener::bind("127.0.0.1:0").unwrap();

    let out = run(&["scan", "--json"], &env, None);
    assert_eq!(
        out.code, 0,
        "scan exits 0 even with findings; stderr: {}",
        out.stderr
    );
    let v = parse_json(&out);
    let findings = v["findings"].as_array().unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f["kind"] == "unlisted_port" && f["severity"] == "warn"),
        "expected an unlisted_port finding, got: {findings:?}"
    );
    assert!(v["summary"]["total"].as_u64().unwrap() >= 1);

    // the scan result is persisted for `report`
    let out = run(&["report", "--json"], &env, None);
    assert_eq!(out.code, 0);
    let v = parse_json(&out);
    assert_eq!(v["status"], "ok");
}

#[test]
fn scan_without_baseline_reports_baseline_missing() {
    let env = setup(&[("a.txt", b"x".as_slice())]);
    let out = run(&["scan", "--json"], &env, None);
    assert_eq!(out.code, 0);
    let v = parse_json(&out);
    assert!(v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["kind"] == "baseline_missing"));
}

#[test]
fn missing_config_file_is_an_error() {
    let env = setup(&[]);
    let out = run(
        &["scan", "--config", "/nonexistent/adonword.toml"],
        &env,
        None,
    );
    assert_ne!(out.code, 0);
    assert!(
        out.stderr.contains("config file not found"),
        "stderr: {}",
        out.stderr
    );
}

#[test]
fn serve_health_invoke_and_token_auth() {
    let env = setup(&[("a.txt", b"x".as_slice())]);
    let out = run(&["baseline", "update", "--json"], &env, None);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);

    let port = free_port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_adonword"))
        .args(["serve", "--port", &port.to_string()])
        .env("ADONWORD_DATA_DIR", &env.data_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn adonword serve");
    let base = format!("http://127.0.0.1:{port}");
    assert!(wait_for_health(&base), "serve did not become ready");

    // GET /health
    let resp: Value = ureq::get(&format!("{base}/health"))
        .timeout(Duration::from_secs(5))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    assert_eq!(resp["ok"], true);

    // POST /invoke action=baseline_check (baseline exists, tree untouched)
    let resp: Value = ureq::post(&format!("{base}/invoke"))
        .timeout(Duration::from_secs(30))
        .send_json(serde_json::json!({
            "tool_id": "tid",
            "tool": "adonword",
            "invoked_by": "integration-test",
            "params": {"action": "baseline_check"}
        }))
        .unwrap()
        .into_json()
        .unwrap();
    assert_eq!(resp["status"], "clean", "response: {resp}");

    // POST /invoke action=scan -> findings array with an unlisted_port
    let resp: Value = ureq::post(&format!("{base}/invoke"))
        .timeout(Duration::from_secs(30))
        .send_json(serde_json::json!({"params": {"action": "scan"}}))
        .unwrap()
        .into_json()
        .unwrap();
    assert!(
        resp["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["kind"] == "unlisted_port"),
        "response: {resp}"
    );

    // GET /report reflects the persisted scan
    let resp: Value = ureq::get(&format!("{base}/report"))
        .timeout(Duration::from_secs(5))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    assert_eq!(resp["status"], "ok");
    assert!(resp["report"]["findings"].as_array().is_some());

    // unknown action -> HTTP 400
    let err = ureq::post(&format!("{base}/invoke"))
        .timeout(Duration::from_secs(5))
        .send_json(serde_json::json!({"params": {"action": "nonsense"}}))
        .unwrap_err();
    match err {
        ureq::Error::Status(code, _) => assert_eq!(code, 400),
        other => panic!("expected HTTP 400, got: {other}"),
    }

    child.kill().unwrap();
    let _ = child.wait();

    // ---- token-protected serve ----
    let port = free_port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_adonword"))
        .args(["serve", "--port", &port.to_string(), "--token", "sekrit"])
        .env("ADONWORD_DATA_DIR", &env.data_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn adonword serve");
    let base = format!("http://127.0.0.1:{port}");
    assert!(
        wait_for_health(&base),
        "token-protected serve did not become ready"
    );

    // /report without token -> 401
    let err = ureq::get(&format!("{base}/report"))
        .timeout(Duration::from_secs(5))
        .call()
        .expect_err("request without token must fail");
    match err {
        ureq::Error::Status(code, _) => assert_eq!(code, 401),
        other => panic!("expected HTTP 401, got: {other}"),
    }
    // with the correct bearer token -> 200
    let resp = ureq::get(&format!("{base}/report"))
        .timeout(Duration::from_secs(5))
        .set("Authorization", "Bearer sekrit")
        .call()
        .unwrap();
    assert_eq!(resp.status(), 200);

    child.kill().unwrap();
    let _ = child.wait();
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn wait_for_health(base: &str) -> bool {
    for _ in 0..100 {
        if let Ok(resp) = ureq::get(&format!("{base}/health"))
            .timeout(Duration::from_secs(2))
            .call()
        {
            if let Ok(v) = resp.into_json::<Value>() {
                if v["ok"] == true {
                    return true;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}
