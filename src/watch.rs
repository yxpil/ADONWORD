use crate::baseline;
use crate::config::Config;
use crate::engine::{run_scan, Finding, ScanResult};
use crate::state;
use anyhow::Result;
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

/// The same finding is only alerted once within this window.
pub const DEDUP_WINDOW: Duration = Duration::from_secs(300);

/// Run scan rounds forever: persist the result, alert on stderr + webhook
/// (with 5-minute per-finding dedup), sleep, repeat.
pub fn run(cfg: Config, data_dir: &Path, interval: u64, json: bool) -> Result<()> {
    let interval = Duration::from_secs(interval.max(1));
    let mut last_sent: HashMap<(String, String), Instant> = HashMap::new();
    eprintln!(
        "adonword watch started (interval {}s, data dir {}, ctrl-c to stop)",
        interval.as_secs(),
        data_dir.display()
    );
    loop {
        let round = Instant::now();
        let result = scan_once(&cfg, data_dir)?;
        for finding in &result.findings {
            let key = (finding.kind.clone(), finding.detail.clone());
            if let Some(sent_at) = last_sent.get(&key) {
                if round.duration_since(*sent_at) < DEDUP_WINDOW {
                    continue; // duplicate within the alert window
                }
            }
            last_sent.insert(key, round);
            alert_stderr(finding);
            send_webhook(&cfg.alert.webhook_url, finding);
        }
        last_sent.retain(|_, sent_at| round.duration_since(*sent_at) < DEDUP_WINDOW);

        if json {
            // One JSON object per round (JSON Lines) on stdout.
            println!("{}", serde_json::to_string(&result)?);
        } else {
            println!(
                "{} scan complete: {} findings ({} crit, {} warn)",
                result.scanned_at, result.summary.total, result.summary.crit, result.summary.warn
            );
        }
        let _ = std::io::stdout().flush();
        std::thread::sleep(interval);
    }
}

/// One scan round: load baseline (if any), run the inspection, persist it to
/// `<data_dir>/state.json`.
pub fn scan_once(cfg: &Config, data_dir: &Path) -> Result<ScanResult> {
    let baseline = baseline::load(data_dir)?;
    let result = run_scan(cfg, baseline.as_ref());
    state::save_scan(data_dir, &result)?;
    Ok(result)
}

fn alert_stderr(finding: &Finding) {
    eprintln!(
        "[ALERT] [{}] {} {} (at {})",
        finding.severity, finding.kind, finding.detail, finding.triggered_at
    );
}

/// POST the finding as JSON to `[alert].webhook_url` (10s timeout).
/// Empty URL is a no-op; transport errors are reported on stderr and never
/// crash the watch loop.
pub fn send_webhook(url: &str, finding: &Finding) {
    if url.trim().is_empty() {
        return;
    }
    let payload = serde_json::json!({
        "kind": finding.kind,
        "severity": finding.severity,
        "detail": finding.detail,
        "triggered_at": finding.triggered_at,
    });
    match ureq::post(url)
        .timeout(Duration::from_secs(10))
        .send_json(&payload)
    {
        Ok(resp) => {
            if resp.status() >= 400 {
                eprintln!("[webhook] unexpected status {}", resp.status());
            }
        }
        Err(e) => eprintln!("[webhook] failed to send alert: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::now_rfc3339;
    use std::io::Read;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn send_webhook_is_noop_for_empty_url() {
        let finding = Finding {
            kind: "test".into(),
            severity: "warn".into(),
            detail: "d".into(),
            triggered_at: now_rfc3339(),
        };
        send_webhook("", &finding);
        send_webhook("   ", &finding);
    }

    #[test]
    fn webhook_posts_finding_json() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut data = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = stream.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&buf[..n]);
                let s = String::from_utf8_lossy(&data);
                if let Some(pos) = s.find("\r\n\r\n") {
                    let body = &s[pos + 4..];
                    let content_length = s
                        .lines()
                        .find_map(|l| {
                            let lower = l.to_lowercase();
                            let v = lower.strip_prefix("content-length:")?;
                            v.trim().parse::<usize>().ok()
                        })
                        .unwrap_or(0);
                    if body.len() >= content_length {
                        break;
                    }
                }
                if data.len() > 16_384 {
                    break;
                }
            }
            let raw = String::from_utf8_lossy(&data).to_string();
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
            let _ = stream.flush();
            raw
        });

        let finding = Finding {
            kind: "unlisted_port".into(),
            severity: "warn".into(),
            detail: "listening on 127.0.0.1:9999".into(),
            triggered_at: now_rfc3339(),
        };
        send_webhook(&format!("http://{addr}/hook"), &finding);

        let raw = handle.join().unwrap();
        assert!(raw.starts_with("POST /hook"), "raw request: {raw}");
        assert!(
            raw.contains("\"kind\":\"unlisted_port\""),
            "raw request: {raw}"
        );
        assert!(raw.contains("\"severity\":\"warn\""), "raw request: {raw}");
    }
}
