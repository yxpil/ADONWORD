use crate::baseline::{self, Baseline};
use crate::config::Config;
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;
use std::time::UNIX_EPOCH;
use walkdir::WalkDir;

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub kind: String,
    pub severity: String,
    pub detail: String,
    pub triggered_at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Summary {
    pub total: usize,
    pub warn: usize,
    pub crit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scanned_at: String,
    pub findings: Vec<Finding>,
    pub summary: Summary,
}

impl ScanResult {
    fn new() -> Self {
        Self {
            scanned_at: now_rfc3339(),
            findings: Vec::new(),
            summary: Summary::default(),
        }
    }

    fn push(&mut self, kind: &str, severity: &str, detail: impl Into<String>) {
        self.findings.push(Finding {
            kind: kind.to_string(),
            severity: severity.to_string(),
            detail: detail.into(),
            triggered_at: self.scanned_at.clone(),
        });
        self.summary.total += 1;
        match severity {
            "crit" => self.summary.crit += 1,
            _ => self.summary.warn += 1,
        }
    }
}

pub fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Run one full inspection: file integrity vs. baseline, process blocklist /
/// allowlist, and listening-port allowlist. Observation only — never kills
/// processes or modifies files.
pub fn run_scan(cfg: &Config, baseline: Option<&Baseline>) -> ScanResult {
    let mut result = ScanResult::new();

    // 1. File integrity
    if cfg.watch.paths.is_empty() {
        result.push(
            "config",
            "warn",
            "no watch paths configured ([watch].paths is empty)",
        );
    } else {
        match baseline {
            Some(b) => {
                let report = baseline::check(cfg, b);
                for warning in &report.warnings {
                    result.push("walk_warning", "warn", warning.clone());
                }
                for path in &report.added {
                    result.push("file_added", "warn", format!("added: {path}"));
                }
                for path in &report.removed {
                    result.push("file_removed", "warn", format!("removed: {path}"));
                }
                for path in &report.modified {
                    result.push("file_modified", "warn", format!("modified: {path}"));
                }
            }
            None => {
                let walk = collect_files(&cfg.watch.paths, &cfg.watch.exclude);
                for warning in &walk.warnings {
                    result.push("walk_warning", "warn", warning.clone());
                }
                result.push(
                    "baseline_missing",
                    "warn",
                    "no baseline found; run `adonword baseline update` first",
                );
            }
        }
    }

    // 2. Processes (blocklist -> crit, allowlist -> warn when non-empty)
    let processes = collect_processes();
    let mut blocked_seen: HashSet<String> = HashSet::new();
    for (name, pid) in &processes {
        if name_matches(name, &cfg.process.blocklist) && blocked_seen.insert(name.to_lowercase()) {
            result.push(
                "blocked_process",
                "crit",
                format!("blocked process is running: {name} (pid {pid})"),
            );
        }
    }
    if !cfg.process.allowlist.is_empty() {
        let mut allow_seen: HashSet<String> = HashSet::new();
        for (name, pid) in &processes {
            if name_matches(name, &cfg.process.blocklist) {
                continue; // already reported as blocked
            }
            if !name_matches(name, &cfg.process.allowlist) && allow_seen.insert(name.to_lowercase())
            {
                result.push(
                    "unallowlisted_process",
                    "warn",
                    format!("process outside allowlist: {name} (pid {pid})"),
                );
            }
        }
    }

    // 3. Listening ports
    if cfg.ports.alert_unlisted {
        match collect_listening_tcp() {
            Ok(sockets) => {
                let (allowed, warnings) = crate::config::expand_ports(&cfg.ports.allowed);
                for warning in warnings {
                    result.push("config", "warn", warning);
                }
                for socket in sockets.values() {
                    if !allowed.contains(&socket.port) {
                        let pid_part = socket
                            .pid
                            .map(|p| format!(" (pid {p})"))
                            .unwrap_or_default();
                        result.push(
                            "unlisted_port",
                            "warn",
                            format!("listening on {}:{}{}", socket.addr, socket.port, pid_part),
                        );
                    }
                }
            }
            Err(e) => result.push(
                "port_scan_error",
                "warn",
                format!("failed to enumerate listening ports: {e}"),
            ),
        }
    }

    result
}

// ---------------------------------------------------------------------------
// File walking
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FileEntry {
    pub abs: std::path::PathBuf,
    pub mtime_ms: i64,
}

#[derive(Debug, Default)]
pub struct WalkResult {
    pub files: BTreeMap<String, FileEntry>,
    pub warnings: Vec<String>,
}

/// Recursively collect regular files under the watch roots.
///
/// - Keys are the path relative to the watch root with `/` separators. With
///   more than one root the (normalized) root path prefixes the key to avoid
///   collisions.
/// - `target/`, `node_modules/` and `.git/` are always skipped; extra excludes
///   come from `[watch].exclude` (glob, matched against file/dir names).
/// - Symlinks and unreadable paths are skipped and recorded as warnings.
pub fn collect_files(paths: &[String], extra_excludes: &[String]) -> WalkResult {
    let mut files = BTreeMap::new();
    let mut warnings = Vec::new();
    let mut excludes: Vec<String> = crate::config::DEFAULT_EXCLUDES
        .iter()
        .map(|s| s.to_string())
        .collect();
    excludes.extend(extra_excludes.iter().cloned());
    let multi_root = paths.len() > 1;

    for raw in paths {
        let root = Path::new(raw);
        let canonical = match root.canonicalize() {
            Ok(c) => c,
            Err(e) => {
                warnings.push(format!("watch path {raw} is not accessible: {e}"));
                continue;
            }
        };
        let meta = match fs::metadata(&canonical) {
            Ok(m) => m,
            Err(e) => {
                warnings.push(format!("cannot stat watch path {raw}: {e}"));
                continue;
            }
        };
        if meta.is_file() {
            let rel = path_string(&canonical);
            match mtime_ms(&meta) {
                Ok(ms) => {
                    files.entry(rel).or_insert_with(|| FileEntry {
                        abs: canonical.clone(),
                        mtime_ms: ms,
                    });
                }
                Err(e) => warnings.push(format!("cannot read mtime for {raw}: {e}")),
            }
            continue;
        }
        if !meta.is_dir() {
            warnings.push(format!("watch path {raw} is not a file or directory"));
            continue;
        }

        let dir_excludes = excludes.clone();
        let walker = WalkDir::new(&canonical)
            .follow_links(false)
            .into_iter()
            .filter_entry(move |entry| {
                if entry.depth() == 0 {
                    return true;
                }
                let name = entry.file_name().to_string_lossy();
                !dir_excludes
                    .iter()
                    .any(|pattern| glob_match(pattern, &name))
            });
        for entry in walker {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    warnings.push(format!("skipped unreadable path under {raw}: {e}"));
                    continue;
                }
            };
            let file_type = entry.file_type();
            if file_type.is_symlink() {
                warnings.push(format!("skipping symlink {}", path_string(entry.path())));
                continue;
            }
            if !file_type.is_file() {
                continue; // directory
            }
            let rel_body = entry
                .path()
                .strip_prefix(&canonical)
                .unwrap_or_else(|_| entry.path())
                .to_string_lossy()
                .replace('\\', "/");
            let rel = if multi_root {
                format!("{}/{}", path_string(&canonical), rel_body)
            } else {
                rel_body
            };
            match entry.metadata() {
                Ok(meta) => match mtime_ms(&meta) {
                    Ok(ms) => {
                        files.entry(rel).or_insert_with(|| FileEntry {
                            abs: entry.path().to_path_buf(),
                            mtime_ms: ms,
                        });
                    }
                    Err(e) => warnings.push(format!(
                        "cannot read mtime for {}: {e}",
                        path_string(entry.path())
                    )),
                },
                Err(e) => warnings.push(format!("cannot stat {}: {e}", path_string(entry.path()))),
            }
        }
    }

    WalkResult { files, warnings }
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn mtime_ms(meta: &fs::Metadata) -> anyhow::Result<i64> {
    let duration = meta.modified()?.duration_since(UNIX_EPOCH)?;
    Ok(i64::try_from(duration.as_millis()).unwrap_or(i64::MAX))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Process matching
// ---------------------------------------------------------------------------

/// Case-insensitive matching with `*` glob support.
pub fn name_matches(name: &str, patterns: &[String]) -> bool {
    let lower = name.to_lowercase();
    patterns
        .iter()
        .any(|p| glob_match(&p.to_lowercase(), &lower))
}

/// Minimal glob: `*` matches any sequence (including empty); everything else
/// is literal.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    match pattern.split_once('*') {
        Some((prefix, rest)) => {
            if !text.starts_with(prefix) {
                return false;
            }
            let tail = &text[prefix.len()..];
            let mut boundaries = std::iter::once(0).chain(tail.char_indices().map(|(i, _)| i + 1));
            boundaries.any(|i| glob_match(rest, &tail[i..]))
        }
        None => pattern == text,
    }
}

/// Snapshot of (process name, pid) pairs for all running processes.
pub fn collect_processes() -> Vec<(String, u32)> {
    let mut system = sysinfo::System::new();
    system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    let mut out = Vec::new();
    for (pid, process) in system.processes() {
        let name = process.name().to_string_lossy().trim().to_string();
        if !name.is_empty() {
            out.push((name, pid.as_u32()));
        }
    }
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// Listening ports
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ListeningSocket {
    pub addr: String,
    pub port: u16,
    pub pid: Option<u32>,
}

/// Enumerate TCP sockets in LISTEN state (one entry per local port).
pub fn collect_listening_tcp() -> anyhow::Result<BTreeMap<u16, ListeningSocket>> {
    use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState};

    let af = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto = ProtocolFlags::TCP;
    let sockets = netstat2::get_sockets_info(af, proto)?;
    let mut out: BTreeMap<u16, ListeningSocket> = BTreeMap::new();
    for socket in sockets {
        if let ProtocolSocketInfo::Tcp(tcp) = socket.protocol_socket_info {
            if tcp.state != TcpState::Listen {
                continue;
            }
            out.entry(tcp.local_port)
                .or_insert_with(|| ListeningSocket {
                    addr: tcp.local_addr.to_string(),
                    port: tcp.local_port,
                    pid: socket.associated_pids.first().copied(),
                });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_match_supports_wildcards() {
        assert!(glob_match("keylog*", "keylogger.exe"));
        assert!(glob_match("*logger.exe", "keylogger.exe"));
        assert!(glob_match("a*b*c", "aXXbYYc"));
        assert!(!glob_match("a*b*c", "aXXbYY"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "exactx"));
        assert!(glob_match(".*", ".hidden"));
        assert!(!glob_match(".*", "visible.txt"));
        assert!(glob_match("*", "anything"));
    }

    #[test]
    fn name_matches_is_case_insensitive_with_globs() {
        let exact = vec!["keylogger.exe".to_string()];
        assert!(name_matches("KEYLOGGER.EXE", &exact));
        assert!(!name_matches("explorer.exe", &exact));
        let wild = vec!["keylog*".to_string()];
        assert!(name_matches("KeyloggerX", &wild));
        assert!(!name_matches("Keychain", &wild));
        assert!(name_matches("anything", &["*".to_string()]));
    }

    #[cfg(unix)]
    #[test]
    fn walk_skips_excluded_dirs_and_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"hello").unwrap();
        fs::write(dir.path().join(".hidden"), b"h").unwrap();
        for excluded in ["target", ".git", "node_modules"] {
            let sub = dir.path().join(excluded);
            fs::create_dir_all(&sub).unwrap();
            fs::write(sub.join("payload.bin"), b"x").unwrap();
        }
        std::os::unix::fs::symlink(dir.path().join("a.txt"), dir.path().join("link.txt")).unwrap();

        let res = collect_files(&[dir.path().to_string_lossy().to_string()], &[]);
        let names: Vec<&str> = res.files.keys().map(|s| s.as_str()).collect();
        assert_eq!(names, vec![".hidden", "a.txt"], "walk result: {names:?}");
        assert!(
            res.warnings.iter().any(|w| w.contains("skipping symlink")),
            "warnings: {:?}",
            res.warnings
        );
    }

    #[test]
    fn walk_honors_extra_excludes_and_keeps_hidden_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".secret"), b"s").unwrap();
        fs::write(dir.path().join("keep.txt"), b"k").unwrap();
        fs::write(dir.path().join("drop.log"), b"d").unwrap();

        let res = collect_files(
            &[dir.path().to_string_lossy().to_string()],
            &["*.log".to_string()],
        );
        let names: Vec<&str> = res.files.keys().map(|s| s.as_str()).collect();
        assert_eq!(names, vec![".secret", "keep.txt"]);
    }

    #[test]
    fn scan_flags_missing_baseline_and_unlisted_ports() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"x").unwrap();
        let cfg = Config {
            watch: crate::config::WatchConfig {
                paths: vec![dir.path().to_string_lossy().to_string()],
                exclude: vec![],
            },
            process: crate::config::ProcessConfig::default(),
            ports: crate::config::PortsConfig {
                allowed: vec![],
                alert_unlisted: true,
            },
            alert: crate::config::AlertConfig::default(),
        };
        let result = run_scan(&cfg, None);
        assert!(result.findings.iter().any(|f| f.kind == "baseline_missing"));
        // There is always at least one listening socket on a real system.
        assert!(result.findings.iter().any(|f| f.kind == "unlisted_port"));
        assert_eq!(result.summary.total, result.findings.len());
    }
}
