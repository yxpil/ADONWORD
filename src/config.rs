use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::{env, fs};

/// Directories that are always skipped while walking watch roots.
pub const DEFAULT_EXCLUDES: &[&str] = &["target", "node_modules", ".git"];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WatchConfig {
    pub paths: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProcessConfig {
    #[serde(default)]
    pub blocklist: Vec<String>,
    #[serde(default)]
    pub allowlist: Vec<String>,
}

/// A single entry of `[ports].allowed`: either a bare port number or an
/// inclusive range written as a string, e.g. `"8000-8100"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PortSpec {
    Port(u16),
    Range(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PortsConfig {
    #[serde(default)]
    pub allowed: Vec<PortSpec>,
    #[serde(default = "default_true")]
    pub alert_unlisted: bool,
}

impl Default for PortsConfig {
    fn default() -> Self {
        Self {
            allowed: vec![
                PortSpec::Port(8751),
                PortSpec::Port(8752),
                PortSpec::Port(8753),
                PortSpec::Port(8754),
                PortSpec::Port(8755),
            ],
            alert_unlisted: true,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertConfig {
    #[serde(default)]
    pub webhook_url: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    #[serde(default)]
    pub watch: WatchConfig,
    #[serde(default)]
    pub process: ProcessConfig,
    #[serde(default)]
    pub ports: PortsConfig,
    #[serde(default)]
    pub alert: AlertConfig,
}

fn default_true() -> bool {
    true
}

/// Expand port specs (single values and inclusive `"start-end"` ranges) into a
/// set of ports. Malformed entries are reported as warnings instead of failing.
pub fn expand_ports(specs: &[PortSpec]) -> (BTreeSet<u16>, Vec<String>) {
    let mut ports = BTreeSet::new();
    let mut warnings = Vec::new();
    for spec in specs {
        match spec {
            PortSpec::Port(p) => {
                ports.insert(*p);
            }
            PortSpec::Range(text) => match parse_range(text) {
                Ok(range) => ports.extend(range),
                Err(e) => warnings.push(format!("invalid port range '{text}': {e}")),
            },
        }
    }
    (ports, warnings)
}

fn parse_range(text: &str) -> Result<Vec<u16>> {
    let (start_s, end_s) = text
        .split_once('-')
        .context("expected format 'start-end', e.g. '8000-8100'")?;
    let start: u16 = start_s
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("'{}' is not a valid port", start_s.trim()))?;
    let end: u16 = end_s
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("'{}' is not a valid port", end_s.trim()))?;
    if start > end {
        bail!("start port {start} is greater than end port {end}");
    }
    Ok((start..=end).collect())
}

/// Resolve the data directory: `ADONWORD_DATA_DIR` env override, otherwise
/// `~/.adonword`.
pub fn data_dir() -> PathBuf {
    if let Ok(dir) = env::var("ADONWORD_DATA_DIR") {
        if !dir.trim().is_empty() {
            return PathBuf::from(dir);
        }
    }
    let home = home::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".adonword")
}

/// Load the effective config: `--config` file (required when given) or
/// `<data_dir>/adonword.toml` (defaults with a warning when absent), then merge
/// the piped-stdin JSON object over it (stdin wins).
pub fn load_effective(explicit: Option<&Path>, stdin: Option<&Value>) -> Result<(Config, PathBuf)> {
    let dir = data_dir();
    let path = match explicit {
        Some(p) => p.to_path_buf(),
        None => dir.join("adonword.toml"),
    };
    let mut cfg: Config = if path.exists() {
        let text = fs::read_to_string(&path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        toml::from_str(&text)
            .with_context(|| format!("failed to parse config file {}", path.display()))?
    } else if explicit.is_some() {
        bail!("config file not found: {}", path.display());
    } else {
        eprintln!(
            "warning: no config file at {}; using defaults",
            path.display()
        );
        Config::default()
    };
    if let Some(v) = stdin {
        cfg = apply_config_overrides(cfg, v)?;
    }
    Ok((cfg, dir))
}

/// Deep-merge the `watch` / `process` / `ports` / `alert` sections of the stdin
/// JSON object over the config loaded from TOML (stdin wins).
pub fn apply_config_overrides(cfg: Config, stdin: &Value) -> Result<Config> {
    let mut tree = serde_json::to_value(&cfg).context("failed to serialize current config")?;
    let mut overrides = serde_json::Map::new();
    for key in ["watch", "process", "ports", "alert"] {
        if let Some(section) = stdin.get(key) {
            overrides.insert(key.to_string(), section.clone());
        }
    }
    merge_value(&mut tree, Value::Object(overrides));
    serde_json::from_value(tree).context("failed to apply stdin config overrides")
}

fn merge_value(target: &mut Value, patch: Value) {
    match (target, patch) {
        (Value::Object(target), Value::Object(patch)) => {
            for (key, value) in patch {
                match target.get_mut(&key) {
                    Some(slot) => merge_value(slot, value),
                    None => {
                        target.insert(key, value);
                    }
                }
            }
        }
        (target, patch) => *target = patch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_alert_unlisted_true() {
        let cfg: Config = toml::from_str("").unwrap();
        assert!(cfg.ports.alert_unlisted);
        assert!(cfg.watch.paths.is_empty());
        assert!(cfg.process.blocklist.is_empty());
        assert_eq!(cfg.ports.allowed.len(), 5);
    }

    #[test]
    fn parse_full_config() {
        let text = r#"
[watch]
paths = ["/tmp/a", "/tmp/b"]
exclude = [".*"]

[process]
blocklist = ["keylogger.exe"]
allowlist = []

[ports]
allowed = [8751, "8000-8100"]
alert_unlisted = false

[alert]
webhook_url = "http://example.com/hook"
"#;
        let cfg: Config = toml::from_str(text).unwrap();
        assert_eq!(cfg.watch.paths, vec!["/tmp/a", "/tmp/b"]);
        assert_eq!(cfg.watch.exclude, vec![".*"]);
        assert_eq!(cfg.process.blocklist, vec!["keylogger.exe"]);
        assert!(!cfg.ports.alert_unlisted);
        assert_eq!(cfg.ports.allowed.len(), 2);
        assert_eq!(cfg.alert.webhook_url, "http://example.com/hook");
    }

    #[test]
    fn expand_ports_single_range_mixed() {
        let specs = vec![
            PortSpec::Port(8751),
            PortSpec::Range("8000-8100".to_string()),
            PortSpec::Port(9001),
        ];
        let (ports, warnings) = expand_ports(&specs);
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        assert_eq!(ports.len(), 103); // 8751 + 8000..=8100 (101) + 9001
        assert!(ports.contains(&8751));
        assert!(ports.contains(&8000));
        assert!(ports.contains(&8100));
        assert!(ports.contains(&9001));
    }

    #[test]
    fn expand_ports_deduplicates_overlaps() {
        let specs = vec![
            PortSpec::Port(8754),
            PortSpec::Range("8750-8760".to_string()),
        ];
        let (ports, warnings) = expand_ports(&specs);
        assert!(warnings.is_empty());
        assert_eq!(ports.len(), 11);
    }

    #[test]
    fn expand_ports_invalid_entries_warn() {
        let specs = vec![
            PortSpec::Range("abc".to_string()),
            PortSpec::Range("10-5".to_string()),
        ];
        let (ports, warnings) = expand_ports(&specs);
        assert!(ports.is_empty());
        assert_eq!(warnings.len(), 2);
    }

    #[test]
    fn stdin_overrides_replace_sections_and_keep_defaults() {
        let cfg = Config::default();
        let stdin: Value = serde_json::from_str(r#"{"watch":{"paths":["/tmp/x"]}}"#).unwrap();
        let merged = apply_config_overrides(cfg, &stdin).unwrap();
        assert_eq!(merged.watch.paths, vec!["/tmp/x"]);
        assert!(merged.ports.alert_unlisted);
        assert_eq!(merged.ports.allowed.len(), 5);
    }
}
