use crate::config::Config;
use crate::engine::{collect_files, now_rfc3339, sha256_hex, FileEntry};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub version: u32,
    pub generated_at: String,
    pub entries: BTreeMap<String, BaselineEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEntry {
    /// sha256 hex digest of the file content
    pub hash: String,
    /// modification time in milliseconds since the Unix epoch
    pub mtime_ms: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CheckReport {
    /// "clean" | "changed" | "missing"
    pub status: String,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub modified: Vec<String>,
    pub warnings: Vec<String>,
}

pub fn baseline_path(data_dir: &Path) -> PathBuf {
    data_dir.join("baseline.json")
}

pub fn load(data_dir: &Path) -> Result<Option<Baseline>> {
    let path = baseline_path(data_dir);
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(&path)
        .with_context(|| format!("failed to read baseline {}", path.display()))?;
    let baseline: Baseline = serde_json::from_str(&text)
        .with_context(|| format!("failed to parse baseline {}", path.display()))?;
    Ok(Some(baseline))
}

/// Recompute the full sha256 baseline for `[watch].paths` and persist it to
/// `<data_dir>/baseline.json`. Returns the baseline plus walk warnings.
pub fn update(cfg: &Config, data_dir: &Path) -> Result<(Baseline, Vec<String>)> {
    let walk = collect_files(&cfg.watch.paths, &cfg.watch.exclude);
    let mut entries = BTreeMap::new();
    let mut warnings = walk.warnings;
    for (rel, entry) in &walk.files {
        match fs::read(&entry.abs) {
            Ok(bytes) => {
                entries.insert(
                    rel.clone(),
                    BaselineEntry {
                        hash: sha256_hex(&bytes),
                        mtime_ms: entry.mtime_ms,
                    },
                );
            }
            Err(e) => warnings.push(format!("skipping unreadable file {rel}: {e}")),
        }
    }
    let baseline = Baseline {
        version: 1,
        generated_at: now_rfc3339(),
        entries,
    };
    fs::create_dir_all(data_dir)
        .with_context(|| format!("failed to create data dir {}", data_dir.display()))?;
    let path = baseline_path(data_dir);
    fs::write(&path, serde_json::to_vec_pretty(&baseline)?)
        .with_context(|| format!("failed to write baseline {}", path.display()))?;
    Ok((baseline, warnings))
}

/// Compare the current file tree against a baseline. Every current file is
/// re-hashed (mtime is stored for information only, never trusted).
pub fn check(cfg: &Config, baseline: &Baseline) -> CheckReport {
    let walk = collect_files(&cfg.watch.paths, &cfg.watch.exclude);
    let mut warnings = walk.warnings;
    let mut current: BTreeMap<String, String> = BTreeMap::new();
    for (rel, FileEntry { abs, .. }) in &walk.files {
        match fs::read(abs) {
            Ok(bytes) => {
                current.insert(rel.clone(), sha256_hex(&bytes));
            }
            Err(e) => warnings.push(format!("skipping unreadable file {rel}: {e}")),
        }
    }

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut modified = Vec::new();
    for (rel, hash) in &current {
        match baseline.entries.get(rel) {
            None => added.push(rel.clone()),
            Some(entry) => {
                if entry.hash != *hash {
                    modified.push(rel.clone());
                }
            }
        }
    }
    for rel in baseline.entries.keys() {
        if !current.contains_key(rel) {
            removed.push(rel.clone());
        }
    }

    let status = if added.is_empty() && removed.is_empty() && modified.is_empty() {
        "clean"
    } else {
        "changed"
    };
    CheckReport {
        status: status.to_string(),
        added,
        removed,
        modified,
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WatchConfig;

    fn test_cfg(dir: &Path) -> Config {
        Config {
            watch: WatchConfig {
                paths: vec![dir.to_string_lossy().to_string()],
                exclude: vec![],
            },
            ..Config::default()
        }
    }

    #[test]
    fn update_and_check_roundtrip() {
        let watch = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        fs::write(watch.path().join("f.txt"), b"v1").unwrap();
        fs::create_dir_all(watch.path().join("sub")).unwrap();
        fs::write(watch.path().join("sub/g.txt"), b"g1").unwrap();
        let cfg = test_cfg(watch.path());

        let (baseline, warnings) = update(&cfg, data.path()).unwrap();
        assert!(warnings.is_empty(), "warnings: {warnings:?}");
        assert_eq!(baseline.entries.len(), 2);
        assert!(data.path().join("baseline.json").exists());

        let report = check(&cfg, &baseline);
        assert_eq!(report.status, "clean");
        assert!(report.added.is_empty() && report.removed.is_empty() && report.modified.is_empty());

        // tamper: modify content
        fs::write(watch.path().join("f.txt"), b"tampered").unwrap();
        let report = check(&cfg, &baseline);
        assert_eq!(report.modified, vec!["f.txt".to_string()]);

        // add a file
        fs::write(watch.path().join("new.txt"), b"n").unwrap();
        let report = check(&cfg, &baseline);
        assert!(report.added.contains(&"new.txt".to_string()));

        // remove a file
        fs::remove_file(watch.path().join("sub/g.txt")).unwrap();
        let report = check(&cfg, &baseline);
        assert!(report.removed.contains(&"sub/g.txt".to_string()));

        // same content as baseline but rewritten (hash identical, mtime changed) -> not modified
        fs::write(watch.path().join("f.txt"), b"v1").unwrap();
        let report = check(&cfg, &baseline);
        assert!(!report.modified.contains(&"f.txt".to_string()));
    }
}
