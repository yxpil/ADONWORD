use crate::engine::ScanResult;
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

pub fn state_path(data_dir: &Path) -> PathBuf {
    data_dir.join("state.json")
}

/// Persist the latest scan result to `<data_dir>/state.json`.
pub fn save_scan(data_dir: &Path, result: &ScanResult) -> Result<()> {
    fs::create_dir_all(data_dir)
        .with_context(|| format!("failed to create data dir {}", data_dir.display()))?;
    let path = state_path(data_dir);
    fs::write(&path, serde_json::to_vec_pretty(result)?)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

pub fn load_scan(data_dir: &Path) -> Result<Option<ScanResult>> {
    let path = state_path(data_dir);
    if !path.exists() {
        return Ok(None);
    }
    let text =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let result: ScanResult = serde_json::from_str(&text)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(Some(result))
}
