//! Capture-file discovery helpers — sibling concern to the writer/reader.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::io_err;
use crate::error::Result;

#[derive(Debug, Clone)]
pub struct CaptureFile {
    pub path: PathBuf,
    pub name: String,
    pub size: u64,
    pub mtime: SystemTime,
}

/// List `*.{ext}` files in `dir`, sorted by mtime descending (newest
/// first). Missing directory is treated as empty, not an error.
pub fn list_captures(dir: &Path, ext: &str) -> Result<Vec<CaptureFile>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| io_err(&format!("readdir {dir:?}"), e))? {
        let entry = entry.map_err(|e| io_err("dirent", e))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some(ext) {
            continue;
        }
        let meta = entry.metadata().map_err(|e| io_err("stat", e))?;
        out.push(CaptureFile {
            name: path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string(),
            path: path.clone(),
            size: meta.len(),
            mtime: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
        });
    }
    out.sort_by_key(|cf| std::cmp::Reverse(cf.mtime));
    Ok(out)
}

/// `{dir}/{prefix}-YYYYMMDD-HHMMSS.{ext}` in local time. Caller-supplied
/// prefix + extension so a consumer's capture files look distinct from
/// any other fridge consumer sharing the dir.
pub fn timestamped_path(dir: &Path, prefix: &str, ext: &str) -> PathBuf {
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    dir.join(format!("{prefix}-{stamp}.{ext}"))
}
