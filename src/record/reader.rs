//! Whole-file reader with optional progress callback.

use std::fs::File;
use std::io::{BufReader, ErrorKind, Read};
use std::path::Path;

use bincode::config::standard;
use bincode::serde::decode_from_slice;
use serde::de::DeserializeOwned;

use super::{bincode_err, io_err, HEADER_LEN, MAGIC, MAX_FRAME_BYTES, VERSION};
use crate::error::{Error, Result};

/// Read the whole capture into a `Vec<M>`. See
/// [`read_all_with_progress`] for the streaming-progress version.
pub fn read_all<M: DeserializeOwned>(path: &Path, tag: [u8; 4]) -> Result<Vec<M>> {
    read_all_with_progress(path, tag, |_, _| {})
}

/// Same as [`read_all`] but invokes `on_progress(read_bytes, total_bytes)`
/// periodically (throttled to ~64 KiB) so a loader running on a worker
/// thread can push updates to the UI without flooding the channel.
pub fn read_all_with_progress<M, F>(
    path: &Path,
    tag: [u8; 4],
    mut on_progress: F,
) -> Result<Vec<M>>
where
    M: DeserializeOwned,
    F: FnMut(u64, u64),
{
    let total_bytes = std::fs::metadata(path)
        .map_err(|e| io_err(&format!("stat {path:?}"), e))?
        .len();
    let mut file = BufReader::new(
        File::open(path).map_err(|e| io_err(&format!("open {path:?}"), e))?,
    );
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)
        .map_err(|e| io_err("read magic", e))?;
    if magic != MAGIC {
        return Err(Error::Record(format!(
            "not a fridge capture (bad magic {magic:?})"
        )));
    }
    let mut ver_bytes = [0u8; 4];
    file.read_exact(&mut ver_bytes)
        .map_err(|e| io_err("read version", e))?;
    let version = u32::from_le_bytes(ver_bytes);
    if version != VERSION {
        return Err(Error::Record(format!(
            "unsupported capture version {version} (this build expects {VERSION})"
        )));
    }
    let mut got_tag = [0u8; 4];
    file.read_exact(&mut got_tag)
        .map_err(|e| io_err("read tag", e))?;
    if got_tag != tag {
        return Err(Error::Record(format!(
            "wrong consumer tag: file has {got_tag:?}, reader expected {tag:?}"
        )));
    }

    let mut read: u64 = HEADER_LEN;
    let mut last_progress: u64 = read;
    on_progress(read, total_bytes);

    let mut out = Vec::new();
    loop {
        let mut len_bytes = [0u8; 4];
        match file.read_exact(&mut len_bytes) {
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(io_err("read len", e)),
        }
        let len = u32::from_le_bytes(len_bytes) as usize;
        if len > MAX_FRAME_BYTES {
            return Err(Error::Record(format!(
                "frame too large: {len} bytes (cap {MAX_FRAME_BYTES}); file likely corrupt"
            )));
        }
        let mut buf = vec![0u8; len];
        if let Err(e) = file.read_exact(&mut buf) {
            if e.kind() == ErrorKind::UnexpectedEof {
                // Partial trailing frame — writer was interrupted.
                break;
            }
            return Err(io_err("read body", e));
        }
        let (msg, _): (M, usize) = decode_from_slice(&buf, standard())
            .map_err(|e| bincode_err(&format!("decode at frame#{}", out.len()), e))?;
        out.push(msg);
        read += 4 + len as u64;
        // Coalesce updates — ms-level UI doesn't care about per-frame ticks.
        if read - last_progress >= 65_536 {
            on_progress(read, total_bytes);
            last_progress = read;
        }
    }
    on_progress(read, total_bytes);
    Ok(out)
}
