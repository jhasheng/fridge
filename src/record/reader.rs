//! Streaming + whole-file readers.
//!
//! [`read_iter`] is the primitive: open + verify header + return an
//! `Iterator<Item = Result<M>>`. The whole-file conveniences
//! ([`read_all`], [`read_all_with_progress`]) are thin wrappers on top.
//! Reach for `read_iter` whenever the capture might be larger than you
//! want to materialize into memory.

use std::fs::File;
use std::io::{BufReader, ErrorKind, Read};
use std::marker::PhantomData;
use std::path::Path;

use bincode::config::standard;
use bincode::serde::decode_from_slice;
use serde::de::DeserializeOwned;

use super::{bincode_err, io_err, HEADER_LEN, MAGIC, MAX_FRAME_BYTES, VERSION};
use crate::error::{Error, Result};

/// Open `path`, verify the header (magic + version + tag), and return an
/// iterator over decoded entries. Each `next()` reads one length-framed
/// entry; a truncated trailing frame ends iteration without an error
/// (interrupted writer is non-fatal).
///
/// Header errors (bad magic, wrong version, tag mismatch) are returned
/// from this function — the iterator itself only fails on per-entry
/// decode / IO problems.
pub fn read_iter<M: DeserializeOwned>(path: &Path, tag: [u8; 4]) -> Result<ReadIter<M>> {
    let file = File::open(path).map_err(|e| io_err(&format!("open {path:?}"), e))?;
    let mut file = BufReader::new(file);

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

    Ok(ReadIter {
        file,
        bytes_read: HEADER_LEN,
        frame_idx: 0,
        done: false,
        _m: PhantomData,
    })
}

/// Iterator yielded by [`read_iter`]. Pulls + decodes one frame per
/// `next()`. End-of-file (clean or truncated) returns `None`; a partial
/// IO read or a bincode decode error returns `Some(Err(_))` and then
/// `None` on the next call.
pub struct ReadIter<M> {
    file: BufReader<File>,
    bytes_read: u64,
    frame_idx: usize,
    done: bool,
    _m: PhantomData<fn() -> M>,
}

impl<M> ReadIter<M> {
    /// Total bytes consumed so far (header + every successfully read
    /// entry). Pair with `std::fs::metadata(path)?.len()` if you want
    /// to display progress.
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }
}

impl<M: DeserializeOwned> Iterator for ReadIter<M> {
    type Item = Result<M>;

    fn next(&mut self) -> Option<Result<M>> {
        if self.done {
            return None;
        }
        let mut len_bytes = [0u8; 4];
        match self.file.read_exact(&mut len_bytes) {
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                self.done = true;
                return None;
            }
            Err(e) => {
                self.done = true;
                return Some(Err(io_err("read len", e)));
            }
        }
        let len = u32::from_le_bytes(len_bytes) as usize;
        if len > MAX_FRAME_BYTES {
            self.done = true;
            return Some(Err(Error::Record(format!(
                "frame too large: {len} bytes (cap {MAX_FRAME_BYTES}); file likely corrupt"
            ))));
        }
        let mut buf = vec![0u8; len];
        if let Err(e) = self.file.read_exact(&mut buf) {
            // Partial trailing frame — writer was interrupted. End cleanly.
            if e.kind() == ErrorKind::UnexpectedEof {
                self.done = true;
                return None;
            }
            self.done = true;
            return Some(Err(io_err("read body", e)));
        }
        let decoded: std::result::Result<(M, usize), _> = decode_from_slice(&buf, standard());
        let (msg, _) = match decoded {
            Ok(p) => p,
            Err(e) => {
                self.done = true;
                return Some(Err(bincode_err(
                    &format!("decode at frame#{}", self.frame_idx),
                    e,
                )));
            }
        };
        self.frame_idx += 1;
        self.bytes_read += 4 + len as u64;
        Some(Ok(msg))
    }
}

/// Read the whole capture into a `Vec<M>`. Built on top of [`read_iter`];
/// for files larger than what fits comfortably in RAM, reach for
/// [`read_iter`] directly instead.
pub fn read_all<M: DeserializeOwned>(path: &Path, tag: [u8; 4]) -> Result<Vec<M>> {
    read_iter::<M>(path, tag)?.collect()
}

/// Same as [`read_all`] but invokes `on_progress(read_bytes, total_bytes)`
/// periodically (throttled to ~64 KiB) so a loader running on a worker
/// thread can push updates to the UI without flooding the channel.
pub fn read_all_with_progress<M, F>(path: &Path, tag: [u8; 4], mut on_progress: F) -> Result<Vec<M>>
where
    M: DeserializeOwned,
    F: FnMut(u64, u64),
{
    let total_bytes = std::fs::metadata(path)
        .map_err(|e| io_err(&format!("stat {path:?}"), e))?
        .len();
    let mut iter = read_iter::<M>(path, tag)?;
    on_progress(iter.bytes_read(), total_bytes);
    let mut last_progress = iter.bytes_read();

    let mut out = Vec::new();
    // `while let` instead of `for` so the implicit `IntoIterator` borrow
    // is released between rounds — we need `iter.bytes_read()` between
    // each `next()` to drive the throttled progress callback.
    while let Some(item) = iter.next() {
        out.push(item?);
        let now = iter.bytes_read();
        if now - last_progress >= 65_536 {
            on_progress(now, total_bytes);
            last_progress = now;
        }
    }
    on_progress(iter.bytes_read(), total_bytes);
    Ok(out)
}
