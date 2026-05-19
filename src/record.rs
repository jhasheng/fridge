//! Length-framed bincode capture format — record / replay any
//! `Serialize`-able message type that a fridge consumer produces.
//!
//! File layout:
//!
//! ```text
//! [4-byte ASCII "FRGE"][u32 LE version=1][4-byte caller tag]
//!   ([u32 LE entry_len][bincode bytes(M) of length entry_len])*
//! ```
//!
//! The 4-byte caller tag is for cross-consumer disambiguation: two
//! crates that each write `Writer<Foo>` and `Writer<Bar>` into the
//! same directory would otherwise both pass the magic check and
//! silently misdecode. Pick a tag from your crate name (e.g.
//! `*b"WCTI"` for wechat-tui inspector); readers must pass the same
//! tag and get a hard error on mismatch.
//!
//! Writer flushes after every append, so a hard crash loses at most
//! the in-flight message. Reader walks until EOF; a partial trailing
//! frame is silently dropped (interrupted append).

use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{BufReader, BufWriter, ErrorKind, Read, Write};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use bincode::config::standard;
use bincode::serde::{decode_from_slice, encode_to_vec};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::{Error, Result};

const MAGIC: [u8; 4] = *b"FRGE";
const VERSION: u32 = 1;
const HEADER_LEN: u64 = (MAGIC.len() + 4 + 4) as u64;

fn io_err(ctx: &str, e: std::io::Error) -> Error {
    Error::Record(format!("{ctx}: {e}"))
}

fn bincode_err(ctx: &str, e: impl std::fmt::Display) -> Error {
    Error::Record(format!("{ctx}: {e}"))
}

/// Streaming appender. Wraps the file in `BufWriter` so per-entry
/// framing doesn't issue 2 separate syscalls per message. The
/// `PhantomData<fn(M)>` keeps `Writer<M>: Send` regardless of `M`'s
/// own Send-ness — the writer never holds an `M` value, only encodes
/// references via the `append` call.
pub struct Writer<M: Serialize> {
    file: BufWriter<File>,
    path: PathBuf,
    _m: PhantomData<fn(M)>,
}

impl<M: Serialize> Writer<M> {
    /// Create (or truncate) a capture file and write the header.
    /// Subsequent calls to [`Writer::append`] append framed entries.
    pub fn create(path: PathBuf, tag: [u8; 4]) -> Result<Self> {
        if let Some(parent) = path.parent() {
            create_dir_all(parent)
                .map_err(|e| io_err(&format!("mkdir {parent:?}"), e))?;
        }
        let mut file = BufWriter::new(
            OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&path)
                .map_err(|e| io_err(&format!("create {path:?}"), e))?,
        );
        file.write_all(&MAGIC).map_err(|e| io_err("write magic", e))?;
        file.write_all(&VERSION.to_le_bytes())
            .map_err(|e| io_err("write version", e))?;
        file.write_all(&tag).map_err(|e| io_err("write tag", e))?;
        file.flush().map_err(|e| io_err("flush header", e))?;
        Ok(Self {
            file,
            path,
            _m: PhantomData,
        })
    }

    /// Encode `msg` and append a length-prefixed frame. Flushes per
    /// call so a crash loses at most this single message.
    pub fn append(&mut self, msg: &M) -> Result<()> {
        let bytes = encode_to_vec(msg, standard())
            .map_err(|e| bincode_err("encode", e))?;
        self.file
            .write_all(&(bytes.len() as u32).to_le_bytes())
            .map_err(|e| io_err("write len", e))?;
        self.file.write_all(&bytes).map_err(|e| io_err("write body", e))?;
        self.file.flush().map_err(|e| io_err("flush entry", e))?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::io::Write;
    use tempfile::tempdir;

    const TEST_TAG: [u8; 4] = *b"TEST";

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestMsg {
        id: u64,
        label: String,
        body: Vec<u8>,
    }

    fn sample() -> TestMsg {
        TestMsg {
            id: 42,
            label: "hello".into(),
            body: vec![1, 2, 3, 4],
        }
    }

    #[test]
    fn round_trip_single_message() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("test.bin");
        let mut w = Writer::<TestMsg>::create(path.clone(), TEST_TAG).unwrap();
        w.append(&sample()).unwrap();
        drop(w);

        let msgs: Vec<TestMsg> = read_all(&path, TEST_TAG).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0], sample());
    }

    #[test]
    fn round_trip_many_messages() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("test.bin");
        let mut w = Writer::<TestMsg>::create(path.clone(), TEST_TAG).unwrap();
        for _ in 0..100 {
            w.append(&sample()).unwrap();
        }
        drop(w);

        let msgs: Vec<TestMsg> = read_all(&path, TEST_TAG).unwrap();
        assert_eq!(msgs.len(), 100);
    }

    #[test]
    fn bad_magic_errors() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("bad.bin");
        // Wrong magic; doesn't matter what follows.
        std::fs::write(&path, b"XXXX\x01\x00\x00\x00TEST").unwrap();
        let err = read_all::<TestMsg>(&path, TEST_TAG).unwrap_err();
        assert!(format!("{err}").contains("bad magic"));
    }

    #[test]
    fn bad_version_errors() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("badver.bin");
        // FRGE + version=999 + tag.
        std::fs::write(&path, b"FRGE\xe7\x03\x00\x00TEST").unwrap();
        let err = read_all::<TestMsg>(&path, TEST_TAG).unwrap_err();
        assert!(format!("{err}").contains("unsupported capture version 999"));
    }

    #[test]
    fn wrong_tag_errors() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("wrongtag.bin");
        let mut w = Writer::<TestMsg>::create(path.clone(), *b"AAAA").unwrap();
        w.append(&sample()).unwrap();
        drop(w);
        let err = read_all::<TestMsg>(&path, *b"BBBB").unwrap_err();
        assert!(
            format!("{err}").contains("wrong consumer tag"),
            "expected tag-mismatch error, got: {err}"
        );
    }

    #[test]
    fn truncated_trailing_frame_is_tolerated() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("trunc.bin");
        let mut w = Writer::<TestMsg>::create(path.clone(), TEST_TAG).unwrap();
        w.append(&sample()).unwrap();
        drop(w);
        // Append a partial frame: length prefix says 200 bytes, no body.
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&[200u8, 0, 0, 0]).unwrap();
        drop(f);

        let msgs: Vec<TestMsg> = read_all(&path, TEST_TAG).unwrap();
        assert_eq!(
            msgs.len(),
            1,
            "partial trailing frame dropped, prior intact"
        );
    }

    #[test]
    fn list_captures_sorted_by_mtime_desc() {
        let tmp = tempdir().unwrap();
        let a = tmp.path().join("a.bin");
        let b = tmp.path().join("b.bin");
        std::fs::write(&a, b"").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(25));
        std::fs::write(&b, b"").unwrap();

        let files = list_captures(tmp.path(), "bin").unwrap();
        assert_eq!(files.len(), 2);
        assert!(files[0].mtime >= files[1].mtime);
        assert_eq!(files[0].name, "b.bin");
    }

    #[test]
    fn list_captures_filters_by_extension() {
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join("a.bin"), b"").unwrap();
        std::fs::write(tmp.path().join("ignore.txt"), b"").unwrap();
        let files = list_captures(tmp.path(), "bin").unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "a.bin");
    }

    #[test]
    fn list_captures_missing_dir_returns_empty() {
        let tmp = tempdir().unwrap();
        let nonexistent = tmp.path().join("does-not-exist");
        assert!(list_captures(&nonexistent, "bin").unwrap().is_empty());
    }

    #[test]
    fn consumer_isolation_round_trip() {
        // Two consumers in the same dir, different tags. Each can read
        // its own files but cross-reads error cleanly.
        let tmp = tempdir().unwrap();
        let a_path = tmp.path().join("a.bin");
        let b_path = tmp.path().join("b.bin");
        const TAG_A: [u8; 4] = *b"AAAA";
        const TAG_B: [u8; 4] = *b"BBBB";

        let mut wa = Writer::<TestMsg>::create(a_path.clone(), TAG_A).unwrap();
        wa.append(&TestMsg {
            id: 1,
            label: "a".into(),
            body: vec![],
        })
        .unwrap();
        drop(wa);

        let mut wb = Writer::<TestMsg>::create(b_path.clone(), TAG_B).unwrap();
        wb.append(&TestMsg {
            id: 2,
            label: "b".into(),
            body: vec![],
        })
        .unwrap();
        drop(wb);

        let listed = list_captures(tmp.path(), "bin").unwrap();
        assert_eq!(listed.len(), 2, "both files visible to list_captures");

        let ma: Vec<TestMsg> = read_all(&a_path, TAG_A).unwrap();
        assert_eq!(ma.len(), 1);
        assert_eq!(ma[0].label, "a");
        let mb: Vec<TestMsg> = read_all(&b_path, TAG_B).unwrap();
        assert_eq!(mb[0].label, "b");

        assert!(read_all::<TestMsg>(&a_path, TAG_B).is_err());
        assert!(read_all::<TestMsg>(&b_path, TAG_A).is_err());
    }

    #[test]
    fn timestamped_path_uses_prefix_and_ext() {
        let tmp = tempdir().unwrap();
        let p = timestamped_path(tmp.path(), "cap", "bin");
        let name = p.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with("cap-"), "{name}");
        assert!(name.ends_with(".bin"), "{name}");
    }
}
