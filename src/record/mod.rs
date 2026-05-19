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
//!
//! ### Sub-module layout
//!
//! - [`writer`] — `Writer<M>` (append-only file).
//! - [`reader`] — `read_all<M>` + `read_all_with_progress<M, F>`.
//! - [`listing`] — `list_captures` + `timestamped_path` + `CaptureFile`.
//!
//! All three are re-exported here, so `use fridge::record::Writer` /
//! `use fridge::record::read_all` work without naming the sub-module.

mod listing;
mod reader;
mod writer;

pub use listing::{list_captures, timestamped_path, CaptureFile};
pub use reader::{read_all, read_all_with_progress};
pub use writer::Writer;

use crate::error::Error;

// Shared header constants + error helpers — `pub(super)` so the three
// sub-modules can reach them, not pub so they stay invisible to users.

pub(super) const MAGIC: [u8; 4] = *b"FRGE";
pub(super) const VERSION: u32 = 1;
pub(super) const HEADER_LEN: u64 = (MAGIC.len() + 4 + 4) as u64;

/// Hard cap on a single entry's encoded byte count. A malformed or
/// adversarial length prefix could otherwise drive a `vec![0u8; len]`
/// of up to 4 GiB before the actual read fails. 16 MiB is generous —
/// frida send payloads in practice are KB-scale; if you hit this on
/// legitimate data, the cap is too low and we should expose it as
/// a Writer/Reader option.
pub(super) const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

pub(super) fn io_err(ctx: &str, e: std::io::Error) -> Error {
    Error::Record(format!("{ctx}: {e}"))
}

pub(super) fn bincode_err(ctx: &str, e: impl std::fmt::Display) -> Error {
    Error::Record(format!("{ctx}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::fs::OpenOptions;
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
    fn oversize_frame_errors_not_panics() {
        // Header valid; len prefix = u32::MAX → if we just trusted it
        // we'd `vec![0u8; 4_294_967_295]` and OOM. The reader should
        // refuse cleanly before any allocation.
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("huge.bin");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"FRGE");
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&TEST_TAG);
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        std::fs::write(&path, &bytes).unwrap();
        let err = read_all::<TestMsg>(&path, TEST_TAG).unwrap_err();
        assert!(
            format!("{err}").contains("frame too large"),
            "expected size-cap error, got: {err}"
        );
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
