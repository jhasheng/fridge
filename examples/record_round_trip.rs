//! Smoke / demo for `fridge::record` — no frida session needed.
//!
//! Writes 100 typed messages to a tempdir, reads them back via
//! `read_iter`, and asserts equality. Useful as:
//!
//!   1. End-to-end check that the `record` API + bincode round-trip
//!      stay consistent across upgrades.
//!   2. Reference for downstream consumers — copy the shape, swap
//!      your own `M` in.
//!
//! Run with: `cargo run --example record_round_trip`

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use fridge::record::{list_captures, read_iter, timestamped_path, Writer};

/// Consumer tag — pick 4 bytes from your crate name so other fridge
/// consumers sharing the dir can't accidentally decode your files.
const TAG: [u8; 4] = *b"DEMO";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct DemoMsg {
    seq: u64,
    label: String,
    body: Vec<u8>,
}

fn make(seq: u64) -> DemoMsg {
    DemoMsg {
        seq,
        label: format!("event-{seq}"),
        body: (0..16).map(|i| ((seq + i) & 0xFF) as u8).collect(),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Throwaway dir; the OS reaps tmp eventually but we also rm it at end.
    let dir = std::env::temp_dir().join("fridge-record-round-trip");
    fs::create_dir_all(&dir)?;

    let path: PathBuf = timestamped_path(&dir, "demo", "bin");
    eprintln!("writing 100 entries to {}", path.display());

    // ── Write ────────────────────────────────────────────────────────
    let mut w = Writer::<DemoMsg>::create(path.clone(), TAG)?;
    for i in 0..100 {
        w.append(&make(i))?;
    }
    drop(w);

    // ── Discover ─────────────────────────────────────────────────────
    let listed = list_captures(&dir, "bin")?;
    eprintln!("list_captures saw {} file(s)", listed.len());
    assert!(listed.iter().any(|cf| cf.path == path));

    // ── Read (streaming) ─────────────────────────────────────────────
    let mut iter = read_iter::<DemoMsg>(&path, TAG)?;
    let mut n = 0u64;
    for item in iter.by_ref() {
        let got = item?;
        assert_eq!(got, make(n), "round-trip mismatch at {n}");
        n += 1;
    }
    assert_eq!(n, 100);
    eprintln!(
        "round-trip OK · {n} entries · {} bytes read",
        iter.bytes_read()
    );

    // ── Cleanup ──────────────────────────────────────────────────────
    fs::remove_dir_all(&dir)?;
    Ok(())
}
