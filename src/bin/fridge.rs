//! `fridge` CLI — a thin demo of the library surface.
//!
//! Two subcommands:
//!
//!   `attach`  hooks a target with a script, prints normalized events as
//!             JSON lines on stdout. With `--record` it also writes a
//!             length-framed capture file consumable by `replay`.
//!
//!   `replay`  reads a capture file and prints each event as a JSON line,
//!             so you can diff a live attach session against a stored one
//!             without re-attaching.
//!
//! Both compile only when the `cli` feature is on (and `cli` pulls in
//! `record`); pure-library users don't pay for clap / ctrlc.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::{Parser, Subcommand};
use fridge::record::Writer;
use fridge::{Capture, DetachReason, DeviceSel, Event, Handler, Target};

/// 4-byte capture-file tag used by this CLI. Captures recorded by
/// `fridge attach --record` are tagged `"FRGE"` and `fridge replay`
/// reads with the same tag. Other consumers of `fridge::record`
/// (e.g. frida-wechat-tui's `"WCTI"` files) can't be read by this
/// CLI — they'd error out on the tag check, which is the point.
const CLI_TAG: [u8; 4] = *b"FRGE";

#[derive(Parser, Debug)]
#[command(
    name = "fridge",
    about = "Thin CLI over the fridge library — attach + replay."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Attach to a process, load a script, print events.
    Attach {
        /// Process name. Picks the main process (parent-pid not same-name)
        /// when several matches exist — Chromium-style multi-process apps.
        #[arg(long)]
        target: String,
        /// Path to a `.js` source or precompiled bytecode (.bin/.qjsc/…).
        #[arg(long)]
        script: PathBuf,
        /// Optional capture file. If set, every event is also appended via
        /// `fridge::record::Writer<Event>` with the CLI's tag.
        #[arg(long)]
        record: Option<PathBuf>,
        /// Which frida device: `local` (default), `usb`, `remote:HOST:PORT`,
        /// `by-id:DEVICE_ID`.
        #[arg(long, default_value = "local")]
        device: String,
    },
    /// Read a fridge capture file and print each event as a JSON line.
    Replay {
        /// Capture file path.
        file: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Attach {
            target,
            script,
            record,
            device,
        } => run_attach(target, script, record, parse_device(&device)?),
        Cmd::Replay { file } => run_replay(file),
    }
}

fn parse_device(s: &str) -> Result<DeviceSel, Box<dyn std::error::Error>> {
    Ok(match s {
        "local" => DeviceSel::Local,
        "usb" => DeviceSel::Usb,
        s if s.starts_with("remote:") => DeviceSel::Remote(s["remote:".len()..].into()),
        s if s.starts_with("by-id:") => DeviceSel::ById(s["by-id:".len()..].into()),
        other => return Err(format!("unknown device selector: {other}").into()),
    })
}

fn run_attach(
    target: String,
    script: PathBuf,
    record: Option<PathBuf>,
    device: DeviceSel,
) -> Result<(), Box<dyn std::error::Error>> {
    let recorder: Option<Arc<Mutex<Writer<Event>>>> = match record {
        Some(path) => {
            eprintln!("recording to {}", path.display());
            Some(Arc::new(Mutex::new(Writer::create(path, CLI_TAG)?)))
        }
        None => None,
    };

    let handle = Capture::builder()
        .target(Target::main_by_name(&target))
        .device(device)
        .script_from_disk(&script)?
        .start(StdoutHandler {
            recorder: recorder.clone(),
        })?;

    eprintln!("attached pid={} · Ctrl+C to stop", handle.pid());

    // Park the main thread until Ctrl+C, then drop the handle (which
    // stop_inner()s on Drop). The recorder Writer flushes per append,
    // so even if Ctrl+C arrives mid-event the on-disk file is intact
    // up to the previous append.
    let running = Arc::new(AtomicBool::new(true));
    let r = Arc::clone(&running);
    ctrlc::set_handler(move || r.store(false, Ordering::Relaxed))?;
    while running.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(100));
    }
    eprintln!("stopping ...");
    handle.stop()?;
    Ok(())
}

fn run_replay(file: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut n: u64 = 0;
    // Stream entries one at a time so a 1 GiB capture doesn't try to
    // sit in memory all at once. Header errors surface from read_iter
    // itself; per-entry errors come through as Iterator items.
    for item in fridge::record::read_iter::<Event>(&file, CLI_TAG)? {
        emit(&mut out, &item?);
        n += 1;
    }
    eprintln!("{n} events");
    Ok(())
}

struct StdoutHandler {
    recorder: Option<Arc<Mutex<Writer<Event>>>>,
}

impl Handler for StdoutHandler {
    fn on_message(&mut self, evt: &Event, _data: Option<&[u8]>) {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        emit(&mut out, evt);
        if let Some(rec) = &self.recorder {
            // Lock contention here is fine — events arrive serialized
            // from the worker thread; the mutex is only there to satisfy
            // Writer's &mut self requirement under Arc.
            if let Ok(mut w) = rec.lock() {
                if let Err(e) = w.append(evt) {
                    eprintln!("record append failed: {e}");
                }
            }
        }
    }

    fn on_detached(&mut self, reason: DetachReason) {
        eprintln!("detached: {reason:?}");
    }
}

fn emit<W: std::io::Write>(out: &mut W, evt: &Event) {
    match serde_json::to_string(evt) {
        Ok(line) => {
            let _ = writeln!(out, "{line}");
        }
        Err(e) => {
            let _ = writeln!(out, "{{\"kind\":\"serialize_error\",\"error\":\"{e}\"}}");
        }
    }
}
