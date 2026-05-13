//! Generic inspector — point at any process, run any script, print messages.
//!
//! Usage:
//!     inspect --name notepad.exe --script hook.js
//!     inspect --pid 1234         --script hook.js
//!     inspect --spawn C:\app.exe --script hook.js
//!     inspect --name X           --bytes hook.bin
//!     inspect --compile hook.js hook.bin     # compile only, then exit
//!
//! `--script` loads JS source, `--bytes` loads precompiled QJS/V8 bytecode.
//! `--inline JS` is for one-line smoke tests. `--compile IN OUT` produces a
//! bytecode blob via `fridge::compile_script` (no target attach needed) and
//! exits.

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use fridge::{Capture, DetachReason, Event, Handler, Target};

struct Stdout;

impl Handler for Stdout {
    fn on_message(&mut self, evt: &Event, data: Option<&[u8]>) {
        let dlen = data.map(|d| d.len()).unwrap_or(0);
        match evt {
            Event::Send { payload } => {
                println!("[send] {} data={}B", payload, dlen);
            }
            Event::Log { level, message } => println!("[log/{:?}] {}", level, message),
            Event::Error {
                description,
                file_name,
                line_number,
                ..
            } => eprintln!("[error] {} @ {}:{}", description, file_name, line_number),
            Event::Unknown(v) => println!("[?] {}", v),
        }
    }

    fn on_detached(&mut self, reason: DetachReason) {
        eprintln!("[detached] {:?}", reason);
    }

    fn on_started(&mut self, pid: u32) {
        eprintln!("[started] pid={}", pid);
    }
}

fn main() -> Result<()> {
    let args = parse_args()?;

    // Compile mode is standalone — no target attach, just JS → bytecode.
    if let Some((src_path, out_path)) = args.compile {
        return run_compile(&src_path, &out_path);
    }

    let target = match (args.name, args.pid, args.spawn) {
        (Some(n), None, None) => Target::name(n),
        (None, Some(p), None) => Target::pid(p),
        (None, None, Some(prog)) => {
            let argv: Vec<&str> = args.spawn_args.iter().map(String::as_str).collect();
            Target::spawn(prog, &argv)
        }
        _ => return Err(anyhow!("pick exactly one of --name / --pid / --spawn")),
    };

    let mut builder = Capture::builder().target(target);
    builder = match (args.inline, args.script_path, args.bytes_path) {
        (Some(s), None, None) => builder.script(s),
        (None, Some(p), None) => builder.script(
            fs::read_to_string(&p).map_err(|e| anyhow!("read script {}: {}", p.display(), e))?,
        ),
        (None, None, Some(p)) => builder.script_bytes(
            fs::read(&p).map_err(|e| anyhow!("read bytes {}: {}", p.display(), e))?,
        ),
        (None, None, None) => return Err(anyhow!("need --script PATH | --inline JS | --bytes PATH")),
        _ => return Err(anyhow!("pick exactly one of --script / --inline / --bytes")),
    };

    let handle = builder.start(Stdout)?;
    eprintln!("[ready] pid={} — Ctrl+C to stop", handle.pid());

    // Park the main thread. frida's callbacks fire on its own GLib threads,
    // not here — we just need to stay alive so the worker thread + frida
    // singletons aren't dropped. Heartbeat every 10s confirms liveness.
    let started = Instant::now();
    let mut beats = 0u32;
    loop {
        std::thread::sleep(Duration::from_secs(10));
        beats += 1;
        eprintln!(
            "[alive] {}s elapsed, {} heartbeats",
            started.elapsed().as_secs(),
            beats
        );
    }
}

fn run_compile(src_path: &PathBuf, out_path: &PathBuf) -> Result<()> {
    let src = fs::read_to_string(src_path).with_context(|| format!("read {}", src_path.display()))?;
    let bc = fridge::compile_script(&src)?;
    fs::write(out_path, &bc).with_context(|| format!("write {}", out_path.display()))?;
    println!(
        "{} ({}B JS) -> {} ({}B bytecode, {:.0}%)",
        src_path.display(),
        src.len(),
        out_path.display(),
        bc.len(),
        100.0 * bc.len() as f64 / src.len().max(1) as f64,
    );
    Ok(())
}

#[derive(Default)]
struct Args {
    name: Option<String>,
    pid: Option<u32>,
    spawn: Option<String>,
    spawn_args: Vec<String>,
    script_path: Option<PathBuf>,
    bytes_path: Option<PathBuf>,
    inline: Option<String>,
    /// Standalone compile mode: (input.js, output.bin).
    compile: Option<(PathBuf, PathBuf)>,
}

fn parse_args() -> Result<Args> {
    let mut a = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--name" | "-n" => a.name = it.next(),
            "--pid" => {
                a.pid = it.next().and_then(|s| s.parse().ok());
                if a.pid.is_none() {
                    return Err(anyhow!("--pid needs a u32"));
                }
            }
            "--spawn" => a.spawn = it.next(),
            "--script" | "-s" => a.script_path = it.next().map(PathBuf::from),
            "--bytes" => a.bytes_path = it.next().map(PathBuf::from),
            "--inline" => a.inline = it.next(),
            "--compile" => {
                let inp = it.next().ok_or_else(|| anyhow!("--compile needs <input.js> <output.bin>"))?;
                let out = it.next().ok_or_else(|| anyhow!("--compile needs <input.js> <output.bin>"))?;
                a.compile = Some((PathBuf::from(inp), PathBuf::from(out)));
            }
            "--" => {
                a.spawn_args = it.by_ref().collect::<Vec<_>>();
                break;
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(anyhow!("unknown arg: {}", other)),
        }
    }
    Ok(a)
}

fn print_usage() {
    eprintln!(
        "usage:\n  \
         inspect (--name N | --pid P | --spawn PROG) \
         (--script PATH | --inline JS | --bytes PATH) [-- ARGS...]\n  \
         inspect --compile <input.js> <output.bin>"
    );
    eprintln!();
    eprintln!("compile JS to bytecode then run:");
    eprintln!("  inspect --compile src/hook.js src/hook.bin");
    eprintln!("  inspect --name Weixin.exe --bytes src/hook.bin");
}
