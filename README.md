# fridge

> A wedge of ergonomics on top of [`frida`](https://crates.io/crates/frida) — and
> a place to chill your script handlers.

Ergonomic wrapper around the official `frida` crate (0.17). Hand it a target +
a script + a `Handler`, get normalized `Event`s on a dedicated worker thread.
No GLib threading footguns, no UB land-mines in `ScriptHandler`.

```rust
use fridge::{Capture, DetachReason, Event, Handler, Target};

struct Logger;
impl Handler for Logger {
    fn on_message(&mut self, evt: &Event, _data: Option<&[u8]>) {
        println!("{:?}", evt);
    }
    fn on_detached(&mut self, reason: DetachReason) {
        eprintln!("detached: {reason:?}");
    }
}

fn main() -> anyhow::Result<()> {
    let handle = Capture::builder()
        .target(Target::name("Weixin.exe"))
        .script(include_str!("../hook.js"))
        .start(Logger)?;

    std::thread::sleep(std::time::Duration::from_secs(60));
    handle.stop()?;
    Ok(())
}
```

## Why a wrapper

The raw `frida` crate is faithful to frida-core, which means:

- `Frida`, `DeviceManager`, `Device`, `Session` are `!Send + !Sync` (GObject thread
  affinity). You can't move them across threads or hold them in an async task
  without thinking hard.
- `ScriptHandler` is moved into the script by value with a `'static` bound — to
  share state with the rest of your program you have to wrap it in
  `Arc<Mutex<_>>` yourself, and in 0.17.2 that triggers
  [frida-rust#189](https://github.com/frida/frida-rust/issues/189) UB.
- There's no `on_detached` callback. To learn the process exited you poll
  `session.is_detached()`.
- `Message::Send` only fires for the internal frida RPC payload shape; plain
  `send({...})` calls from JS silently fall through to `Message::Other`
  (frida-rust#210).

`fridge` does all of the above for you:

- Spawns one dedicated worker thread, calls `Frida::obtain` there, keeps every
  frida handle on that thread.
- Exposes a `Send`-able `CaptureHandle` to your code. Stop, join, drop — all
  safe from any thread.
- Wraps your `Handler` in `Arc<Mutex<_>>` internally and reuses it for both
  `on_message` (script callback) and `on_detached` (polled watchdog).
- Normalizes script events into an `Event` enum: any `send()` from JS lands
  in `Event::Send { payload: Value }` regardless of the inner shape.

## ⚠️ Setup — required patch

`fridge`'s `frida` dep on crates.io is **0.17.2 with unfixed UB**
([frida-rust#189](https://github.com/frida/frida-rust/issues/189)). This
crate's own build redirects to a [patched fork](https://github.com/jhasheng/frida-rust/tree/fridge-fixes)
via `[patch.crates-io]`, but **that redirect only applies to the workspace
root being built** — downstream consumers have to add the same redirect in
their own workspace root, otherwise `Arc<Mutex<_>>` handlers read garbage
memory and `script.load()` deadlocks on synchronous `send()`.

In your project's **workspace root** `Cargo.toml`:

```toml
[dependencies]
fridge = "0.1"

[patch.crates-io]
frida = { git = "https://github.com/jhasheng/frida-rust.git", rev = "6a92b72" }
```

The pinned `frida-rust` rev carries two extra commits on top of 0.17.2:

1. The fix for frida-rust#189 (ScriptHandler `user_data` UB).
2. `Session::compile_script` + `Session::create_script_from_bytes`
   (bytecode loading — fridge depends on both).

Once these patches land upstream and a new `frida` release ships, this
`[patch]` block goes away and `fridge = "0.1"` works standalone.

If you'd rather skip the patch line, depend on `fridge` via git instead —
the redirect is baked into this repo's own `Cargo.toml`:

```toml
[dependencies]
fridge = { git = "https://github.com/jhasheng/fridge.git" }
```

## Targets

```rust
Target::name("Weixin.exe")              // enumerate_processes + filter
Target::pid(12345)                      // attach directly
Target::spawn("C:\\app.exe", &["--flag"]) // spawn-and-attach, auto-resume
```

## Devices

```rust
DeviceSel::Local                        // default
DeviceSel::Usb                          // first USB device
DeviceSel::Remote("192.168.1.10:27042") // frida-server over TCP
DeviceSel::ById("emulator-5554")
```

## Bytecode

`CaptureBuilder` accepts either JS source or precompiled bytecode. Generate
the bytecode out-of-band with `frida-compile`:

```bash
npm install -g frida-compile
frida-compile -b hook.js -o hook.bin
```

Then load it:

```rust
Capture::builder()
    .target(Target::name("Weixin.exe"))
    .script_bytes(std::fs::read("hook.bin")?)
    .start(handler)?;
```

Caveats:
- Bytecode is runtime-specific. Compile with the same `ScriptRuntime` you
  load with (frida defaults to QJS).
- It's mild obfuscation, not encryption. V8/QJS bytecode is reversible — it
  raises the floor, not the ceiling.

## Build requirements

- LLVM / `libclang.dll` on `LIBCLANG_PATH` (frida-sys uses bindgen at build).
- `auto-download` feature (on by default) pulls a pinned frida-core devkit at
  build time, so you don't need anything else pre-installed. Disable it if
  you want to point at a system devkit via `rustc-link-search`.

## Etymology

`frida` + `wedge`. Also: it's where you put things you want to keep cold.
