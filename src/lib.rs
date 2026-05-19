//! Ergonomic wrapper over the official [`frida`](https://docs.rs/frida) crate.
//!
//! # Quick start
//!
//! ```no_run
//! use fridge::{Capture, DetachReason, Event, Handler, Target};
//!
//! struct Logger;
//! impl Handler for Logger {
//!     fn on_message(&mut self, evt: &Event, _data: Option<&[u8]>) {
//!         println!("{:?}", evt);
//!     }
//!     fn on_detached(&mut self, reason: DetachReason) {
//!         eprintln!("detached: {reason:?}");
//!     }
//! }
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let handle = Capture::builder()
//!     .target(Target::name("Weixin.exe"))
//!     .script("Interceptor.attach(ptr('0x0'), { onEnter: function() {} });")
//!     .start(Logger)?;
//!
//! // ... your code runs while frida delivers messages on a worker thread ...
//!
//! handle.stop()?;
//! # Ok(()) }
//! ```
//!
//! # What this crate adds over `frida`
//!
//! 1. **Thread plumbing.** `frida`'s types are `!Send + !Sync`. This crate
//!    runs them on a private worker thread and gives you a `Send`-able handle.
//! 2. **`on_detached` watchdog.** The raw binding doesn't expose a detach
//!    callback — we poll [`Session::is_detached`](frida::Session) for you and
//!    fire [`Handler::on_detached`] when it flips.
//! 3. **Builder ergonomics.** Pick a [`Target`] + [`DeviceSel`], hand over a
//!    JS string, plug in a [`Handler`]. No `Frida::obtain` / `DeviceManager` /
//!    `ScriptOption` boilerplate.
//! 4. **Script source on disk.** [`CaptureBuilder::script_from_disk`] reads
//!    the file and dispatches by extension — `.js` → source, anything else
//!    → bytecode bytes — so callers don't repeat the read+route boilerplate.
//! 5. **Capture record/replay** (feature `record`, default-on). The
//!    [`record`] module is a length-framed bincode appender + reader,
//!    generic over any `Serialize`-able message type — capture frida
//!    messages to disk and read them back without rolling your own framing.
//!
//! # CLI
//!
//! With the `cli` feature on, the crate also ships a `fridge` binary
//! (`cargo install fridge --features cli`) that wraps the library:
//!
//! ```text
//! fridge attach --target Weixin.exe --script hook.js [--record cap.bin]
//! fridge replay cap.bin
//! ```
//!
//! Events print as JSON lines on stdout. `--record` writes them through
//! `fridge::record::Writer<Event>` so `replay` can read them back.

mod capture;
mod error;

pub use capture::{
    Capture, CaptureBuilder, CaptureHandle, DetachReason, DeviceSel, Event, Handler, LogLevel,
    Message, Target,
};
pub use error::{Error, Result};

#[cfg(feature = "record")]
pub mod record;

/// Compile JS source to V8/QJS bytecode for later use with
/// [`CaptureBuilder::script_bytes`].
///
/// frida-core requires an active session to compile, so this attaches to the
/// current process briefly, compiles, and detaches. The compiled bytecode
/// is runtime-independent of the target you'll later load it into, as long
/// as you compile with the same `ScriptRuntime` you'll load with (frida's
/// default is QJS).
pub fn compile_script(source: &str) -> Result<Vec<u8>> {
    let frida = unsafe { frida::Frida::obtain() };
    let mgr = frida::DeviceManager::obtain(&frida);
    let device = mgr.get_local_device()?;
    let session = device.attach(std::process::id())?;
    let mut opts = frida::ScriptOption::default();
    let bytes = session.compile_script(source, &mut opts)?;
    let _ = session.detach();
    Ok(bytes)
}
