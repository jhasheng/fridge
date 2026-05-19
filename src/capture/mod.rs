//! `Capture` + `CaptureBuilder` — the public surface for assembling a session.
//!
//! The actual frida work happens on a worker thread; see [`worker`]. This
//! file only owns the user-facing config + the `start()` plumbing that hands
//! the config to a worker and returns a [`CaptureHandle`].

pub mod handle;
pub mod handler;
mod worker;

pub use handle::CaptureHandle;
pub use handler::{Handler, Message};

use std::path::Path;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use self::worker::worker_loop;
use crate::error::{Error, Result};
use crate::target::{DeviceSel, Target};

const DEFAULT_DETACH_POLL: Duration = Duration::from_millis(500);
const DEFAULT_START_TIMEOUT: Duration = Duration::from_secs(30);

/// A ready-to-start capture. Build via [`Capture::builder`].
pub struct Capture {
    cfg: CaptureConfig,
}

/// Worker-thread config snapshot. `pub(crate)` so worker.rs can read it.
pub(crate) struct CaptureConfig {
    pub(crate) target: Target,
    pub(crate) device: DeviceSel,
    pub(crate) script: ScriptInput,
    pub(crate) resume_after_spawn: bool,
    pub(crate) detach_poll: Duration,
    pub(crate) start_timeout: Duration,
}

/// How the script reaches the target — JS source or precompiled bytecode.
pub(crate) enum ScriptInput {
    Source(String),
    Bytes(Vec<u8>),
}

/// Builder for [`Capture`].
pub struct CaptureBuilder {
    target: Option<Target>,
    device: DeviceSel,
    script: Option<ScriptInput>,
    resume_after_spawn: bool,
    detach_poll: Duration,
    start_timeout: Duration,
}

impl Default for CaptureBuilder {
    fn default() -> Self {
        Self {
            target: None,
            device: DeviceSel::default(),
            script: None,
            resume_after_spawn: true,
            detach_poll: DEFAULT_DETACH_POLL,
            start_timeout: DEFAULT_START_TIMEOUT,
        }
    }
}

impl CaptureBuilder {
    pub fn target(mut self, t: Target) -> Self {
        self.target = Some(t);
        self
    }

    pub fn device(mut self, d: DeviceSel) -> Self {
        self.device = d;
        self
    }

    /// JS source. Mutually exclusive with [`script_bytes`](Self::script_bytes);
    /// the last one set wins.
    pub fn script<S: Into<String>>(mut self, s: S) -> Self {
        self.script = Some(ScriptInput::Source(s.into()));
        self
    }

    /// Precompiled bytecode blob (V8 or QJS — must match the runtime that
    /// produced it). Generate with [`crate::compile_script`] or `frida-compile`.
    ///
    /// Mutually exclusive with [`script`](Self::script); the last one set wins.
    pub fn script_bytes<B: Into<Vec<u8>>>(mut self, b: B) -> Self {
        self.script = Some(ScriptInput::Bytes(b.into()));
        self
    }

    /// Read a script from disk and dispatch by extension: `.js` → source
    /// string (UTF-8 required), everything else → bytecode bytes. The
    /// "everything else" branch covers `.bin`, `.qjsc`, and any other
    /// extension a frida-compile downstream might pick; the only stable
    /// rule is "is it `.js` or not".
    ///
    /// Mutually exclusive with [`script`](Self::script) and
    /// [`script_bytes`](Self::script_bytes); the last one set wins.
    pub fn script_from_disk<P: AsRef<Path>>(self, path: P) -> Result<Self> {
        let p = path.as_ref();
        let bytes = std::fs::read(p)
            .map_err(|e| Error::Frida(format!("read script {}: {e}", p.display())))?;
        Ok(if p.extension().and_then(|e| e.to_str()) == Some("js") {
            let src = String::from_utf8(bytes).map_err(|e| {
                Error::Frida(format!("script {} is not valid utf-8: {e}", p.display()))
            })?;
            self.script(src)
        } else {
            self.script_bytes(bytes)
        })
    }

    /// When the target was spawned (vs. attached to a running process), should
    /// the worker call `device.resume(pid)` after the script loads? Default `true`.
    pub fn resume_after_spawn(mut self, b: bool) -> Self {
        self.resume_after_spawn = b;
        self
    }

    /// How often the watchdog polls `Session::is_detached()`. Default 500ms.
    pub fn detach_poll_interval(mut self, d: Duration) -> Self {
        self.detach_poll = d;
        self
    }

    /// Cap on how long `start()` waits for the worker thread to load the
    /// script and emit "ready". Default 30s.
    pub fn start_timeout(mut self, d: Duration) -> Self {
        self.start_timeout = d;
        self
    }

    pub fn build(self) -> Result<Capture> {
        let target = self.target.ok_or(Error::MissingTarget)?;
        let script = self.script.ok_or(Error::MissingScript)?;
        Ok(Capture {
            cfg: CaptureConfig {
                target,
                script,
                device: self.device,
                resume_after_spawn: self.resume_after_spawn,
                detach_poll: self.detach_poll,
                start_timeout: self.start_timeout,
            },
        })
    }

    /// Shorthand for `self.build()?.start(handler)`.
    pub fn start<H: Handler>(self, handler: H) -> Result<CaptureHandle> {
        self.build()?.start(handler)
    }
}

impl Capture {
    pub fn builder() -> CaptureBuilder {
        CaptureBuilder::default()
    }

    /// Spawn the worker thread and block until the script reports loaded (or
    /// the start timeout elapses, or frida rejects something).
    pub fn start<H: Handler>(self, handler: H) -> Result<CaptureHandle> {
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<u32>>(1);
        let cfg = self.cfg;
        let start_timeout = cfg.start_timeout;
        let handler = Arc::new(Mutex::new(handler));
        let handler_for_worker = Arc::clone(&handler);

        let worker = thread::Builder::new()
            .name("fridge-worker".into())
            .spawn(move || worker_loop(cfg, handler_for_worker, stop_rx, ready_tx))
            .map_err(|e| Error::Frida(format!("spawn worker: {e}")))?;

        let pid = match ready_rx.recv_timeout(start_timeout) {
            Ok(r) => r?,
            Err(_) => return Err(Error::StartTimeout(start_timeout)),
        };

        Ok(CaptureHandle::new(worker, stop_tx, pid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn script_from_disk_js_loads_as_source() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("hook.js");
        std::fs::write(&p, b"console.log('hi');").unwrap();
        let b = Capture::builder().script_from_disk(&p).unwrap();
        match b.script.as_ref().unwrap() {
            ScriptInput::Source(s) => assert_eq!(s, "console.log('hi');"),
            ScriptInput::Bytes(_) => panic!(".js should land as Source"),
        }
    }

    #[test]
    fn script_from_disk_bin_loads_as_bytes() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("hook.bin");
        // Non-UTF-8 bytes — would fail the .js path's String::from_utf8 check.
        let payload: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xFF];
        std::fs::write(&p, &payload).unwrap();
        let b = Capture::builder().script_from_disk(&p).unwrap();
        match b.script.as_ref().unwrap() {
            ScriptInput::Bytes(bs) => assert_eq!(bs, &payload),
            ScriptInput::Source(_) => panic!(".bin should land as Bytes"),
        }
    }

    #[test]
    fn script_from_disk_qjsc_also_loads_as_bytes() {
        // Anything not `.js` → bytes. Covers `.bin`, `.qjsc`, no-extension.
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("hook.qjsc");
        std::fs::write(&p, b"\x01\x02\x03").unwrap();
        let b = Capture::builder().script_from_disk(&p).unwrap();
        assert!(matches!(b.script.as_ref(), Some(ScriptInput::Bytes(_))));
    }

    #[test]
    fn script_from_disk_missing_file_errors() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("nope.js");
        let Err(e) = Capture::builder().script_from_disk(&p) else {
            panic!("expected read failure");
        };
        assert!(format!("{e}").contains("read script"));
    }

    #[test]
    fn script_from_disk_invalid_utf8_js_errors() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("bad.js");
        // 0xFF is never valid utf-8.
        std::fs::write(&p, [b'l', b'e', b't', 0xFF]).unwrap();
        let Err(e) = Capture::builder().script_from_disk(&p) else {
            panic!("expected utf-8 failure");
        };
        assert!(format!("{e}").contains("utf-8"));
    }

    #[test]
    fn script_from_disk_overrides_prior_script_call() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("hook.js");
        std::fs::write(&p, b"after").unwrap();
        let b = Capture::builder()
            .script("before")
            .script_from_disk(&p)
            .unwrap();
        match b.script.as_ref().unwrap() {
            ScriptInput::Source(s) => assert_eq!(s, "after"),
            _ => panic!(),
        }
    }
}
