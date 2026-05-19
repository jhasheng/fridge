//! `CaptureHandle` — the caller-side rope on a running session.
//!
//! Holds the worker thread's `JoinHandle` + a command channel. Drop or
//! explicit `stop()` tears the worker down deterministically. The
//! `reload_*` methods reuse the channel to swap the script without
//! detaching the session.

use std::path::Path;
use std::sync::{mpsc, Mutex};
use std::thread::JoinHandle;

use super::{script_input_from_disk, ScriptInput, WorkerCmd};
use crate::error::{Error, Result};

/// Live capture handle. Drop or call [`stop`](Self::stop) to tear down.
/// `reload_*` methods are `&self` and can be called any number of times.
pub struct CaptureHandle {
    worker: Option<JoinHandle<()>>,
    // `Mutex<Option<Sender>>` because `Sender` is `Send` but `!Sync` —
    // we need shared access (reload via `&self`) plus consume-on-stop.
    cmd_tx: Mutex<Option<mpsc::Sender<WorkerCmd>>>,
    pid: u32,
}

impl CaptureHandle {
    pub(crate) fn new(worker: JoinHandle<()>, cmd_tx: mpsc::Sender<WorkerCmd>, pid: u32) -> Self {
        CaptureHandle {
            worker: Some(worker),
            cmd_tx: Mutex::new(Some(cmd_tx)),
            pid,
        }
    }

    /// PID we attached to (or spawned).
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Hot-reload from JS source. Worker unloads the current script,
    /// creates a new one from the source, and `script.load()`s it on
    /// the same `Session` — no detach + reattach + handler re-init.
    /// Returns `Err` if the worker has already exited (stopped /
    /// detached / panicked).
    pub fn reload_source<S: Into<String>>(&self, src: S) -> Result<()> {
        self.send_cmd(WorkerCmd::ReloadScript(ScriptInput::Source(src.into())))
    }

    /// Hot-reload from precompiled bytecode. See [`reload_source`].
    pub fn reload_bytes<B: Into<Vec<u8>>>(&self, bytes: B) -> Result<()> {
        self.send_cmd(WorkerCmd::ReloadScript(ScriptInput::Bytes(bytes.into())))
    }

    /// Read a script from disk and reload, dispatching by extension
    /// the same way [`crate::CaptureBuilder::script_from_disk`] does
    /// at start-up: `.js` → source, anything else → bytecode.
    pub fn reload_from_disk<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        self.send_cmd(WorkerCmd::ReloadScript(script_input_from_disk(
            path.as_ref(),
        )?))
    }

    /// Signal the worker to stop, then join it. After this returns the script
    /// is unloaded, the session is detached, and `Handler::on_detached` has
    /// already fired.
    pub fn stop(mut self) -> Result<()> {
        self.stop_inner()
    }

    fn send_cmd(&self, cmd: WorkerCmd) -> Result<()> {
        let guard = self
            .cmd_tx
            .lock()
            .map_err(|_| Error::Frida("CaptureHandle cmd_tx mutex poisoned".into()))?;
        let tx = guard
            .as_ref()
            .ok_or_else(|| Error::Frida("CaptureHandle already stopped".into()))?;
        tx.send(cmd)
            .map_err(|_| Error::Frida("worker thread no longer receiving".into()))
    }

    fn stop_inner(&mut self) -> Result<()> {
        // Drop the sender to signal Disconnected as a fallback — and
        // try one explicit Stop first so the worker exits faster than
        // the next `detach_poll` tick.
        if let Some(tx) = self
            .cmd_tx
            .get_mut()
            .ok()
            .and_then(|opt| opt.take())
        {
            let _ = tx.send(WorkerCmd::Stop);
        }
        if let Some(j) = self.worker.take() {
            j.join().map_err(|p| Error::WorkerPanic(format!("{p:?}")))?;
        }
        Ok(())
    }
}

impl Drop for CaptureHandle {
    fn drop(&mut self) {
        let _ = self.stop_inner();
    }
}
