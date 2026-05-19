//! `CaptureHandle` — the caller-side rope on a running session.
//!
//! Holds the worker thread's `JoinHandle` + a stop signal channel. Drop or
//! explicit `stop()` tears the worker down deterministically.

use std::sync::mpsc;
use std::thread::JoinHandle;

use crate::error::{Error, Result};

/// Live capture handle. Drop or call [`stop`](Self::stop) to tear down.
pub struct CaptureHandle {
    worker: Option<JoinHandle<()>>,
    stop_tx: Option<mpsc::Sender<()>>,
    pid: u32,
}

impl CaptureHandle {
    pub(crate) fn new(worker: JoinHandle<()>, stop_tx: mpsc::Sender<()>, pid: u32) -> Self {
        CaptureHandle {
            worker: Some(worker),
            stop_tx: Some(stop_tx),
            pid,
        }
    }

    /// PID we attached to (or spawned).
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Signal the worker to stop, then join it. After this returns the script
    /// is unloaded, the session is detached, and `Handler::on_detached` has
    /// already fired.
    pub fn stop(mut self) -> Result<()> {
        self.stop_inner()
    }

    fn stop_inner(&mut self) -> Result<()> {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
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
