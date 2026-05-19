//! Wrap one `Handler` in another — fridge's `Handler` trait is just
//! `Send + 'static`, so the decorator pattern works without any
//! special support from the crate.
//!
//! This example shows two wrappers:
//!
//!   `PrintPrefix<H>`  prefixes every message with a label before
//!                     forwarding to the inner handler. Useful when
//!                     multiple captures share a stdout.
//!
//!   `RateLimited<H>`  drops messages once the per-second budget is
//!                     spent, again forwarding the survivors to the
//!                     inner handler. A drop-in for noisy hooks.
//!
//! Compose them: `PrintPrefix::new("api", RateLimited::new(50, MyHook))`.

use std::time::{Duration, Instant};

use fridge::{DetachReason, Event, Handler};

/// Tags each forwarded event with a short label. Useful when running
/// multiple `Capture` sessions that all log to the same stream.
pub struct PrintPrefix<H> {
    label: &'static str,
    inner: H,
}

impl<H> PrintPrefix<H> {
    pub fn new(label: &'static str, inner: H) -> Self {
        Self { label, inner }
    }
}

impl<H: Handler> Handler for PrintPrefix<H> {
    fn on_message(&mut self, evt: &Event, data: Option<&[u8]>) {
        eprintln!("[{}]", self.label);
        self.inner.on_message(evt, data);
    }

    fn on_detached(&mut self, reason: DetachReason) {
        eprintln!("[{}] detached: {reason:?}", self.label);
        self.inner.on_detached(reason);
    }

    fn on_started(&mut self, pid: u32) {
        eprintln!("[{}] started pid={pid}", self.label);
        self.inner.on_started(pid);
    }
}

/// Drops events once the per-second budget is spent; resets every
/// 1-second window. The dropped count is reported to stderr so the
/// consumer notices spam.
pub struct RateLimited<H> {
    budget: u32,
    window_start: Instant,
    used: u32,
    dropped_this_window: u32,
    inner: H,
}

impl<H> RateLimited<H> {
    pub fn new(budget_per_sec: u32, inner: H) -> Self {
        Self {
            budget: budget_per_sec,
            window_start: Instant::now(),
            used: 0,
            dropped_this_window: 0,
            inner,
        }
    }
}

impl<H: Handler> Handler for RateLimited<H> {
    fn on_message(&mut self, evt: &Event, data: Option<&[u8]>) {
        if self.window_start.elapsed() >= Duration::from_secs(1) {
            if self.dropped_this_window > 0 {
                eprintln!(
                    "rate-limit: dropped {} in last window",
                    self.dropped_this_window
                );
            }
            self.window_start = Instant::now();
            self.used = 0;
            self.dropped_this_window = 0;
        }
        if self.used >= self.budget {
            self.dropped_this_window += 1;
            return;
        }
        self.used += 1;
        self.inner.on_message(evt, data);
    }

    fn on_detached(&mut self, reason: DetachReason) {
        self.inner.on_detached(reason);
    }

    fn on_started(&mut self, pid: u32) {
        self.inner.on_started(pid);
    }
}

/// Plain stdout handler — the leaf of the decorator chain.
struct StdoutHandler;
impl Handler for StdoutHandler {
    fn on_message(&mut self, evt: &Event, _data: Option<&[u8]>) {
        println!("{evt:?}");
    }
}

fn main() {
    // This example doesn't actually attach to a process — the point is
    // to demonstrate the type composition. To exercise live, replace
    // the eprintln below with a `Capture::builder()...start(handler)?`.
    let handler = PrintPrefix::new("demo", RateLimited::new(50, StdoutHandler));
    eprintln!(
        "Composed: {} (would feed to Capture::start)",
        std::any::type_name_of_val(&handler)
    );
}
