//! User-supplied callback contract.
//!
//! `Handler` is the only thing every consumer of this crate has to implement.
//! All methods except `on_message` have empty default impls — you only opt in
//! to what you care about.

use super::event::Event;
use super::target::DetachReason;

// Re-export frida's raw Message in case a consumer needs the unfiltered form.
pub use frida::Message;

/// Called by the worker thread when frida delivers script events.
///
/// **Thread model:** every method runs on the crate's internal worker thread,
/// which is the same thread that owns the frida `Session` and `Script`. Don't
/// block here — frida cannot deliver further messages until you return. Forward
/// to a channel / `Arc<Mutex<_>>` if you need to do anything expensive.
///
/// **Composition:** since the trait only requires `Send + 'static`, wrapping
/// one `Handler` in another (rate-limiter, prefix tagger, fan-out, JSON
/// logger) needs no special crate support — implement the trait on a struct
/// that owns the inner `H` and forward the calls. See `examples/decorator.rs`
/// for the pattern in action.
pub trait Handler: Send + 'static {
    /// Normalized script event — `send()`, console log, or runtime error.
    /// `data` is the binary payload from `send(obj, data)`, if any.
    fn on_message(&mut self, evt: &Event, data: Option<&[u8]>);

    /// Session ended. Called at most once. Default: no-op.
    fn on_detached(&mut self, _reason: DetachReason) {}

    /// Worker started, script loaded, process resumed (if spawn). PID is the
    /// pid we attached to. Default: no-op.
    fn on_started(&mut self, _pid: u32) {}
}
