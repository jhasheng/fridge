//! Worker thread that owns every frida handle for one capture session.
//!
//! Frida's types (`Frida`, `DeviceManager`, `Device`, `Session`, `Script`)
//! are `!Send + !Sync` — they must stay on a single thread. The worker
//! thread defined here is that thread. The lifecycle:
//!
//!   1. `Frida::obtain()` + `DeviceManager`.
//!   2. Resolve the requested `Target` to a PID (spawn / name lookup / pid).
//!   3. `device.attach(pid)`, `session.create_script(...)`, install handler.
//!   4. `script.load()` + optional `device.resume(pid)` for spawn targets.
//!   5. Send the PID back to `Capture::start` via `ready_tx`.
//!   6. Poll `session.is_detached()` until either the user stops us or the
//!      target dies.
//!   7. Unload, fire `Handler::on_detached`, exit.

use std::sync::{mpsc, Arc, Mutex};

use std::collections::HashSet;

use frida::{
    Device, DeviceManager, DeviceType, Frida, Scope, ScriptHandler, ScriptOption, SpawnOptions,
};

use super::event::Event;
use super::handler::{Handler, Message};
use super::target::{DetachReason, DeviceSel, Target};
use super::{CaptureConfig, ScriptInput};
use crate::error::{Error, Result};

pub(crate) fn worker_loop<H: Handler>(
    cfg: CaptureConfig,
    handler: Arc<Mutex<H>>,
    stop_rx: mpsc::Receiver<()>,
    ready_tx: mpsc::SyncSender<Result<u32>>,
) {
    let outcome = run_capture(&cfg, &handler, &stop_rx, &ready_tx);

    match outcome {
        Ok(reason) => {
            if let Ok(mut h) = handler.lock() {
                h.on_detached(reason);
            }
        }
        Err(e) => {
            let msg = e.to_string();
            // Best-effort: if start() is still waiting, hand the error to it.
            // If the slot is already filled (ready was sent), this is a no-op.
            let _ = ready_tx.send(Err(e));
            if let Ok(mut h) = handler.lock() {
                h.on_detached(DetachReason::Error(msg));
            }
        }
    }
}

fn run_capture<H: Handler>(
    cfg: &CaptureConfig,
    handler: &Arc<Mutex<H>>,
    stop_rx: &mpsc::Receiver<()>,
    ready_tx: &mpsc::SyncSender<Result<u32>>,
) -> Result<DetachReason> {
    let frida = unsafe { Frida::obtain() };
    let mgr = DeviceManager::obtain(&frida);
    let mut device = pick_device(&mgr, &cfg.device)?;

    let (pid, spawned) = resolve_target(&mut device, &cfg.target)?;

    let session = device.attach(pid)?;
    let mut opts = ScriptOption::default();
    let mut script = match &cfg.script {
        ScriptInput::Source(src) => session.create_script(src, &mut opts)?,
        ScriptInput::Bytes(bytes) => session.create_script_from_bytes(bytes, &mut opts)?,
    };

    let bridge = MessageBridge::<H> {
        handler: Arc::clone(handler),
    };
    script.handle_message(bridge)?;
    script.load()?;

    if spawned && cfg.resume_after_spawn {
        device.resume(pid)?;
    }

    if let Ok(mut h) = handler.lock() {
        h.on_started(pid);
    }
    let _ = ready_tx.send(Ok(pid));

    loop {
        match stop_rx.recv_timeout(cfg.detach_poll) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = script.unload();
                return Ok(DetachReason::Stopped);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if session.is_detached() {
                    return Ok(DetachReason::Detected);
                }
            }
        }
    }
}

fn pick_device<'a>(mgr: &'a DeviceManager, sel: &DeviceSel) -> Result<Device<'a>> {
    Ok(match sel {
        DeviceSel::Local => mgr.get_local_device()?,
        DeviceSel::Usb => mgr.get_device_by_type(DeviceType::USB)?,
        DeviceSel::Remote(host) => mgr.get_remote_device(host)?,
        DeviceSel::ById(id) => mgr.get_device_by_id(id)?,
    })
}

fn resolve_target(device: &mut Device, t: &Target) -> Result<(u32, bool)> {
    match t {
        Target::Pid(p) => Ok((*p, false)),
        Target::Name(name) => {
            let processes = device.enumerate_processes();
            let needle_lc = name.to_ascii_lowercase();
            for p in processes {
                let pname = p.get_name();
                if pname == name.as_str() || pname.to_ascii_lowercase() == needle_lc {
                    return Ok((p.get_pid(), false));
                }
            }
            Err(Error::ProcessNotFound(name.clone()))
        }
        Target::MainByName(name) => {
            // Need parameters (ppid) — Scope::Full populates them.
            let processes = device.enumerate_processes_with_options(Scope::Full);
            let needle_lc = name.to_ascii_lowercase();
            let matches: Vec<_> = processes
                .iter()
                .filter(|p| {
                    let pname = p.get_name();
                    pname == name.as_str() || pname.to_ascii_lowercase() == needle_lc
                })
                .collect();
            if matches.is_empty() {
                return Err(Error::ProcessNotFound(name.clone()));
            }
            let same_name_pids: HashSet<u32> = matches.iter().map(|p| p.get_pid()).collect();
            let main = matches.iter().find(|p| {
                p.get_parameters()
                    .get("ppid")
                    .and_then(|v| v.get_int())
                    .map(|ppid| !same_name_pids.contains(&(ppid as u32)))
                    .unwrap_or(false)
            });
            match main {
                Some(p) => Ok((p.get_pid(), false)),
                None => Err(Error::ProcessNotFound(name.clone())),
            }
        }
        Target::Spawn { program, args } => {
            let argv: Vec<&str> = args.iter().map(String::as_str).collect();
            let opts = SpawnOptions::new().argv(argv);
            let pid = device.spawn(program, &opts)?;
            Ok((pid, true))
        }
    }
}

/// Adapts our `Handler` trait to frida's `ScriptHandler`, translating raw
/// `frida::Message` into the friendlier `Event` along the way.
struct MessageBridge<H: Handler> {
    handler: Arc<Mutex<H>>,
}

impl<H: Handler> ScriptHandler for MessageBridge<H> {
    fn on_message(&mut self, message: Message, data: Option<Vec<u8>>) {
        let evt = Event::from_frida(&message);
        if let Ok(mut h) = self.handler.lock() {
            h.on_message(&evt, data.as_deref());
        }
    }
}
