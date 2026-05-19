//! Device + process discovery — read-only listing helpers built on top
//! of frida's enumeration APIs. Wrap them so consumers don't have to
//! think about `Frida::obtain` / `DeviceManager` lifecycle or copy
//! data out of `!Send` GObject wrappers themselves.

use frida::{DeviceManager, DeviceType, Frida, Scope};

use crate::error::Result;
use crate::DeviceSel;

/// Minimal owned snapshot of a frida device. The raw `frida::Device`
/// is `!Send` and lifetime-tied to a `DeviceManager`; we copy the
/// fields we care about so callers can hold them across threads.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub id: String,
    pub name: String,
    pub kind: DeviceKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    Local,
    Remote,
    Usb,
    /// `DeviceType` value frida-rust didn't classify into the trio above.
    Other,
}

/// Minimal owned snapshot of a process visible on a frida device.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    /// Parent pid, when available (only populated when frida exposes
    /// it via `Scope::Full` parameters — Windows / Android typically
    /// do; bare macOS may not).
    pub ppid: Option<u32>,
}

/// List every device frida currently sees. Equivalent to
/// `DeviceManager::enumerate_all_devices()` with the wrapping cleaned up.
pub fn devices() -> Result<Vec<DeviceInfo>> {
    let frida = unsafe { Frida::obtain() };
    let mgr = DeviceManager::obtain(&frida);
    let out = mgr
        .enumerate_all_devices()
        .into_iter()
        .map(|d| DeviceInfo {
            id: d.get_id().to_string(),
            name: d.get_name().to_string(),
            kind: classify(d.get_type()),
        })
        .collect();
    Ok(out)
}

/// List processes on the given device, with parent-pid included when
/// the platform exposes it. Use this to pick a `Target::Pid` / build
/// process-name filters at runtime instead of hard-coding them.
pub fn processes(sel: DeviceSel) -> Result<Vec<ProcessInfo>> {
    let frida = unsafe { Frida::obtain() };
    let mgr = DeviceManager::obtain(&frida);
    let device = match sel {
        DeviceSel::Local => mgr.get_local_device()?,
        DeviceSel::Usb => mgr.get_device_by_type(DeviceType::USB)?,
        DeviceSel::Remote(ref host) => mgr.get_remote_device(host)?,
        DeviceSel::ById(ref id) => mgr.get_device_by_id(id)?,
    };
    // Scope::Full gives us ppid for free — cheap when the list is short,
    // negligible when it isn't (frida already walks the kernel table once).
    let out = device
        .enumerate_processes_with_options(Scope::Full)
        .iter()
        .map(|p| ProcessInfo {
            pid: p.get_pid(),
            name: p.get_name().to_string(),
            ppid: p
                .get_parameters()
                .get("ppid")
                .and_then(|v| v.get_int())
                .map(|i| i as u32),
        })
        .collect();
    Ok(out)
}

fn classify(t: DeviceType) -> DeviceKind {
    match t {
        DeviceType::Local => DeviceKind::Local,
        DeviceType::Remote => DeviceKind::Remote,
        DeviceType::USB => DeviceKind::Usb,
        _ => DeviceKind::Other,
    }
}
