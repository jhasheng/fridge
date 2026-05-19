//! What to attach to, and where.

/// What process this capture targets.
#[derive(Debug, Clone)]
pub enum Target {
    /// Attach to an already-running process by PID.
    Pid(u32),
    /// Attach to the first process whose name matches (case-sensitive on
    /// Linux/macOS; case-insensitive substring on Windows — frida-core's call).
    Name(String),
    /// Same as [`Target::Name`] but, when multiple processes share the name,
    /// picks the **main** one — the entry whose parent PID does not refer to
    /// another same-name process. Targets Chromium-style multi-process apps
    /// (Weixin / Chrome / Electron / Discord / VSCode) where attaching the
    /// "first" same-name process lands on a helper subprocess by mistake.
    ///
    /// Requires the host to expose `ppid` in
    /// [`frida::Process::get_parameters`]; falls back to `ProcessNotFound`
    /// if every match has a same-name parent.
    MainByName(String),
    /// Spawn the program, attach, then `resume` it (unless `resume_after_spawn(false)`).
    Spawn { program: String, args: Vec<String> },
}

impl Target {
    pub fn pid(p: u32) -> Self {
        Target::Pid(p)
    }

    pub fn name<S: Into<String>>(s: S) -> Self {
        Target::Name(s.into())
    }

    /// See [`Target::MainByName`].
    pub fn main_by_name<S: Into<String>>(s: S) -> Self {
        Target::MainByName(s.into())
    }

    pub fn spawn<S: Into<String>>(program: S, args: &[&str]) -> Self {
        Target::Spawn {
            program: program.into(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }
}

/// Which frida device hosts the target.
#[derive(Debug, Clone, Default)]
pub enum DeviceSel {
    /// `frida-core` local device — your machine. Default.
    #[default]
    Local,
    /// First device of type USB (adb-attached Android / lockdown iOS).
    Usb,
    /// `frida-server` reachable over TCP.
    Remote(String),
    /// Pick by frida device id (e.g. `"emulator-5554"`).
    ById(String),
}

/// Why the session ended.
#[derive(Debug, Clone)]
pub enum DetachReason {
    /// Watchdog observed `Session::is_detached() == true` — process exited or
    /// frida lost the channel.
    Detected,
    /// User called `CaptureHandle::stop()` or dropped the handle.
    Stopped,
    /// Frida raised an error after the session was already running. The
    /// builder's `start()` has already returned `Ok`, so the only place this
    /// error can surface is `on_detached`.
    Error(String),
}
