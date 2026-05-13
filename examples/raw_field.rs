//! Regression test for upstream frida-rust#189 (ScriptHandler with fields
//! reads/writes garbage memory). Uses the raw `frida` crate directly,
//! bypassing fridge's `Capture` wrapper, to assert that the patched build
//! we depend on (jhasheng/frida-rust@fridge-fixes) routes `user_data`
//! through `cb.script_handler` instead of casting it to `*mut I`. With the
//! patch the count must print 1, 2, 3 cleanly. Without it the count starts
//! at a garbage value and corrupts adjacent memory.

use std::env;
use std::thread;
use std::time::Duration;

use frida::{DeviceManager, Frida, Message, ScriptHandler, ScriptOption};

struct WithField {
    count: u64,
}

impl ScriptHandler for WithField {
    fn on_message(&mut self, message: Message, _data: Option<Vec<u8>>) {
        self.count += 1;
        eprintln!("[field-recv #{}] {:?}", self.count, message);
    }
}

fn main() {
    let pid: u32 = env::args().nth(1).unwrap().parse().unwrap();
    let script_path = env::args().nth(2).unwrap();
    let src = std::fs::read_to_string(&script_path).unwrap();

    let frida = unsafe { Frida::obtain() };
    let mgr = DeviceManager::obtain(&frida);
    let dev = mgr.get_local_device().unwrap();
    let session = dev.attach(pid).unwrap();
    let mut opts = ScriptOption::default();
    let mut script = session.create_script(&src, &mut opts).unwrap();
    script.handle_message(WithField { count: 0 }).unwrap();
    script.load().unwrap();
    eprintln!("[field] loaded");
    thread::sleep(Duration::from_secs(8));
    eprintln!("[field] done sleeping");
}
