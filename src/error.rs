//! Error type — wraps frida's own error plus our orchestration failures.

use std::time::Duration;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// Builder was started without a script. Frida itself accepts an empty
    /// script but it's almost always a bug, so we refuse early.
    #[error("CaptureBuilder missing script")]
    MissingScript,

    /// Builder was started without a target.
    #[error("CaptureBuilder missing target")]
    MissingTarget,

    /// Process-name lookup found nothing matching.
    #[error("no process matching name {0:?} on the selected device")]
    ProcessNotFound(String),

    /// Worker thread didn't signal "ready" within the timeout — typically the
    /// frida script failed to load.
    #[error("capture worker did not start within {0:?}")]
    StartTimeout(Duration),

    /// Worker thread panicked. The inner string is whatever payload we could
    /// recover from `JoinHandle::join`.
    #[error("capture worker panicked: {0}")]
    WorkerPanic(String),

    /// Anything the underlying `frida` crate raised.
    #[error("frida: {0}")]
    Frida(String),
}

impl From<frida::Error> for Error {
    fn from(e: frida::Error) -> Self {
        Error::Frida(format!("{e:?}"))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
