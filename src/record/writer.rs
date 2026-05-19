//! Streaming append-only writer.

use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use bincode::config::standard;
use bincode::serde::encode_to_vec;
use serde::Serialize;

use super::{bincode_err, io_err, MAGIC, VERSION};
use crate::error::Result;

/// Streaming appender. Wraps the file in `BufWriter` so per-entry
/// framing doesn't issue 2 separate syscalls per message. The
/// `PhantomData<fn(M)>` keeps `Writer<M>: Send` regardless of `M`'s
/// own Send-ness — the writer never holds an `M` value, only encodes
/// references via the `append` call.
pub struct Writer<M: Serialize> {
    file: BufWriter<File>,
    path: PathBuf,
    _m: PhantomData<fn(M)>,
}

impl<M: Serialize> Writer<M> {
    /// Create (or truncate) a capture file and write the header.
    /// Subsequent calls to [`Writer::append`] append framed entries.
    pub fn create(path: PathBuf, tag: [u8; 4]) -> Result<Self> {
        if let Some(parent) = path.parent() {
            create_dir_all(parent).map_err(|e| io_err(&format!("mkdir {parent:?}"), e))?;
        }
        let mut file = BufWriter::new(
            OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&path)
                .map_err(|e| io_err(&format!("create {path:?}"), e))?,
        );
        file.write_all(&MAGIC)
            .map_err(|e| io_err("write magic", e))?;
        file.write_all(&VERSION.to_le_bytes())
            .map_err(|e| io_err("write version", e))?;
        file.write_all(&tag).map_err(|e| io_err("write tag", e))?;
        file.flush().map_err(|e| io_err("flush header", e))?;
        Ok(Self {
            file,
            path,
            _m: PhantomData,
        })
    }

    /// Encode `msg` and append a length-prefixed frame. Flushes per
    /// call so a crash loses at most this single message.
    pub fn append(&mut self, msg: &M) -> Result<()> {
        let bytes = encode_to_vec(msg, standard()).map_err(|e| bincode_err("encode", e))?;
        self.file
            .write_all(&(bytes.len() as u32).to_le_bytes())
            .map_err(|e| io_err("write len", e))?;
        self.file
            .write_all(&bytes)
            .map_err(|e| io_err("write body", e))?;
        self.file.flush().map_err(|e| io_err("flush entry", e))?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}
