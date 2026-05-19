//! Event-specific record wrapper.
//!
//! The generic [`Writer<M>`](super::Writer) / [`read_iter<M>`](super::read_iter)
//! API encodes `M` directly with bincode. That works for any plain-old
//! struct, but breaks for [`Event`](crate::Event): its `Send.payload`
//! and `Unknown.0` fields are `serde_json::Value`, which deserializes
//! via `deserialize_any` — a method bincode (a non-self-describing
//! format) explicitly refuses. The result: writes succeed, reads
//! return `Serde(AnyNotSupported)`.
//!
//! This module adds an Event-shaped wire format that side-steps the
//! limitation: payload values are pre-serialized to JSON strings before
//! bincode encodes them, and re-parsed on the way back. The original
//! generic Writer / read_iter API stays untouched so non-Event
//! consumers can keep using the cheap binary path.
//!
//! ### Wire shape
//!
//! Each frame holds a [`WireEntry`] = `(WireEvent, Option<Vec<u8>>)`,
//! where `Option<Vec<u8>>` is the binary `data` argument from
//! `send(payload, data)`. Storing data inline (rather than alongside)
//! keeps the per-message unit atomic — a partial trailing frame loses
//! both halves cleanly, not one without the other.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{read_iter, ReadIter, Writer};
use crate::capture::event::LogLevel;
use crate::error::{Error, Result};
use crate::Event;

/// Open (or truncate) a recording for `Event` entries. See
/// [`EventWriter::append`] for the per-message API.
pub fn create_event_writer(path: PathBuf, tag: [u8; 4]) -> Result<EventWriter> {
    Ok(EventWriter(Writer::<WireEntry>::create(path, tag)?))
}

/// Streaming iterator over a recording, yielding the original `Event`
/// plus the `Option<Vec<u8>>` data buffer passed to `send()` on the JS
/// side. Header errors surface from [`read_event_iter`]; per-entry decode
/// errors surface from the iterator.
pub fn read_event_iter(path: &Path, tag: [u8; 4]) -> Result<EventReadIter> {
    Ok(EventReadIter(read_iter::<WireEntry>(path, tag)?))
}

/// Whole-file convenience: collect every `(Event, data)` pair into a
/// `Vec`. For files larger than what fits comfortably in RAM, reach for
/// [`read_event_iter`] directly.
pub fn read_all_events(path: &Path, tag: [u8; 4]) -> Result<Vec<(Event, Option<Vec<u8>>)>> {
    read_event_iter(path, tag)?.collect()
}

/// Streaming appender for events. Always flushes per call so a crash
/// loses at most this single entry.
pub struct EventWriter(Writer<WireEntry>);

impl EventWriter {
    /// Encode and append one event. `data` is the binary buffer from
    /// `send(payload, data)` (or `None` for plain `send(payload)` / log
    /// / error events).
    pub fn append(&mut self, evt: &Event, data: Option<&[u8]>) -> Result<()> {
        let entry = WireEntry::from_event(evt, data)?;
        self.0.append(&entry)
    }

    pub fn path(&self) -> &Path {
        self.0.path()
    }
}

/// Iterator over `(Event, Option<Vec<u8>>)`. See [`read_event_iter`].
pub struct EventReadIter(ReadIter<WireEntry>);

impl EventReadIter {
    pub fn bytes_read(&self) -> u64 {
        self.0.bytes_read()
    }
}

impl Iterator for EventReadIter {
    type Item = Result<(Event, Option<Vec<u8>>)>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.0.next()? {
            Ok(entry) => Some(entry.into_event()),
            Err(e) => Some(Err(e)),
        }
    }
}

// ── wire types ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireEntry {
    event: WireEvent,
    data: Option<Vec<u8>>,
}

/// Mirror of [`Event`] with JSON-string payloads. Externally tagged
/// (the serde default) — internally tagged enums require
/// `deserialize_any`, which bincode (non-self-describing) rejects.
/// Variant index goes on the wire as a single byte, which is also more
/// compact than a 4-letter discriminant string.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum WireEvent {
    Send {
        payload_json: String,
    },
    Log {
        level: LogLevel,
        message: String,
    },
    Error {
        description: String,
        stack: String,
        file_name: String,
        line_number: usize,
        column_number: usize,
    },
    Unknown {
        json: String,
    },
}

impl WireEntry {
    fn from_event(evt: &Event, data: Option<&[u8]>) -> Result<Self> {
        let wire = match evt {
            Event::Send { payload } => WireEvent::Send {
                payload_json: serde_json::to_string(payload)
                    .map_err(|e| Error::Record(format!("serialize send payload: {e}")))?,
            },
            Event::Log { level, message } => WireEvent::Log {
                level: *level,
                message: message.clone(),
            },
            Event::Error {
                description,
                stack,
                file_name,
                line_number,
                column_number,
            } => WireEvent::Error {
                description: description.clone(),
                stack: stack.clone(),
                file_name: file_name.clone(),
                line_number: *line_number,
                column_number: *column_number,
            },
            Event::Unknown(v) => WireEvent::Unknown {
                json: serde_json::to_string(v)
                    .map_err(|e| Error::Record(format!("serialize unknown value: {e}")))?,
            },
        };
        Ok(Self {
            event: wire,
            data: data.map(<[u8]>::to_vec),
        })
    }

    fn into_event(self) -> Result<(Event, Option<Vec<u8>>)> {
        let evt = match self.event {
            WireEvent::Send { payload_json } => {
                let payload: Value = serde_json::from_str(&payload_json)
                    .map_err(|e| Error::Record(format!("parse send payload: {e}")))?;
                Event::Send { payload }
            }
            WireEvent::Log { level, message } => Event::Log { level, message },
            WireEvent::Error {
                description,
                stack,
                file_name,
                line_number,
                column_number,
            } => Event::Error {
                description,
                stack,
                file_name,
                line_number,
                column_number,
            },
            WireEvent::Unknown { json } => {
                let v: Value = serde_json::from_str(&json)
                    .map_err(|e| Error::Record(format!("parse unknown value: {e}")))?;
                Event::Unknown(v)
            }
        };
        Ok((evt, self.data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    const TAG: [u8; 4] = *b"TEST";

    fn sample_send() -> Event {
        Event::Send {
            payload: json!({
                "action": "request",
                "url": "/cgi-bin/foo",
                "id": 42,
                "length": 128,
            }),
        }
    }

    #[test]
    fn round_trip_send_with_data() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("evt.bin");
        let mut w = create_event_writer(path.clone(), TAG).unwrap();
        let data = vec![0xaa, 0xbb, 0xcc, 0xdd];
        w.append(&sample_send(), Some(&data)).unwrap();
        drop(w);

        let events = read_all_events(&path, TAG).unwrap();
        assert_eq!(events.len(), 1);
        let (evt, got_data) = &events[0];
        match evt {
            Event::Send { payload } => {
                assert_eq!(payload.get("action").and_then(|v| v.as_str()), Some("request"));
                assert_eq!(payload.get("id").and_then(|v| v.as_u64()), Some(42));
            }
            _ => panic!("expected Send, got {evt:?}"),
        }
        assert_eq!(got_data.as_deref(), Some(data.as_slice()));
    }

    #[test]
    fn round_trip_send_without_data() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("evt.bin");
        let mut w = create_event_writer(path.clone(), TAG).unwrap();
        w.append(&sample_send(), None).unwrap();
        drop(w);

        let events = read_all_events(&path, TAG).unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0].1.is_none());
    }

    #[test]
    fn round_trip_log_and_error() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("diag.bin");
        let mut w = create_event_writer(path.clone(), TAG).unwrap();
        w.append(
            &Event::Log {
                level: LogLevel::Warning,
                message: "heads up".into(),
            },
            None,
        )
        .unwrap();
        w.append(
            &Event::Error {
                description: "boom".into(),
                stack: "at line 1".into(),
                file_name: "hook.js".into(),
                line_number: 1,
                column_number: 2,
            },
            None,
        )
        .unwrap();
        drop(w);

        let events = read_all_events(&path, TAG).unwrap();
        assert_eq!(events.len(), 2);
        matches!(events[0].0, Event::Log { .. });
        matches!(events[1].0, Event::Error { .. });
    }

    #[test]
    fn many_messages_stream() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("many.bin");
        let mut w = create_event_writer(path.clone(), TAG).unwrap();
        for i in 0..50 {
            let data = vec![i as u8; (i * 8) as usize];
            w.append(&sample_send(), Some(&data)).unwrap();
        }
        drop(w);

        let iter = read_event_iter(&path, TAG).unwrap();
        let mut count = 0;
        for item in iter {
            let (_, data) = item.unwrap();
            assert_eq!(data.unwrap().len(), count * 8);
            count += 1;
        }
        assert_eq!(count, 50);
    }

    #[test]
    fn wrong_tag_errors() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("tag.bin");
        let mut w = create_event_writer(path.clone(), *b"AAAA").unwrap();
        w.append(&sample_send(), None).unwrap();
        drop(w);
        assert!(read_all_events(&path, *b"BBBB").is_err());
    }
}
