//! What the consumer actually sees.
//!
//! Frida's own `Message` enum is strict: `Message::Send` only fires when the
//! payload matches a hard-coded `{type:String, id, result, returns}` shape,
//! which is the frida-internal RPC schema. A plain `send({...})` from JS
//! falls through to `Message::Other` with a serde error and a raw JSON
//! string buried inside — useless without a second parse pass.
//!
//! `Event` smooths this over: any `send()` from JS lands in `Event::Send`
//! with the JS-side payload as an untyped `serde_json::Value`, so the
//! consumer can `.get("url").and_then(|v| v.as_str())` etc. without
//! re-parsing themselves.

use serde::Serialize;
use serde_json::Value;

/// Normalized script event.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    /// A `send(payload, data)` call from the JS side. `payload` is whatever
    /// shape the script chose to emit.
    Send { payload: Value },

    /// `console.log` / `console.warn` / `console.error` from the script.
    Log { level: LogLevel, message: String },

    /// JS runtime error.
    Error {
        description: String,
        stack: String,
        file_name: String,
        line_number: usize,
        column_number: usize,
    },

    /// Unrecognized message — frida sent something we couldn't classify.
    /// The raw value is preserved so users can inspect it.
    Unknown(Value),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Info,
    Debug,
    Warning,
    Error,
}

impl Event {
    /// Translate from frida's native `Message`. Non-RPC sends arrive via
    /// `Message::Other` (frida-rust's strict deserializer rejected them);
    /// dig the raw JSON out of the `data` field and re-parse to recover the
    /// `Event::Send` we wanted in the first place.
    pub(crate) fn from_frida(msg: &frida::Message) -> Self {
        match msg {
            frida::Message::Send(s) => {
                // SendPayload only impls Deserialize — re-pack the fields by
                // hand so we can present the consumer a uniform `Value`.
                let payload = serde_json::json!({
                    "type": s.payload.r#type,
                    "id": s.payload.id,
                    "result": s.payload.result,
                    "returns": s.payload.returns,
                });
                Event::Send { payload }
            }
            frida::Message::Log(l) => Event::Log {
                level: log_level_from_frida(&l.level),
                message: l.payload.clone(),
            },
            frida::Message::Error(e) => Event::Error {
                description: e.description.clone(),
                stack: e.stack.clone(),
                file_name: e.file_name.clone(),
                line_number: e.line_number,
                column_number: e.column_number,
            },
            frida::Message::Other(v) => Self::from_other(v),
        }
    }

    fn from_other(v: &Value) -> Self {
        // The frida crate's fallback wraps the raw JSON string in
        // `{"data": "<json>", "error": "<serde err>"}`. Pull the inner.
        let inner_str = match v.get("data").and_then(|d| d.as_str()) {
            Some(s) => s,
            None => return Event::Unknown(v.clone()),
        };
        let parsed: Value = match serde_json::from_str(inner_str) {
            Ok(p) => p,
            Err(_) => return Event::Unknown(v.clone()),
        };

        match parsed.get("type").and_then(|t| t.as_str()).unwrap_or("") {
            "send" => Event::Send {
                payload: parsed.get("payload").cloned().unwrap_or(Value::Null),
            },
            "log" => Event::Log {
                level: parsed
                    .get("level")
                    .and_then(|l| l.as_str())
                    .map(parse_level)
                    .unwrap_or(LogLevel::Info),
                message: parsed
                    .get("payload")
                    .and_then(|p| p.as_str())
                    .unwrap_or("")
                    .to_string(),
            },
            "error" => Event::Error {
                description: str_field(&parsed, "description"),
                stack: str_field(&parsed, "stack"),
                file_name: str_field(&parsed, "fileName"),
                line_number: u64_field(&parsed, "lineNumber") as usize,
                column_number: u64_field(&parsed, "columnNumber") as usize,
            },
            _ => Event::Unknown(parsed),
        }
    }
}

fn log_level_from_frida(l: &frida::MessageLogLevel) -> LogLevel {
    match l {
        frida::MessageLogLevel::Info => LogLevel::Info,
        frida::MessageLogLevel::Debug => LogLevel::Debug,
        frida::MessageLogLevel::Warning => LogLevel::Warning,
        frida::MessageLogLevel::Error => LogLevel::Error,
    }
}

fn parse_level(s: &str) -> LogLevel {
    match s {
        "debug" => LogLevel::Debug,
        "warning" | "warn" => LogLevel::Warning,
        "error" => LogLevel::Error,
        _ => LogLevel::Info,
    }
}

fn str_field(v: &Value, key: &str) -> String {
    v.get(key).and_then(|x| x.as_str()).unwrap_or("").to_string()
}

fn u64_field(v: &Value, key: &str) -> u64 {
    v.get(key).and_then(|x| x.as_u64()).unwrap_or(0)
}
