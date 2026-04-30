// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: Elastic-2.0

//! Structured-JSON log shipper for the relay.
//!
//! Same envelope shape as the edge shipper so a single SIEM pipeline can
//! ingest events from edge + relay + manager unchanged. The relay's
//! `Event` type carries fewer scoped IDs than the edge's (only
//! `flow_id` — there is no input/output concept here), so `input_id` and
//! `output_id` always render as `null`. The category namespace is
//! distinct (`edge` / `tunnel` / `manager`) so SIEM rules can route by
//! source project.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{Map, Value, json};
use tokio::sync::mpsc;

use crate::config::{JsonLogTarget, LogFormat, LoggingConfig};
use crate::manager::events::{Event, EventSeverity};

const SHIPPER_CHANNEL_CAPACITY: usize = 2048;

#[derive(Clone, Debug)]
pub struct JsonLogShipper {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    tx: mpsc::Sender<Vec<u8>>,
    drop_total: AtomicU64,
    drop_pending: AtomicU64,
    last_warn_us: AtomicU64,
    static_fields: StaticFields,
    format: LogFormat,
}

#[derive(Clone, Debug)]
struct StaticFields {
    relay_id: String,
    software_version: &'static str,
    host: String,
}

impl JsonLogShipper {
    pub fn from_config(
        cfg: &LoggingConfig,
        relay_id: String,
        software_version: &'static str,
    ) -> Result<Option<Self>> {
        let Some(target) = cfg.json_target.clone() else {
            return Ok(None);
        };
        let static_fields = StaticFields {
            relay_id,
            software_version,
            host: hostname(),
        };
        let format = match &target {
            JsonLogTarget::Stdout { format }
            | JsonLogTarget::File { format, .. }
            | JsonLogTarget::Syslog { format, .. } => *format,
        };
        let (tx, rx) = mpsc::channel::<Vec<u8>>(SHIPPER_CHANNEL_CAPACITY);
        spawn_writer_task(target, rx)?;
        Ok(Some(Self {
            inner: Arc::new(Inner {
                tx,
                drop_total: AtomicU64::new(0),
                drop_pending: AtomicU64::new(0),
                last_warn_us: AtomicU64::new(0),
                static_fields,
                format,
            }),
        }))
    }

    pub fn ship_event(&self, event: &Event) {
        let line = self.render_line(event);
        if let Err(mpsc::error::TrySendError::Full(_)) = self.inner.tx.try_send(line) {
            self.inner.note_drop();
        }
    }

    fn render_line(&self, event: &Event) -> Vec<u8> {
        let envelope = build_envelope(&self.inner.static_fields, event, self.inner.format);
        let mut line = serde_json::to_vec(&envelope).unwrap_or_else(|_| {
            br#"{"level":"error","message":"log_shipper render failed"}"#.to_vec()
        });
        line.push(b'\n');
        line
    }
}

impl Inner {
    fn note_drop(&self) {
        self.drop_total.fetch_add(1, Ordering::Relaxed);
        let pending = self.drop_pending.fetch_add(1, Ordering::Relaxed) + 1;
        let now_us = monotonic_us();
        let last = self.last_warn_us.load(Ordering::Relaxed);
        if now_us.saturating_sub(last) >= 1_000_000
            && self
                .last_warn_us
                .compare_exchange(last, now_us, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            let pending_now = self.drop_pending.swap(0, Ordering::Relaxed);
            tracing::warn!(
                pending = pending_now,
                total = self.drop_total.load(Ordering::Relaxed),
                capacity = SHIPPER_CHANNEL_CAPACITY,
                "json log shipper queue full — dropping events ({} since last warn)",
                pending,
            );
        }
    }
}

#[derive(Serialize)]
struct Envelope<'a> {
    ts: String,
    level: &'a str,
    host: &'a str,
    software_version: &'a str,
    /// Source project — `edge` / `relay` / `manager`. Lets a SIEM rule
    /// route events by project without parsing the category.
    source: &'static str,
    /// Project-specific node identity. For the relay this is its
    /// manager-assigned `node_id` (or `"unknown"` when running standalone).
    relay_id: &'a str,
    flow_id: Option<&'a str>,
    input_id: Option<&'a str>,
    output_id: Option<&'a str>,
    category: &'a str,
    error_code: Option<String>,
    message: &'a str,
    details: Option<Value>,
}

fn build_envelope(static_fields: &StaticFields, event: &Event, format: LogFormat) -> Value {
    let level = match event.severity {
        EventSeverity::Info => "info",
        EventSeverity::Warning => "warning",
        EventSeverity::Critical => "critical",
    };
    let error_code = event
        .details
        .as_ref()
        .and_then(|d| d.get("error_code").and_then(|v| v.as_str()))
        .map(String::from);
    let envelope = Envelope {
        ts: format_rfc3339_now(),
        level,
        host: &static_fields.host,
        software_version: static_fields.software_version,
        source: "relay",
        relay_id: &static_fields.relay_id,
        flow_id: event.flow_id.as_deref(),
        input_id: None,
        output_id: None,
        category: &event.category,
        error_code: error_code.clone(),
        message: &event.message,
        details: event.details.clone(),
    };
    let raw = serde_json::to_value(&envelope).unwrap_or(Value::Null);
    apply_format(raw, format, error_code)
}

fn apply_format(raw: Value, format: LogFormat, error_code: Option<String>) -> Value {
    match format {
        LogFormat::Raw => raw,
        LogFormat::Splunk => json!({ "event": raw }),
        LogFormat::Dataminer => {
            let mut obj: Map<String, Value> = match raw {
                Value::Object(m) => m,
                other => return other,
            };
            obj.remove("error_code");
            if let Some(code) = error_code {
                obj.insert("parameter_id".to_string(), Value::String(code));
            }
            Value::Object(obj)
        }
    }
}

fn format_rfc3339_now() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let secs = now.as_secs() as i64;
    let micros = now.subsec_micros();
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, micros * 1000)
        .unwrap_or_else(chrono::Utc::now)
        .to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

fn monotonic_us() -> u64 {
    use std::time::Instant;
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let start = *START.get_or_init(Instant::now);
    Instant::now().saturating_duration_since(start).as_micros() as u64
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "unknown".to_string())
}

fn spawn_writer_task(target: JsonLogTarget, mut rx: mpsc::Receiver<Vec<u8>>) -> Result<()> {
    match target {
        JsonLogTarget::Stdout { .. } => {
            tokio::spawn(async move {
                let mut stdout = tokio::io::stdout();
                while let Some(line) = rx.recv().await {
                    use tokio::io::AsyncWriteExt;
                    if stdout.write_all(&line).await.is_err() {
                        break;
                    }
                }
            });
        }
        JsonLogTarget::File {
            path,
            max_size_mb,
            max_backups,
            ..
        } => {
            let path_buf = PathBuf::from(&path);
            let max_size_bytes = (max_size_mb as u64).saturating_mul(1024 * 1024);
            if let Some(parent) = path_buf.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path_buf)
                .with_context(|| format!("opening log_shipper file at {}", path_buf.display()))?;
            let initial_len = file.metadata().map(|m| m.len()).unwrap_or(0);
            tokio::task::spawn_blocking(move || {
                writer_task_file_blocking(rx, path_buf, file, initial_len, max_size_bytes, max_backups)
            });
        }
        JsonLogTarget::Syslog { addr, .. } => {
            let std_socket = std::net::UdpSocket::bind("0.0.0.0:0")
                .with_context(|| "binding ephemeral UDP for syslog log_shipper")?;
            std_socket
                .set_nonblocking(true)
                .with_context(|| "setting UDP socket nonblocking")?;
            let socket = tokio::net::UdpSocket::from_std(std_socket)
                .with_context(|| "wrapping UDP socket for syslog log_shipper")?;
            let target_addr: std::net::SocketAddr = addr
                .parse()
                .with_context(|| format!("parsing syslog addr '{addr}'"))?;
            tokio::spawn(async move {
                while let Some(line) = rx.recv().await {
                    let mut framed = Vec::with_capacity(line.len() + 16);
                    framed.extend_from_slice(b"<134>1 ");
                    framed.extend_from_slice(&line);
                    let _ = socket.send_to(&framed, target_addr).await;
                }
            });
        }
    }
    Ok(())
}

fn writer_task_file_blocking(
    mut rx: mpsc::Receiver<Vec<u8>>,
    path: PathBuf,
    mut file: std::fs::File,
    mut size: u64,
    max_size_bytes: u64,
    max_backups: u32,
) {
    while let Some(line) = rx.blocking_recv() {
        if size.saturating_add(line.len() as u64) > max_size_bytes {
            if let Err(e) = rotate_file(&path, max_backups) {
                tracing::warn!(error = %e, path = %path.display(), "log_shipper file rotation failed");
            } else {
                match std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                {
                    Ok(f) => {
                        file = f;
                        size = 0;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, path = %path.display(), "log_shipper reopen after rotation failed");
                    }
                }
            }
        }
        if let Err(e) = file.write_all(&line) {
            tracing::warn!(error = %e, path = %path.display(), "log_shipper file write failed");
            continue;
        }
        size = size.saturating_add(line.len() as u64);
    }
}

fn rotate_file(path: &PathBuf, max_backups: u32) -> std::io::Result<()> {
    if max_backups == 0 {
        return std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
            .map(|_| ());
    }
    let oldest = backup_path(path, max_backups);
    let _ = std::fs::remove_file(&oldest);
    for n in (1..max_backups).rev() {
        let from = backup_path(path, n);
        let to = backup_path(path, n + 1);
        if from.exists() {
            std::fs::rename(&from, &to)?;
        }
    }
    if path.exists() {
        std::fs::rename(path, backup_path(path, 1))?;
    }
    Ok(())
}

fn backup_path(path: &PathBuf, n: u32) -> PathBuf {
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("log");
    path.with_extension(format!("{ext}.{n}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::events::{Event, EventSeverity};
    use serde_json::json;

    fn make_event(category: &str, error_code: Option<&str>) -> Event {
        Event {
            severity: EventSeverity::Critical,
            category: category.to_string(),
            message: "boom".to_string(),
            details: error_code.map(|c| json!({ "error_code": c })),
            flow_id: Some("tunnel-1".to_string()),
        }
    }

    fn static_fields() -> StaticFields {
        StaticFields {
            relay_id: "relay-test".to_string(),
            software_version: "0.0.0-test",
            host: "test-host".to_string(),
        }
    }

    #[test]
    fn raw_envelope_carries_required_fields_with_relay_source() {
        let ev = make_event("tunnel", Some("bind_auth_failed"));
        let env = build_envelope(&static_fields(), &ev, LogFormat::Raw);
        assert_eq!(env["level"], "critical");
        assert_eq!(env["source"], "relay");
        assert_eq!(env["relay_id"], "relay-test");
        assert_eq!(env["category"], "tunnel");
        assert_eq!(env["error_code"], "bind_auth_failed");
        assert_eq!(env["flow_id"], "tunnel-1");
        assert!(env["input_id"].is_null());
        assert!(env["output_id"].is_null());
        assert!(env["ts"].is_string());
    }

    #[test]
    fn dataminer_format_renames_error_code() {
        let ev = make_event("tunnel", Some("bind_auth_failed"));
        let env = build_envelope(&static_fields(), &ev, LogFormat::Dataminer);
        assert!(env.get("error_code").is_none());
        assert_eq!(env["parameter_id"], "bind_auth_failed");
    }
}
