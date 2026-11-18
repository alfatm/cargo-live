//! `<data_dir>/audit.log`: one JSON line per credential decision and per
//! proxied network connection (0600). Entries never contain secrets or
//! payloads.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use serde::Serialize;

use cargo_live_proto::cred::format_rfc3339;

use crate::log;

#[derive(Debug, Serialize)]
pub struct Entry<'a> {
    pub ts: String,
    pub token: &'a str,
    pub workspace: &'a str,
    pub kind: String,
    pub scope: String,
    pub phase: String,
    /// `agent:<name>`, `client`, or `none`.
    pub source: &'a str,
    /// `served`, `cached` or `denied`.
    pub outcome: &'a str,
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub chain: Vec<String>,
}

pub fn record(path: &Path, entry: &Entry<'_>) {
    let expires = entry
        .expires_at
        .as_deref()
        .map(|e| format!(" expires_at={e}"))
        .unwrap_or_default();
    let chain = if entry.chain.is_empty() {
        String::new()
    } else {
        format!(" ({})", entry.chain.join("; "))
    };
    log!(
        "credential: token={} workspace={} {} {} phase={} source={} outcome={}{expires}{chain}",
        entry.token,
        short(entry.workspace),
        entry.kind,
        entry.scope,
        entry.phase,
        entry.source,
        entry.outcome
    );
    append(path, entry);
}

/// One proxied connection (`kind = "network"`), written when it closes or
/// is refused.
#[derive(Debug, Serialize)]
pub struct NetEntry<'a> {
    pub ts: String,
    pub token: &'a str,
    pub workspace: &'a str,
    /// Always `network`.
    pub kind: &'static str,
    pub host: &'a str,
    pub port: u16,
    pub phase: String,
    /// `agent` (direct), `client` (tunnel) or `none` (refused).
    pub via: &'a str,
    /// `closed`, `idle-timeout`, `error`, `step-ended` (still open when
    /// the build step ended, e.g. a keep-alive connection) or `denied`.
    pub outcome: &'a str,
    pub bytes_up: u64,
    pub bytes_down: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub chain: Vec<String>,
}

pub fn record_net(path: &Path, entry: &NetEntry<'_>) {
    let chain = if entry.chain.is_empty() {
        String::new()
    } else {
        format!(" ({})", entry.chain.join("; "))
    };
    log!(
        "network: token={} workspace={} {} phase={} via={} outcome={} up={} down={}{chain}",
        entry.token,
        short(entry.workspace),
        cargo_live_proto::net::Destination {
            host: entry.host.to_owned(),
            port: entry.port
        },
        entry.phase,
        entry.via,
        entry.outcome,
        entry.bytes_up,
        entry.bytes_down
    );
    append(path, entry);
}

fn append(path: &Path, entry: &impl Serialize) {
    let Ok(mut line) = serde_json::to_string(entry) else {
        return;
    };
    line.push('\n');
    let result = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .and_then(|mut f| f.write_all(line.as_bytes()));
    if let Err(e) = result {
        log!("cannot write {}: {e}", path.display());
    }
}

pub fn expires(at: Option<i64>) -> Option<String> {
    at.map(format_rfc3339)
}

fn short(ws: &str) -> &str {
    ws.get(..12).unwrap_or(ws)
}
