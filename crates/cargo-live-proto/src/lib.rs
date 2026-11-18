//! Protocol shared by `cargo-live` (client) and `cargo-live-agent` (server).
//!
//! Both sides talk over a single SSH session channel opened with the exec
//! request [`CHANNEL_NAME`]. Every message is a frame: a big-endian `u32`
//! payload length followed by a postcard-encoded [`ClientMsg`] or
//! [`AgentMsg`].
//!
//! Compatibility: `ClientMsg::Hello`, `AgentMsg::Welcome` and
//! `AgentMsg::Error` must keep their variant index and fields forever so that
//! mismatched versions can still report the mismatch.

pub mod cred;
mod exclude;
mod frame;
mod path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use cred::{CredEvent, Credential, CredentialPolicy, ExplainStep, Phase, Scope};

pub use exclude::{ExcludeError, ExcludeSet};
pub use frame::{decode, encode, read_frame, write_frame, FrameError, FrameReader, MAX_FRAME};
pub use path::{is_token_name, is_workspace_id, validate_relative_path, PathError};

/// Bumped on every incompatible protocol change.
pub const PROTOCOL_VERSION: u32 = 2;
/// The SSH exec/subsystem name the agent accepts.
pub const CHANNEL_NAME: &str = "cargo-live";
/// The SSH user name; the password is the API token.
pub const USERNAME: &str = "cargo-live";
pub const DEFAULT_PORT: u16 = 2222;
/// Size of file and binary chunks.
pub const CHUNK_SIZE: usize = 256 * 1024;
/// Prefix of API tokens.
pub const TOKEN_PREFIX: &str = "clt_";
/// The target triple the current binary was compiled for.
pub const BUILD_TARGET: &str = env!("CARGO_LIVE_BUILD_TARGET");

/// Messages sent by the client.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ClientMsg {
    /// Must stay variant 0.
    Hello {
        protocol_version: u32,
        client_version: String,
    },
    Open {
        workspace_id: String,
    },
    Manifest {
        entries: Vec<Entry>,
    },
    /// Contents of the next file listed in `AgentMsg::Need`, in order.
    FileChunk(Vec<u8>),
    /// Ends the current file; `ok` is false if the client could not read it.
    FileEnd {
        ok: bool,
    },
    Build(BuildRequest),
    Fetch {
        executable: String,
        known_blake3: Option<String>,
    },
    /// Credential rules, the forwarding allowlist and registry definitions.
    /// Sent after `Opened` (or before `Explain`); replaces earlier policy.
    CredentialPolicy(CredentialPolicy),
    /// Answer to `AgentMsg::CredentialRequest`. The error is a short reason.
    CredentialResponse {
        id: u64,
        result: Result<Credential, String>,
    },
    /// Dry run of the credential resolution for `scope`.
    Explain {
        scope: Scope,
    },
}

/// Messages sent by the agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AgentMsg {
    /// Must stay variant 0.
    Welcome(Welcome),
    /// Must stay variant 1. Fatal; the agent closes the channel afterwards.
    Error {
        message: String,
    },
    Waiting {
        reason: WaitReason,
    },
    Opened {
        /// The source mirror as the agent names it.
        source_dir: String,
        /// The same directory with symlinks resolved.
        source_dir_physical: String,
    },
    Need {
        paths: Vec<String>,
    },
    Synced(SyncStats),
    /// One line of Cargo's stdout, without the line terminator.
    Stdout(String),
    Stderr(Vec<u8>),
    /// Cargo exited. Signals are reported as 128 + signal number.
    Exit {
        code: i32,
    },
    /// The executable `cargo run` would have started, and the environment
    /// variables Cargo set for it.
    RunTarget {
        executable: String,
        env: Vec<(String, String)>,
    },
    BinaryInfo {
        blake3: String,
        size: u64,
        mode: u32,
    },
    BinaryChunk(Vec<u8>),
    BinaryEnd,
    /// Asks the client to resolve a credential (`client` source). May be
    /// interleaved with `Stdout`/`Stderr` during a build.
    CredentialRequest {
        id: u64,
        scope: Scope,
        phase: Phase,
    },
    /// A credential decision, for the client's stderr line.
    CredentialEvent(CredEvent),
    /// Answer to `ClientMsg::Explain`.
    ExplainResult {
        steps: Vec<ExplainStep>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Welcome {
    pub protocol_version: u32,
    pub agent_version: String,
    /// Output of `rustc -vV` on the agent.
    pub rustc_vv: String,
    pub host_triple: String,
    pub glibc_version: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WaitReason {
    WorkspaceLock,
    BuildSlot,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncStats {
    pub files_written: u64,
    pub bytes_written: u64,
    pub deleted: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BuildCommand {
    Run,
    Check,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildRequest {
    pub command: BuildCommand,
    /// `+toolchain` without the plus sign, passed to the remote rustup proxy.
    pub toolchain: Option<String>,
    /// Cargo arguments after the subcommand.
    pub args: Vec<String>,
    /// Working directory relative to the workspace root ("" for the root).
    pub relative_cwd: String,
    /// Whether the client forwards JSON messages (otherwise it renders them).
    pub json_output: bool,
}

/// One entry of the client's workspace listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Relative path with `/` separators.
    pub path: String,
    pub kind: EntryKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryKind {
    Dir,
    File {
        size: u64,
        /// Modification time in nanoseconds since the Unix epoch.
        mtime_ns: i64,
        executable: bool,
    },
    Symlink {
        target: String,
    },
}

/// Lowercase hexadecimal encoding.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// SHA-256 as lowercase hex.
pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// OpenSSH-style fingerprint (`SHA256:<unpadded base64>`) of a public key in
/// SSH wire encoding.
pub fn fingerprint(public_key_blob: &[u8]) -> String {
    use base64::Engine;
    let digest = Sha256::digest(public_key_blob);
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
    )
}

/// Parses a dotted version such as `2.39` for comparison.
pub fn parse_version(version: &str) -> Option<Vec<u32>> {
    version
        .trim()
        .split('.')
        .map(|part| part.parse().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_matches_openssh_format() {
        // `ssh-keygen -lf` of an all-zero Ed25519 key blob.
        let mut blob = Vec::new();
        blob.extend_from_slice(&11u32.to_be_bytes());
        blob.extend_from_slice(b"ssh-ed25519");
        blob.extend_from_slice(&32u32.to_be_bytes());
        blob.extend_from_slice(&[0; 32]);
        let fp = fingerprint(&blob);
        assert!(fp.starts_with("SHA256:"));
        assert_eq!(fp.len(), 7 + 43);
        assert!(!fp.ends_with('='));
    }

    #[test]
    fn hex_and_versions() {
        assert_eq!(hex(&[0, 0xab, 0x10]), "00ab10");
        assert_eq!(sha256_hex(b"").len(), 64);
        assert!(parse_version("2.31").unwrap() < parse_version("2.39").unwrap());
        assert!(parse_version("2.9").unwrap() < parse_version("2.10").unwrap());
        assert_eq!(parse_version("x"), None);
    }
}
