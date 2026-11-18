//! Client-side files: known host keys, credentials and the binary cache.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{error, Result};

fn xdg_dir(var: &str, fallback: &str) -> Result<PathBuf> {
    if let Some(path) = env::var_os(var).filter(|v| !v.is_empty()) {
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            return Err(error(format!("{var} must be absolute")).into());
        }
        return Ok(path.join("cargo-live"));
    }
    let home = env::var_os("HOME").ok_or_else(|| error("HOME is not set"))?;
    Ok(PathBuf::from(home).join(fallback).join("cargo-live"))
}

pub fn config_dir() -> Result<PathBuf> {
    xdg_dir("XDG_CONFIG_HOME", ".config")
}

pub fn cache_dir() -> Result<PathBuf> {
    xdg_dir("XDG_CACHE_HOME", ".cache")
}

/// Writes `contents` to `path` atomically with mode 0600.
pub fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    let _ = fs::remove_file(&tmp);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path)?;
    Ok(())
}

fn read_optional(path: &Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(error(format!("cannot read {}: {e}", path.display())).into()),
    }
}

/// Result of looking up a host key.
#[derive(Debug, PartialEq, Eq)]
pub enum HostKeyStatus {
    Known,
    Unknown,
    Mismatch { expected: String },
}

/// `host:port SHA256:...` lines.
pub struct KnownHosts {
    pub path: PathBuf,
}

impl KnownHosts {
    pub fn default_location() -> Result<Self> {
        Ok(Self {
            path: config_dir()?.join("known_hosts"),
        })
    }

    fn entries(&self) -> Result<Vec<(String, String)>> {
        Ok(read_optional(&self.path)?
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
            .filter_map(|l| {
                let mut parts = l.split_whitespace();
                Some((parts.next()?.to_owned(), parts.next()?.to_owned()))
            })
            .collect())
    }

    pub fn check(&self, host: &str, fingerprint: &str) -> Result<HostKeyStatus> {
        match self.entries()?.into_iter().find(|(h, _)| h == host) {
            None => Ok(HostKeyStatus::Unknown),
            Some((_, fp)) if fp == fingerprint => Ok(HostKeyStatus::Known),
            Some((_, expected)) => Ok(HostKeyStatus::Mismatch { expected }),
        }
    }

    pub fn learn(&self, host: &str, fingerprint: &str) -> Result<()> {
        let mut text = read_optional(&self.path)?.unwrap_or_default();
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&format!("{host} {fingerprint}\n"));
        write_private(&self.path, text.as_bytes())
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialsFile {
    #[serde(default)]
    tokens: BTreeMap<String, String>,
}

/// Tokens keyed by canonical agent url.
pub struct Credentials {
    pub path: PathBuf,
}

pub const TOKEN_ENV: &str = "CARGO_LIVE_TOKEN";

impl Credentials {
    pub fn default_location() -> Result<Self> {
        Ok(Self {
            path: config_dir()?.join("credentials.toml"),
        })
    }

    fn load(&self) -> Result<CredentialsFile> {
        match read_optional(&self.path)? {
            Some(text) => Ok(toml::from_str(&text)
                .map_err(|e| error(format!("invalid {}: {e}", self.path.display())))?),
            None => Ok(CredentialsFile::default()),
        }
    }

    /// `CARGO_LIVE_TOKEN` first, then the credentials file.
    pub fn lookup(&self, url: &str) -> Result<Option<String>> {
        if let Some(token) = env::var(TOKEN_ENV).ok().filter(|t| !t.is_empty()) {
            return Ok(Some(token));
        }
        self.lookup_file(url)
    }

    pub fn lookup_file(&self, url: &str) -> Result<Option<String>> {
        Ok(self.load()?.tokens.remove(url))
    }

    pub fn store(&self, url: &str, token: &str) -> Result<()> {
        let mut file = self.load()?;
        file.tokens.insert(url.to_owned(), token.to_owned());
        write_private(&self.path, toml::to_string(&file)?.as_bytes())
    }

    /// Returns whether a token was removed.
    pub fn remove(&self, url: &str) -> Result<bool> {
        let mut file = self.load()?;
        if file.tokens.remove(url).is_none() {
            return Ok(false);
        }
        write_private(&self.path, toml::to_string(&file)?.as_bytes())?;
        Ok(true)
    }
}

/// A cached executable with a `.blake3` sidecar (`<hash> <size> <mtime_ns>`).
pub struct CachedBinary {
    pub path: PathBuf,
}

impl CachedBinary {
    fn sidecar(&self) -> PathBuf {
        self.path.with_extension("blake3")
    }

    fn stamp(md: &fs::Metadata) -> (u64, i128) {
        use std::os::unix::fs::MetadataExt;
        (
            md.len(),
            i128::from(md.mtime()) * 1_000_000_000 + i128::from(md.mtime_nsec()),
        )
    }

    /// The BLAKE3 hash of the cached copy, if there is one. Uses the sidecar
    /// when size and mtime still match, and rehashes otherwise.
    pub fn hash(&self) -> Option<String> {
        let md = fs::symlink_metadata(&self.path).ok()?;
        if !md.is_file() {
            return None;
        }
        let (size, mtime) = Self::stamp(&md);
        if let Ok(text) = fs::read_to_string(self.sidecar()) {
            let parts: Vec<&str> = text.split_whitespace().collect();
            if let [hash, s, m] = parts[..] {
                if s.parse() == Ok(size) && m.parse() == Ok(mtime) {
                    return Some(hash.to_owned());
                }
            }
        }
        let mut hasher = blake3::Hasher::new();
        let mut file = fs::File::open(&self.path).ok()?;
        std::io::copy(&mut file, &mut hasher).ok()?;
        let hash = hasher.finalize().to_hex().to_string();
        self.write_sidecar(&hash);
        Some(hash)
    }

    fn write_sidecar(&self, hash: &str) {
        if let Ok(md) = fs::metadata(&self.path) {
            let (size, mtime) = Self::stamp(&md);
            let _ = fs::write(self.sidecar(), format!("{hash} {size} {mtime}\n"));
        }
    }

    /// Moves a verified download into place.
    pub fn install(&self, tmp: &Path, hash: &str) -> Result<()> {
        fs::set_permissions(tmp, fs::Permissions::from_mode(0o755))?;
        let _ = fs::remove_file(self.sidecar());
        fs::rename(tmp, &self.path)?;
        self.write_sidecar(hash);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const B: &str = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    #[test]
    fn known_hosts_trust_on_first_use() {
        let dir = tempfile::tempdir().unwrap();
        let kh = KnownHosts {
            path: dir.path().join("sub/known_hosts"),
        };
        assert_eq!(kh.check("h:2222", A).unwrap(), HostKeyStatus::Unknown);
        kh.learn("h:2222", A).unwrap();
        kh.learn("other:2222", B).unwrap();
        assert_eq!(kh.check("h:2222", A).unwrap(), HostKeyStatus::Known);
        assert_eq!(
            kh.check("h:2222", B).unwrap(),
            HostKeyStatus::Mismatch { expected: A.into() }
        );
        // Keyed by host:port.
        assert_eq!(kh.check("h:2223", B).unwrap(), HostKeyStatus::Unknown);
        let mode = fs::metadata(&kh.path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn credentials_store_and_remove() {
        let dir = tempfile::tempdir().unwrap();
        let creds = Credentials {
            path: dir.path().join("credentials.toml"),
        };
        assert_eq!(creds.lookup_file("h:2222").unwrap(), None);
        creds.store("h:2222", "clt_a").unwrap();
        creds.store("g:1", "clt_b").unwrap();
        assert_eq!(
            creds.lookup_file("h:2222").unwrap().as_deref(),
            Some("clt_a")
        );
        assert_eq!(creds.lookup_file("g:1").unwrap().as_deref(), Some("clt_b"));
        let mode = fs::metadata(&creds.path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(creds.remove("h:2222").unwrap());
        assert!(!creds.remove("h:2222").unwrap());
        assert_eq!(creds.lookup_file("h:2222").unwrap(), None);
        assert_eq!(creds.lookup_file("g:1").unwrap().as_deref(), Some("clt_b"));
    }

    #[test]
    fn cached_binary_hash_tracks_changes() {
        let dir = tempfile::tempdir().unwrap();
        let cached = CachedBinary {
            path: dir.path().join("bin"),
        };
        assert_eq!(cached.hash(), None);
        let tmp = dir.path().join("download");
        fs::write(&tmp, b"one").unwrap();
        let h1 = blake3::hash(b"one").to_hex().to_string();
        cached.install(&tmp, &h1).unwrap();
        assert_eq!(cached.hash().as_deref(), Some(h1.as_str()));
        fs::write(&cached.path, b"two!").unwrap();
        assert_eq!(
            cached.hash().unwrap(),
            blake3::hash(b"two!").to_hex().to_string()
        );
    }
}
