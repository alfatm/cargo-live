//! API tokens. Only the SHA-256 of each token is stored.

use std::fs;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use cargo_live_proto::{hex, is_token_name, TOKEN_PREFIX};

use crate::Result;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TokenEntry {
    pub name: String,
    pub sha256: String,
    pub created: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenFile {
    #[serde(default, rename = "token")]
    pub tokens: Vec<TokenEntry>,
}

pub fn generate_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| format!("OS random number generator failed: {e}"))?;
    Ok(format!(
        "{TOKEN_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    ))
}

pub fn hash_token(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

impl TokenFile {
    pub fn load(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(text) => {
                let file: TokenFile = toml::from_str(&text)
                    .map_err(|e| format!("invalid {}: {e}", path.display()))?;
                Ok(file)
            }
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("cannot read {}: {e}", path.display()).into()),
        }
    }

    /// Writes the file atomically with mode 0600.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        let text = toml::to_string(self)?;
        let tmp = path.with_extension("toml.tmp");
        let _ = fs::remove_file(&tmp);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Adds a token and returns its plaintext.
    pub fn create(&mut self, name: &str, created: String) -> Result<String> {
        if !is_token_name(name) {
            return Err(
                "token names may contain letters, digits, '-', '_' and '.' (max 64)".into(),
            );
        }
        if self.tokens.iter().any(|t| t.name == name) {
            return Err(format!("a token named {name:?} already exists").into());
        }
        let token = generate_token()?;
        self.tokens.push(TokenEntry {
            name: name.to_owned(),
            sha256: hash_token(&token),
            created,
        });
        Ok(token)
    }

    pub fn revoke(&mut self, name: &str) -> Result<()> {
        let before = self.tokens.len();
        self.tokens.retain(|t| t.name != name);
        if self.tokens.len() == before {
            return Err(format!("no token named {name:?}").into());
        }
        Ok(())
    }

    /// Returns the name of the token matching `presented`. Compares every
    /// stored hash in constant time.
    pub fn verify(&self, presented: &str) -> Option<&str> {
        let hash = hash_token(presented);
        let mut found = None;
        for entry in &self.tokens {
            let equal: bool = entry.sha256.as_bytes().ct_eq(hash.as_bytes()).into();
            if equal && found.is_none() && is_token_name(&entry.name) {
                found = Some(entry.name.as_str());
            }
        }
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn tokens_have_expected_format() {
        let token = generate_token().unwrap();
        assert!(token.starts_with("clt_"));
        assert_eq!(token.len(), 4 + 43);
        assert_ne!(token, generate_token().unwrap());
    }

    #[test]
    fn create_verify_revoke() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/tokens.toml");
        let mut file = TokenFile::load(&path).unwrap();
        let alice = file.create("alice", "t".into()).unwrap();
        let bob = file.create("bob", "t".into()).unwrap();
        assert!(file.create("alice", "t".into()).is_err());
        assert!(file.create("../x", "t".into()).is_err());
        file.save(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains(&alice), "plaintext token stored");
        assert!(text.contains(&hash_token(&alice)));

        let mut file = TokenFile::load(&path).unwrap();
        assert_eq!(file.verify(&alice), Some("alice"));
        assert_eq!(file.verify(&bob), Some("bob"));
        assert_eq!(file.verify("clt_wrong"), None);
        assert_eq!(file.verify(""), None);
        file.revoke("alice").unwrap();
        assert!(file.revoke("alice").is_err());
        assert_eq!(file.verify(&alice), None);
    }
}
