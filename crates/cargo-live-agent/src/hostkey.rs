//! The agent's Ed25519 host key.

use std::fs;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::ssh_key::LineEnding;
use russh::keys::{Algorithm, PrivateKey};

use crate::Result;

/// Loads the host key, generating it on first use. Returns whether it was
/// generated.
pub fn load_or_generate(path: &Path) -> Result<(PrivateKey, bool)> {
    match fs::read(path) {
        Ok(data) => {
            let key = PrivateKey::from_openssh(&data)
                .map_err(|e| format!("invalid host key {}: {e}", path.display()))?;
            if key.algorithm() != Algorithm::Ed25519 {
                return Err(format!("host key {} is not Ed25519", path.display()).into());
            }
            let mode = fs::metadata(path)?.permissions().mode();
            if mode & 0o077 != 0 {
                crate::log!(
                    "warning: host key {} is accessible by other users (mode {:o})",
                    path.display(),
                    mode & 0o777
                );
            }
            Ok((key, false))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok((generate(path)?, true)),
        Err(e) => Err(format!("cannot read host key {}: {e}", path.display()).into()),
    }
}

fn generate(path: &Path) -> Result<PrivateKey> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| format!("OS random number generator failed: {e}"))?;
    let key = PrivateKey::from(Ed25519Keypair::from_seed(&seed));
    seed.fill(0);
    let text = key
        .to_openssh(LineEnding::LF)
        .map_err(|e| format!("cannot encode host key: {e}"))?;
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("cannot create host key {}: {e}", path.display()))?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    Ok(key)
}

pub fn fingerprint(key: &PrivateKey) -> Result<String> {
    let blob = key
        .public_key()
        .to_bytes()
        .map_err(|e| format!("cannot encode public key: {e}"))?;
    Ok(cargo_live_proto::fingerprint(&blob))
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::HashAlg;

    #[test]
    fn generates_once_with_private_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys/host_key");
        let (key, generated) = load_or_generate(&path).unwrap();
        assert!(generated);
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let (again, generated) = load_or_generate(&path).unwrap();
        assert!(!generated);
        assert_eq!(fingerprint(&key).unwrap(), fingerprint(&again).unwrap());
        // Same format as OpenSSH / ssh-key.
        assert_eq!(
            fingerprint(&key).unwrap(),
            key.public_key().fingerprint(HashAlg::Sha256).to_string()
        );
    }
}
