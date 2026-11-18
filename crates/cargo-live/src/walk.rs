//! Listing the local workspace for synchronization.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use cargo_live_proto::{Entry, EntryKind, ExcludeSet};

use crate::{error, Result};

/// Lists `root` without following symlinks. Skips `/.git`, `/target`, the
/// Cargo target directory if it is inside the workspace, special files and
/// excluded paths. Returns entries sorted by path together with their local
/// paths.
pub fn manifest(
    root: &Path,
    target_dir: &Path,
    excludes: &ExcludeSet,
) -> Result<Vec<(Entry, PathBuf)>> {
    let target_rel = match target_dir.strip_prefix(root) {
        Ok(rel) if rel.as_os_str().is_empty() => {
            return Err(
                error("Cargo target directory is the workspace root; refusing to sync").into(),
            )
        }
        Ok(rel) => Some(
            rel.to_str()
                .ok_or_else(|| error("target directory path must be UTF-8"))?
                .to_owned(),
        ),
        Err(_) => None,
    };
    let mut out = Vec::new();
    walk(root, "", target_rel.as_deref(), excludes, &mut out)?;
    Ok(out)
}

fn walk(
    dir: &Path,
    prefix: &str,
    target_rel: Option<&str>,
    excludes: &ExcludeSet,
    out: &mut Vec<(Entry, PathBuf)>,
) -> Result<()> {
    let mut entries: Vec<_> = fs::read_dir(dir)?.collect::<std::io::Result<_>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| error(format!("{} is not valid UTF-8", path.display())))?;
        let rel = format!("{prefix}{name}");
        if prefix.is_empty() && (name == ".git" || name == "target") {
            continue;
        }
        if target_rel == Some(rel.as_str()) {
            continue;
        }
        let md = fs::symlink_metadata(&path)?;
        let file_type = md.file_type();
        if excludes.is_excluded(&rel, file_type.is_dir()) {
            continue;
        }
        let kind = if file_type.is_dir() {
            EntryKind::Dir
        } else if file_type.is_file() {
            EntryKind::File {
                size: md.len(),
                mtime_ns: md
                    .mtime()
                    .saturating_mul(1_000_000_000)
                    .saturating_add(md.mtime_nsec()),
                executable: md.permissions().mode() & 0o111 != 0,
            }
        } else if file_type.is_symlink() {
            let target = fs::read_link(&path)?;
            let target = target
                .to_str()
                .ok_or_else(|| error(format!("symlink target of {rel} is not UTF-8")))?;
            EntryKind::Symlink {
                target: target.to_owned(),
            }
        } else {
            // Sockets, FIFOs and devices are not synchronized.
            continue;
        };
        let is_dir = matches!(kind, EntryKind::Dir);
        out.push((
            Entry {
                path: rel.clone(),
                kind,
            },
            path.clone(),
        ));
        if is_dir {
            walk(&path, &format!("{rel}/"), target_rel, excludes, out)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn lists_workspace_with_exclusions() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for d in [
            ".git",
            "target",
            "src/bin",
            "build/out",
            "node_modules",
            "web/node_modules",
        ] {
            fs::create_dir_all(root.join(d)).unwrap();
        }
        fs::write(root.join("Cargo.toml"), "x").unwrap();
        fs::write(root.join("src/main.rs"), "x").unwrap();
        fs::write(root.join(".env"), "secret").unwrap();
        fs::write(root.join("build/out/f"), "x").unwrap();
        fs::write(root.join("web/node_modules/m.js"), "x").unwrap();
        fs::write(root.join("debug.log"), "x").unwrap();
        symlink("src", root.join("link")).unwrap();
        let excludes = ExcludeSet::new(&["/.env", "/node_modules", "*.log"]).unwrap();
        let entries = manifest(root, &root.join("build"), &excludes).unwrap();
        let paths: Vec<&str> = entries.iter().map(|(e, _)| e.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "Cargo.toml",
                "link",
                "src",
                "src/bin",
                "src/main.rs",
                "web",
                "web/node_modules",
                "web/node_modules/m.js"
            ]
        );
        assert!(matches!(
            &entries[1].0.kind,
            EntryKind::Symlink { target } if target == "src"
        ));
        assert!(manifest(root, root, &excludes).is_err());
    }
}
