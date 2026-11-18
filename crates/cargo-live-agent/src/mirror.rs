//! The agent-side source mirror.
//!
//! Every path comes from the client and is validated with
//! [`validate_relative_path`]. While writing or deleting, the agent never
//! follows a symlink: each parent component must be a real directory
//! ([`resolve`]), symlinks are replicated as symlinks and never traversed,
//! and replacing an entry uses `rename`, which does not follow the final
//! component either.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{self, ErrorKind};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cargo_live_proto::{validate_relative_path, Entry, EntryKind};

use crate::Result;

/// What the agent last wrote for each mirrored path.
pub type Index = BTreeMap<String, EntryKind>;

const MAX_ENTRIES: usize = 2_000_000;

pub fn load_index(path: &Path) -> Index {
    fs::read(path)
        .ok()
        .and_then(|data| postcard::from_bytes(&data).ok())
        .unwrap_or_default()
}

pub fn save_index(path: &Path, index: &Index) -> Result<()> {
    let data = postcard::to_allocvec(index)?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, data)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Returns `root/rel` after checking that `rel` is a safe relative path and
/// that every parent component below `root` is an existing real directory
/// (not a symlink). The final component itself is not inspected.
pub fn resolve(root: &Path, rel: &str) -> Result<PathBuf> {
    let components =
        validate_relative_path(rel).map_err(|e| format!("rejected path {rel:?}: {e}"))?;
    let mut path = root.to_path_buf();
    let (last, parents) = components.split_last().expect("validated nonempty");
    for component in parents {
        path.push(component);
        match fs::symlink_metadata(&path) {
            Ok(md) if md.file_type().is_dir() => {}
            Ok(_) => {
                return Err(
                    format!("rejected path {rel:?}: a parent is not a real directory").into(),
                )
            }
            Err(e) => return Err(format!("rejected path {rel:?}: parent missing: {e}").into()),
        }
    }
    path.push(last);
    Ok(path)
}

pub fn mtime_ns(md: &fs::Metadata) -> i64 {
    md.mtime()
        .saturating_mul(1_000_000_000)
        .saturating_add(md.mtime_nsec())
}

fn system_time(ns: i64) -> SystemTime {
    if ns >= 0 {
        UNIX_EPOCH + Duration::from_nanos(ns as u64)
    } else {
        UNIX_EPOCH - Duration::from_nanos(ns.unsigned_abs())
    }
}

fn file_matches(path: &Path, kind: &EntryKind) -> bool {
    let EntryKind::File {
        size,
        mtime_ns: mtime,
        executable,
    } = kind
    else {
        return false;
    };
    match fs::symlink_metadata(path) {
        Ok(md) => {
            md.file_type().is_file()
                && md.len() == *size
                && mtime_ns(&md) == *mtime
                && (md.permissions().mode() & 0o100 != 0) == *executable
        }
        Err(_) => false,
    }
}

pub struct Plan {
    /// Files the client must send, in this order.
    pub need: Vec<(String, EntryKind)>,
    pub deleted: u64,
}

/// Validates the manifest, deletes mirror entries that are absent from it
/// (or have a different kind), creates directories and symlinks, and
/// returns the files whose contents are needed.
pub fn prepare(root: &Path, index: &mut Index, entries: Vec<Entry>) -> Result<Plan> {
    if entries.len() > MAX_ENTRIES {
        return Err(format!("manifest has more than {MAX_ENTRIES} entries").into());
    }
    let mut wanted: HashMap<String, EntryKind> = HashMap::with_capacity(entries.len());
    for entry in entries {
        validate_relative_path(&entry.path)
            .map_err(|e| format!("rejected path {:?}: {e}", entry.path))?;
        if let EntryKind::Symlink { target } = &entry.kind {
            if target.is_empty() || target.contains('\0') {
                return Err(format!("rejected symlink target for {:?}", entry.path).into());
            }
        }
        if wanted.insert(entry.path.clone(), entry.kind).is_some() {
            return Err(format!("duplicate manifest path {:?}", entry.path).into());
        }
    }

    let mut deleted = 0;
    prune(root, "", &wanted, index, &mut deleted)?;
    index.retain(|path, kind| wanted.get(path) == Some(kind));

    let mut sorted: Vec<(String, EntryKind)> = wanted.into_iter().collect();
    // Parents sort before their children.
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut need = Vec::new();
    for (rel, kind) in sorted {
        let path = resolve(root, &rel)?;
        match &kind {
            EntryKind::Dir => match fs::symlink_metadata(&path) {
                Ok(md) if md.file_type().is_dir() => {}
                Ok(_) => return Err(format!("cannot replace {rel:?} with a directory").into()),
                Err(e) if e.kind() == ErrorKind::NotFound => fs::create_dir(&path)?,
                Err(e) => return Err(e.into()),
            },
            EntryKind::Symlink { target } => {
                let current = fs::read_link(&path).ok();
                if current.as_deref() != Some(Path::new(target)) {
                    if current.is_some() {
                        fs::remove_file(&path)?;
                    }
                    std::os::unix::fs::symlink(target, &path)?;
                }
            }
            EntryKind::File { .. } => {
                if index.get(&rel) == Some(&kind) && file_matches(&path, &kind) {
                    continue;
                }
                index.remove(&rel);
                need.push((rel.clone(), kind.clone()));
                continue;
            }
        }
        index.insert(rel, kind);
    }
    Ok(Plan { need, deleted })
}

/// Removes everything below `dir` that the manifest does not want, without
/// following symlinks. Lockfiles generated by Cargo on the agent are kept
/// (see [`is_generated_lockfile`]).
fn prune(
    dir: &Path,
    prefix: &str,
    wanted: &HashMap<String, EntryKind>,
    index: &Index,
    deleted: &mut u64,
) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        // `DirEntry::file_type` does not follow symlinks.
        let file_type = entry.file_type()?;
        let path = entry.path();
        let rel = entry
            .file_name()
            .to_str()
            .map(|name| format!("{prefix}{name}"));
        let keep = match rel.as_ref().and_then(|rel| wanted.get(rel)) {
            Some(EntryKind::Dir) => file_type.is_dir(),
            Some(EntryKind::File { .. }) => file_type.is_file(),
            Some(EntryKind::Symlink { target }) => {
                file_type.is_symlink()
                    && fs::read_link(&path).ok().as_deref() == Some(Path::new(target))
            }
            None => {
                file_type.is_file()
                    && rel
                        .as_deref()
                        .is_some_and(|rel| is_generated_lockfile(rel, wanted, index))
            }
        };
        if keep {
            if file_type.is_dir() {
                let rel = rel.expect("kept entries have UTF-8 names");
                prune(&path, &format!("{rel}/"), wanted, index, deleted)?;
            }
        } else if file_type.is_dir() {
            *deleted += count_tree(&path) + 1;
            // std's remove_dir_all does not follow symlinks.
            fs::remove_dir_all(&path)?;
        } else {
            *deleted += 1;
            fs::remove_file(&path)?;
        }
    }
    Ok(())
}

/// Whether `rel`, absent from the manifest, is a `Cargo.lock` that Cargo
/// generated on the agent: it sits next to a `Cargo.toml` the client sent
/// (a workspace or package root) and the agent did not write it from a
/// client copy (it is not in the index). Keeping it avoids re-resolving
/// dependencies on every build of a workspace without a local lockfile. A
/// lockfile the client sent and later deleted is in the index and removed;
/// a local lockfile always replaces the agent's copy.
fn is_generated_lockfile(rel: &str, wanted: &HashMap<String, EntryKind>, index: &Index) -> bool {
    let Some(dir) = rel.strip_suffix("Cargo.lock") else {
        return false;
    };
    (dir.is_empty() || dir.ends_with('/'))
        && matches!(
            wanted.get(&format!("{dir}Cargo.toml")),
            Some(EntryKind::File { .. })
        )
        && !index.contains_key(rel)
}

fn count_tree(dir: &Path) -> u64 {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .map(|e| {
            let nested = match e.file_type() {
                Ok(t) if t.is_dir() => count_tree(&e.path()),
                _ => 0,
            };
            nested + 1
        })
        .sum()
}

/// Moves a fully received temporary file into the mirror at `rel`, setting
/// its mode and modification time first. Returns the index entry.
pub fn install(root: &Path, tmp: &Path, rel: &str, kind: &EntryKind) -> Result<EntryKind> {
    let EntryKind::File {
        mtime_ns,
        executable,
        ..
    } = *kind
    else {
        return Err("not a file entry".into());
    };
    let file = fs::OpenOptions::new().write(true).open(tmp)?;
    let mode = if executable { 0o755 } else { 0o644 };
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    file.set_times(fs::FileTimes::new().set_modified(system_time(mtime_ns)))?;
    let size = file.metadata()?.len();
    drop(file);
    let dest = resolve(root, rel)?;
    match fs::symlink_metadata(&dest) {
        Ok(md) if md.file_type().is_dir() => {
            return Err(format!("cannot replace directory {rel:?} with a file").into())
        }
        Ok(_) | Err(_) => {}
    }
    // rename replaces a symlink at `dest` instead of following it.
    fs::rename(tmp, &dest).map_err(|e| io::Error::new(e.kind(), format!("{rel}: {e}")))?;
    Ok(EntryKind::File {
        size,
        mtime_ns,
        executable,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn file(path: &str, size: u64, mtime_ns: i64) -> Entry {
        Entry {
            path: path.into(),
            kind: EntryKind::File {
                size,
                mtime_ns,
                executable: false,
            },
        }
    }

    fn dir(path: &str) -> Entry {
        Entry {
            path: path.into(),
            kind: EntryKind::Dir,
        }
    }

    fn write_and_install(root: &Path, tmpdir: &Path, entry: &Entry, data: &[u8]) -> EntryKind {
        let tmp = tmpdir.join("upload");
        fs::write(&tmp, data).unwrap();
        install(root, &tmp, &entry.path, &entry.kind).unwrap()
    }

    #[test]
    fn diff_uses_index_and_filesystem_metadata() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("source");
        let tmpdir = temp.path().join("tmp");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&tmpdir).unwrap();
        let mut index = Index::new();
        let manifest = vec![dir("src"), file("src/main.rs", 3, 1_000_000_123)];

        let plan = prepare(&root, &mut index, manifest.clone()).unwrap();
        assert_eq!(plan.need.len(), 1);
        let kind = write_and_install(&root, &tmpdir, &manifest[1], b"abc");
        index.insert("src/main.rs".into(), kind);
        let md = fs::metadata(root.join("src/main.rs")).unwrap();
        assert_eq!(mtime_ns(&md), 1_000_000_123);

        // Unchanged: nothing needed.
        let plan = prepare(&root, &mut index, manifest.clone()).unwrap();
        assert!(plan.need.is_empty());
        assert_eq!(plan.deleted, 0);

        // Changed mtime locally: needed.
        let changed = vec![dir("src"), file("src/main.rs", 3, 2_000_000_000)];
        assert_eq!(prepare(&root, &mut index, changed).unwrap().need.len(), 1);

        // Tampered on the agent with the same index: needed again.
        let mut index2 = Index::new();
        index2.insert("src/main.rs".into(), manifest[1].kind.clone());
        fs::write(root.join("src/main.rs"), b"abcd").unwrap();
        assert_eq!(prepare(&root, &mut index2, manifest).unwrap().need.len(), 1);
    }

    #[test]
    fn deletes_entries_absent_from_manifest() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("keep")).unwrap();
        fs::create_dir_all(root.join("gone/deep")).unwrap();
        fs::write(root.join("gone/deep/f"), "x").unwrap();
        fs::write(root.join("stale"), "x").unwrap();
        // A symlink pointing outside: removed as a link, target untouched.
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("precious"), "x").unwrap();
        symlink(outside.path(), root.join("link")).unwrap();
        let mut index = Index::new();
        let plan = prepare(root, &mut index, vec![dir("keep")]).unwrap();
        assert_eq!(plan.deleted, 5);
        assert!(root.join("keep").is_dir());
        assert!(!root.join("gone").exists());
        assert!(!root.join("stale").exists());
        assert!(fs::symlink_metadata(root.join("link")).is_err());
        assert!(outside.path().join("precious").exists());
    }

    #[test]
    fn replicates_symlinks_without_traversing_them() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("source");
        fs::create_dir_all(&root).unwrap();
        let outside = temp.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        let mut index = Index::new();
        let link = Entry {
            path: "link".into(),
            kind: EntryKind::Symlink {
                target: outside.display().to_string(),
            },
        };
        prepare(&root, &mut index, vec![link.clone()]).unwrap();
        assert_eq!(fs::read_link(root.join("link")).unwrap(), outside);

        // Writing through the symlink is refused at planning time...
        let evil = vec![link.clone(), file("link/pwned", 1, 0)];
        assert!(prepare(&root, &mut index, evil).is_err());
        // ...and at install time.
        let tmp = temp.path().join("upload");
        fs::write(&tmp, "x").unwrap();
        assert!(install(&root, &tmp, "link/pwned", &file("link/pwned", 1, 0).kind).is_err());
        assert!(!outside.join("pwned").exists());

        // Directories below a symlink cannot be created either.
        assert!(prepare(&root, &mut index, vec![link, dir("link/sub")]).is_err());
        assert!(!outside.join("sub").exists());
    }

    #[test]
    fn install_replaces_symlink_instead_of_following_it() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("source");
        fs::create_dir_all(&root).unwrap();
        let victim = temp.path().join("victim");
        fs::write(&victim, "original").unwrap();
        symlink(&victim, root.join("f")).unwrap();
        let tmp = temp.path().join("upload");
        fs::write(&tmp, "new").unwrap();
        install(&root, &tmp, "f", &file("f", 3, 0).kind).unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "original");
        assert!(fs::symlink_metadata(root.join("f"))
            .unwrap()
            .file_type()
            .is_file());
    }

    #[test]
    fn rejects_unsafe_manifests() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("source");
        fs::create_dir_all(&root).unwrap();
        for bad in [
            vec![file("../escape", 1, 0)],
            vec![file("/etc/passwd", 1, 0)],
            vec![file("a//b", 1, 0)],
            vec![file("missing-parent/f", 1, 0)],
            vec![file("x", 1, 0), file("x", 1, 0)],
        ] {
            let mut index = Index::new();
            assert!(prepare(&root, &mut index, bad.clone()).is_err(), "{bad:?}");
        }
        assert!(!temp.path().join("escape").exists());
    }

    #[test]
    fn keeps_lockfiles_generated_on_the_agent() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("source");
        let tmpdir = temp.path().join("tmp");
        fs::create_dir_all(root.join("member")).unwrap();
        fs::create_dir_all(root.join("other")).unwrap();
        fs::create_dir_all(&tmpdir).unwrap();
        // Written by Cargo on the agent, not by the client.
        for f in [
            "Cargo.lock",
            "member/Cargo.lock",
            "other/Cargo.lock",
            "x.lock",
        ] {
            fs::write(root.join(f), "generated").unwrap();
        }
        let manifest = vec![
            file("Cargo.toml", 1, 0),
            dir("member"),
            file("member/Cargo.toml", 1, 0),
            dir("other"),
        ];
        let mut index = Index::new();
        let plan = prepare(&root, &mut index, manifest.clone()).unwrap();
        // Only lockfiles next to a synced Cargo.toml survive.
        assert!(root.join("Cargo.lock").exists());
        assert!(root.join("member/Cargo.lock").exists());
        assert!(!root.join("other/Cargo.lock").exists());
        assert!(!root.join("x.lock").exists());
        assert_eq!(plan.deleted, 2);
        assert_eq!(plan.need.len(), 2, "only the manifests");

        // A local lockfile replaces the generated one...
        let lock = file("Cargo.lock", 5, 7);
        let mut with_lock = manifest.clone();
        with_lock.push(lock.clone());
        let plan = prepare(&root, &mut index, with_lock).unwrap();
        assert!(plan.need.iter().any(|(p, _)| p == "Cargo.lock"));
        let kind = write_and_install(&root, &tmpdir, &lock, b"local");
        index.insert("Cargo.lock".into(), kind);
        assert_eq!(
            fs::read_to_string(root.join("Cargo.lock")).unwrap(),
            "local"
        );

        // ...and deleting it locally deletes it on the agent too.
        let plan = prepare(&root, &mut index, manifest).unwrap();
        assert_eq!(plan.deleted, 1);
        assert!(!root.join("Cargo.lock").exists());
        assert!(root.join("member/Cargo.lock").exists());
    }

    #[test]
    fn kind_changes_replace_entries() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::write(root.join("x"), "file").unwrap();
        fs::create_dir_all(root.join("y/z")).unwrap();
        let mut index = Index::new();
        let plan = prepare(root, &mut index, vec![dir("x"), file("y", 1, 0)]).unwrap();
        assert!(root.join("x").is_dir());
        assert!(!root.join("y").exists());
        assert_eq!(plan.need.len(), 1);
    }
}
