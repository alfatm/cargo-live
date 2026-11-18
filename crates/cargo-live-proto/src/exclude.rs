use std::fmt;

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

/// Exclusion patterns with rsync-like semantics:
///
/// - a leading `/` anchors the pattern to the workspace root; otherwise it
///   matches at any depth;
/// - a trailing `/` matches directories only;
/// - `*` and `?` do not cross `/`, `**` does.
///
/// An excluded directory excludes everything below it.
#[derive(Debug, Clone)]
pub struct ExcludeSet {
    any: GlobSet,
    dirs: GlobSet,
}

#[derive(Debug)]
pub struct ExcludeError(String);

impl fmt::Display for ExcludeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ExcludeError {}

impl ExcludeSet {
    pub fn new<S: AsRef<str>>(patterns: &[S]) -> Result<Self, ExcludeError> {
        let mut any = GlobSetBuilder::new();
        let mut dirs = GlobSetBuilder::new();
        for pattern in patterns {
            let original = pattern.as_ref();
            let mut pattern = original;
            let dir_only = pattern.ends_with('/');
            pattern = pattern.trim_end_matches('/');
            let anchored = pattern.starts_with('/');
            pattern = pattern.trim_start_matches('/');
            if pattern.is_empty() {
                return Err(ExcludeError(format!(
                    "invalid exclude pattern {original:?}: matches the workspace root"
                )));
            }
            let glob = if anchored {
                pattern.to_owned()
            } else {
                format!("**/{pattern}")
            };
            let glob = GlobBuilder::new(&glob)
                .literal_separator(true)
                .backslash_escape(true)
                .build()
                .map_err(|e| ExcludeError(format!("invalid exclude pattern {original:?}: {e}")))?;
            if dir_only {
                dirs.add(glob);
            } else {
                any.add(glob);
            }
        }
        let build = |b: GlobSetBuilder| b.build().map_err(|e| ExcludeError(e.to_string()));
        Ok(Self {
            any: build(any)?,
            dirs: build(dirs)?,
        })
    }

    /// Whether the entry at `path` (relative, `/`-separated) is excluded.
    /// Callers walking a tree skip excluded directories entirely.
    pub fn is_excluded(&self, path: &str, is_dir: bool) -> bool {
        self.any.is_match(path) || (is_dir && self.dirs.is_match(path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(patterns: &[&str]) -> ExcludeSet {
        ExcludeSet::new(patterns).unwrap()
    }

    #[test]
    fn anchored_patterns_match_only_at_root() {
        let s = set(&["/.env", "/node_modules"]);
        assert!(s.is_excluded(".env", false));
        assert!(!s.is_excluded("sub/.env", false));
        assert!(s.is_excluded("node_modules", true));
        assert!(!s.is_excluded("web/node_modules", true));
    }

    #[test]
    fn unanchored_patterns_match_at_any_depth() {
        let s = set(&["*.log", "cache", "a/b"]);
        assert!(s.is_excluded("x.log", false));
        assert!(s.is_excluded("deep/dir/x.log", false));
        assert!(s.is_excluded("cache", true));
        assert!(s.is_excluded("sub/cache", false));
        assert!(s.is_excluded("a/b", false));
        assert!(s.is_excluded("z/a/b", true));
        assert!(!s.is_excluded("a/c/b", false));
    }

    #[test]
    fn trailing_slash_matches_directories_only() {
        let s = set(&["build/"]);
        assert!(s.is_excluded("build", true));
        assert!(s.is_excluded("x/build", true));
        assert!(!s.is_excluded("build", false));
    }

    #[test]
    fn star_does_not_cross_separators_but_double_star_does() {
        let s = set(&["/src/*.rs", "/gen/**/out"]);
        assert!(s.is_excluded("src/main.rs", false));
        assert!(!s.is_excluded("src/bin/main.rs", false));
        assert!(s.is_excluded("gen/out", false));
        assert!(s.is_excluded("gen/a/b/out", false));
        let q = set(&["file?.txt"]);
        assert!(q.is_excluded("file1.txt", false));
        assert!(!q.is_excluded("file12.txt", false));
    }

    #[test]
    fn rejects_root_patterns() {
        assert!(ExcludeSet::new(&["/"]).is_err());
        assert!(ExcludeSet::new(&["a[".to_owned()]).is_err());
    }
}
