use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    Empty,
    Absolute,
    EmptyComponent,
    DotComponent,
    Nul,
    TooLong,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PathError::Empty => "path is empty",
            PathError::Absolute => "path is absolute",
            PathError::EmptyComponent => "path has an empty component",
            PathError::DotComponent => "path contains '.' or '..'",
            PathError::Nul => "path contains a NUL byte",
            PathError::TooLong => "path is too long",
        })
    }
}

impl std::error::Error for PathError {}

/// Validates a relative, `/`-separated path received over the wire and
/// returns its components. Rejects absolute paths, `.`/`..`, empty
/// components (including leading, trailing or doubled slashes) and NUL.
pub fn validate_relative_path(path: &str) -> Result<Vec<&str>, PathError> {
    if path.is_empty() {
        return Err(PathError::Empty);
    }
    if path.len() > 4096 {
        return Err(PathError::TooLong);
    }
    if path.contains('\0') {
        return Err(PathError::Nul);
    }
    if path.starts_with('/') {
        return Err(PathError::Absolute);
    }
    path.split('/')
        .map(|component| match component {
            "" => Err(PathError::EmptyComponent),
            "." | ".." => Err(PathError::DotComponent),
            c if c.len() > 255 => Err(PathError::TooLong),
            c => Ok(c),
        })
        .collect()
}

/// A workspace id is the lowercase hex SHA-256 of the client's workspace path.
pub fn is_workspace_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Token names are used as directory names on the agent.
pub fn is_token_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && !name.starts_with(['.', '-'])
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_normal_relative_paths() {
        assert_eq!(
            validate_relative_path("src/main.rs").unwrap(),
            ["src", "main.rs"]
        );
        assert_eq!(validate_relative_path(".env").unwrap(), [".env"]);
        assert_eq!(
            validate_relative_path("a/..b/c..").unwrap(),
            ["a", "..b", "c.."]
        );
    }

    #[test]
    fn rejects_unsafe_paths() {
        for (path, err) in [
            ("", PathError::Empty),
            ("/etc/passwd", PathError::Absolute),
            ("..", PathError::DotComponent),
            ("a/../../b", PathError::DotComponent),
            ("./a", PathError::DotComponent),
            ("a//b", PathError::EmptyComponent),
            ("a/", PathError::EmptyComponent),
            ("a\0b", PathError::Nul),
        ] {
            assert_eq!(validate_relative_path(path), Err(err), "{path:?}");
        }
        assert_eq!(
            validate_relative_path(&"a".repeat(300)),
            Err(PathError::TooLong)
        );
    }

    #[test]
    fn validates_ids_and_names() {
        assert!(is_workspace_id(&"a1".repeat(32)));
        assert!(!is_workspace_id(&"A1".repeat(32)));
        assert!(!is_workspace_id("../x"));
        assert!(is_token_name("alice-laptop_1"));
        for bad in ["", ".", "..", "-x", "a/b", "a b", &"x".repeat(65)] {
            assert!(!is_token_name(bad), "{bad:?}");
        }
    }
}
