//! Handling of remote Cargo output.

use std::path::Path;

use serde_json::Value;

#[derive(Debug, PartialEq)]
pub enum Emit {
    Stdout(String),
    Stderr(String),
    Nothing,
}

/// Processes one line of remote Cargo stdout.
pub fn handle_line(text: &str, json_output: bool, remotes: &[&str], local: &Path) -> Emit {
    if text.is_empty() {
        return Emit::Nothing;
    }
    let mut value = match serde_json::from_str::<Value>(text) {
        Ok(value @ Value::Object(_)) => value,
        // Not a Cargo message, e.g. output of a wrapper around remote Cargo.
        // Keep stdout clean for rust-analyzer.
        _ => return Emit::Stderr(format!("{text}\n")),
    };
    if json_output {
        remap_paths(&mut value, remotes, local);
        Emit::Stdout(value.to_string())
    } else if let Some(rendered) = value.pointer("/message/rendered").and_then(Value::as_str) {
        Emit::Stderr(remap_str(rendered, remotes, local))
    } else {
        Emit::Nothing
    }
}

/// Replaces a leading remote path prefix with the local workspace path.
/// Also handles `file://` URLs such as Cargo package ids
/// (`path+file:///remote/source#name@0.1.0`).
pub fn remap_path(s: &str, remotes: &[&str], local: &Path) -> Option<String> {
    for scheme in ["path+file://", "file://"] {
        if let Some(url_path) = s.strip_prefix(scheme) {
            for remote in remotes.iter().filter(|r| !r.is_empty()) {
                if let Some(rest) = url_path
                    .strip_prefix(remote)
                    .filter(|rest| rest.is_empty() || rest.starts_with(['/', '#', '?']))
                {
                    return Some(format!("{scheme}{}{rest}", local.to_string_lossy()));
                }
            }
            return None;
        }
    }
    for remote in remotes.iter().filter(|r| !r.is_empty()) {
        if s == *remote {
            return Some(local.to_string_lossy().into_owned());
        } else if let Some(rest) = s.strip_prefix(remote).and_then(|v| v.strip_prefix('/')) {
            return Some(local.join(rest).to_string_lossy().into_owned());
        }
    }
    None
}

/// Replaces remote path prefixes anywhere in rendered text.
fn remap_str(s: &str, remotes: &[&str], local: &Path) -> String {
    let local = local.to_string_lossy();
    let mut out = s.to_owned();
    for remote in remotes.iter().filter(|r| !r.is_empty()) {
        out = out.replace(&format!("{remote}/"), &format!("{local}/"));
    }
    out
}

/// Replaces any of the remote path prefixes in JSON strings.
pub fn remap_paths(value: &mut Value, remotes: &[&str], local: &Path) {
    match value {
        Value::String(s) => {
            if let Some(mapped) = remap_path(s, remotes, local) {
                *s = mapped;
            }
        }
        Value::Array(values) => values
            .iter_mut()
            .for_each(|v| remap_paths(v, remotes, local)),
        Value::Object(values) => values
            .values_mut()
            .for_each(|v| remap_paths(v, remotes, local)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remaps_only_complete_path_prefixes() {
        let mut value = serde_json::json!({
            "path": "/remote/project/src/main.rs",
            "other": "/remote/project-other/file.rs",
            "nested": ["/remote/project"]
        });
        remap_paths(
            &mut value,
            &["/remote/project"],
            Path::new("/local/project"),
        );
        assert_eq!(value["path"], "/local/project/src/main.rs");
        assert_eq!(value["other"], "/remote/project-other/file.rs");
        assert_eq!(value["nested"][0], "/local/project");
    }

    #[test]
    fn remaps_physical_and_logical_prefixes() {
        let mut value = serde_json::json!({
            "logical": "/link/source/src/main.rs",
            "physical": "/real/source/src/lib.rs",
        });
        let remotes = ["/link/source", "/real/source"];
        remap_paths(&mut value, &remotes, Path::new("/local"));
        assert_eq!(value["logical"], "/local/src/main.rs");
        assert_eq!(value["physical"], "/local/src/lib.rs");
    }

    #[test]
    fn remaps_package_id_urls() {
        let mut value = serde_json::json!({
            "package_id": "path+file:///real/source#app@0.1.0",
            "sub": "path+file:///real/source/crates/a#0.1.0",
            "other": "path+file:///real/source2#x@1.0.0",
            "registry": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0",
        });
        remap_paths(&mut value, &["/real/source"], Path::new("/local"));
        assert_eq!(value["package_id"], "path+file:///local#app@0.1.0");
        assert_eq!(value["sub"], "path+file:///local/crates/a#0.1.0");
        assert_eq!(value["other"], "path+file:///real/source2#x@1.0.0");
        assert!(value["registry"].as_str().unwrap().starts_with("registry+"));
    }

    #[test]
    fn non_json_lines_are_passed_to_stderr() {
        for json_output in [true, false] {
            for line in ["warning: not json", "42"] {
                let emit = handle_line(line, json_output, &[], Path::new("/l"));
                assert_eq!(emit, Emit::Stderr(format!("{line}\n")));
            }
        }
        let emit = handle_line(
            r#"{"reason":"build-finished","success":true}"#,
            true,
            &[],
            Path::new("/l"),
        );
        assert!(matches!(emit, Emit::Stdout(_)));
    }

    #[test]
    fn renders_diagnostics_when_not_forwarding_json() {
        let line =
            r#"{"reason":"compiler-message","message":{"rendered":"error at /r/src/main.rs:1\n"}}"#;
        assert_eq!(
            handle_line(line, false, &["/r"], Path::new("/l")),
            Emit::Stderr("error at /l/src/main.rs:1\n".into())
        );
        let artifact = r#"{"reason":"compiler-artifact"}"#;
        assert_eq!(
            handle_line(artifact, false, &[], Path::new("/l")),
            Emit::Nothing
        );
    }
}
