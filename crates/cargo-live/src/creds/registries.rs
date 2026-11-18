//! Registry definitions from the local Cargo configuration.
//!
//! Only the workspace is synced, so `[registries]`, `[source]` and
//! `registry.default` from `$CARGO_HOME/config.toml` (and `.cargo/config`
//! files in directories above the workspace, which Cargo also reads) are
//! sent to the agent and passed to remote Cargo as `--config` entries.
//! Tokens and credential providers are never sent. Registries and sources
//! that the workspace's own (synced) `.cargo/config.toml` defines are left
//! to it.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use toml::{Table, Value};

/// `$CARGO_HOME`, or `~/.cargo`.
pub fn cargo_home() -> Option<PathBuf> {
    env::var_os("CARGO_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|h| PathBuf::from(h).join(".cargo")))
}

/// `dir/config.toml`, else `dir/config`.
fn config_in(dir: &Path) -> Option<PathBuf> {
    ["config.toml", "config"]
        .iter()
        .map(|n| dir.join(n))
        .find(|p| p.is_file())
}

/// The local Cargo configuration outside the workspace, merged with
/// Cargo's precedence (deeper directories win over `$CARGO_HOME`).
#[derive(Debug, Default, Clone)]
pub struct LocalCargoConfig {
    pub cargo_home: Option<PathBuf>,
    pub merged: Table,
    /// Registry and source names the workspace's own config defines.
    pub workspace_registries: BTreeSet<String>,
    pub workspace_sources: BTreeSet<String>,
}

fn read_table(path: &Path) -> Option<Table> {
    read_with_includes(path, 0)
}

/// Reads a config file and the files its `include` key names (relative to
/// the file; included values have lower precedence than the file's own).
fn read_with_includes(path: &Path, depth: usize) -> Option<Table> {
    let text = fs::read_to_string(path).ok()?;
    let mut table: Table = match toml::from_str(&text) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cargo-live: warning: ignoring {}: {e}", path.display());
            return None;
        }
    };
    let Some(include) = table.remove("include") else {
        return Some(table);
    };
    let base = path.parent().unwrap_or(Path::new("."));
    let items = match include {
        Value::Array(items) => items,
        other => vec![other],
    };
    let mut merged = Table::new();
    for item in items {
        let rel = match &item {
            Value::String(s) => Some(s.as_str()),
            Value::Table(t) => t.get("path").and_then(Value::as_str),
            _ => None,
        };
        if let (Some(rel), true) = (rel, depth < 8) {
            if let Some(included) = read_with_includes(&base.join(rel), depth + 1) {
                merge(&mut merged, included);
            }
        }
    }
    merge(&mut merged, table);
    Some(merged)
}

fn merge(into: &mut Table, from: Table) {
    for (k, v) in from {
        match (into.get_mut(&k), v) {
            (Some(Value::Table(a)), Value::Table(b)) => merge(a, b),
            (_, v) => {
                into.insert(k, v);
            }
        }
    }
}

impl LocalCargoConfig {
    pub fn load(workspace: &Path) -> Self {
        Self::load_from(workspace, cargo_home())
    }

    pub fn load_from(workspace: &Path, cargo_home: Option<PathBuf>) -> Self {
        let mut files = Vec::new();
        if let Some(home) = &cargo_home {
            files.extend(config_in(home));
        }
        // Ancestors above the workspace, outermost first.
        let mut ancestors: Vec<&Path> = workspace.ancestors().skip(1).collect();
        ancestors.reverse();
        for dir in ancestors {
            let dot = dir.join(".cargo");
            if cargo_home
                .as_ref()
                .is_some_and(|h| h.canonicalize().ok() == dot.canonicalize().ok())
            {
                continue;
            }
            files.extend(config_in(&dot));
        }
        let mut merged = Table::new();
        for file in &files {
            if let Some(table) = read_table(file) {
                merge(&mut merged, table);
            }
        }
        let own = config_in(&workspace.join(".cargo"))
            .and_then(|p| read_table(&p))
            .unwrap_or_default();
        let names = |key: &str| -> BTreeSet<String> {
            own.get(key)
                .and_then(Value::as_table)
                .map(|t| t.keys().cloned().collect())
                .unwrap_or_default()
        };
        Self {
            cargo_home,
            workspace_registries: names("registries"),
            workspace_sources: names("source"),
            merged,
        }
    }

    pub fn table(&self, path: &[&str]) -> Option<&Table> {
        let mut t = &self.merged;
        for key in path {
            t = t.get(*key)?.as_table()?;
        }
        Some(t)
    }

    /// The index URL of a registry name.
    pub fn registry_index(&self, name: &str) -> Option<String> {
        if name == "crates-io" {
            return Some("https://github.com/rust-lang/crates.io-index".into());
        }
        self.table(&["registries", name])?
            .get("index")?
            .as_str()
            .map(str::to_owned)
    }

    /// The registry name whose index matches `index`.
    pub fn registry_name(&self, index: &str) -> Option<String> {
        use cargo_live_proto::cred::normalize_index;
        self.table(&["registries"])?
            .iter()
            .find(|(_, v)| {
                v.get("index")
                    .and_then(Value::as_str)
                    .is_some_and(|i| normalize_index(i) == normalize_index(index))
            })
            .map(|(k, _)| k.clone())
    }

    /// `--config` entries for the agent.
    pub fn registries_config(&self) -> Vec<String> {
        let quote = |s: &str| Value::String(s.to_owned()).to_string();
        let mut out = Vec::new();
        if let Some(registries) = self.table(&["registries"]) {
            for (name, def) in registries {
                if self.workspace_registries.contains(name) {
                    continue;
                }
                let Some(def) = def.as_table() else { continue };
                for key in ["index", "protocol"] {
                    if let Some(v) = def.get(key).and_then(Value::as_str) {
                        out.push(format!("registries.{}.{key} = {}", quote(name), quote(v)));
                    }
                }
            }
        }
        if let Some(default) = self
            .table(&["registry"])
            .and_then(|r| r.get("default"))
            .and_then(Value::as_str)
        {
            out.push(format!("registry.default = {}", quote(default)));
        }
        if let Some(sources) = self.table(&["source"]) {
            // Local sources (directory, local-registry) point at paths on
            // this machine; they and replacements by them are not sent.
            let local: BTreeSet<&str> = sources
                .iter()
                .filter(|(_, d)| {
                    d.as_table().is_some_and(|t| {
                        t.contains_key("directory") || t.contains_key("local-registry")
                    })
                })
                .map(|(k, _)| k.as_str())
                .collect();
            for (name, def) in sources {
                if local.contains(name.as_str()) || self.workspace_sources.contains(name) {
                    continue;
                }
                let Some(def) = def.as_table() else { continue };
                for key in ["registry", "replace-with", "git", "branch", "tag", "rev"] {
                    let Some(v) = def.get(key).and_then(Value::as_str) else {
                        continue;
                    };
                    if key == "replace-with" && local.contains(v) {
                        eprintln!(
                            "cargo-live: warning: source.{name}.replace-with = {v:?} is a local \
                             source and is not used on the agent"
                        );
                        continue;
                    }
                    out.push(format!("source.{}.{key} = {}", quote(name), quote(v)));
                }
            }
        }
        out
    }

    /// Credential providers configured for a registry, highest precedence
    /// first, with aliases resolved. Each is argv (path and arguments).
    pub fn credential_providers(&self, name: &str) -> Vec<Vec<String>> {
        let to_argv = |v: &Value| -> Option<Vec<String>> {
            match v {
                Value::String(s) => Some(
                    s.split(' ')
                        .filter(|p| !p.is_empty())
                        .map(str::to_owned)
                        .collect(),
                ),
                Value::Array(a) => a.iter().map(|x| x.as_str().map(str::to_owned)).collect(),
                _ => None,
            }
        };
        let resolve_alias = |argv: Vec<String>| -> Vec<String> {
            if argv.len() == 1 {
                if let Some(alias) = self
                    .table(&["credential-alias"])
                    .and_then(|t| t.get(&argv[0]))
                    .and_then(to_argv)
                {
                    return alias;
                }
            }
            argv
        };
        let specific = self
            .table(&["registries", name])
            .and_then(|t| t.get("credential-provider"))
            .or_else(|| {
                (name == "crates-io")
                    .then(|| self.table(&["registry"])?.get("credential-provider"))
                    .flatten()
            });
        if let Some(v) = specific {
            return to_argv(v).map(resolve_alias).into_iter().collect();
        }
        let mut list: Vec<Vec<String>> = self
            .table(&["registry"])
            .and_then(|r| r.get("global-credential-providers"))
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(to_argv).map(resolve_alias).collect())
            .unwrap_or_default();
        // Later entries have higher precedence.
        list.reverse();
        list
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[registry]
default = "acme"
token = "crates-io-secret"
global-credential-providers = ["cargo:token", "my-alias", "/usr/bin/other --flag"]

[credential-alias]
my-alias = ["/opt/my provider", "--x"]

[registries.acme]
index = "sparse+https://registry.acme.dev/index/"
token = "acme-secret"
credential-provider = "cargo:token"

[registries.projectreg]
index = "sparse+https://p/"

[registries.crates-io]
protocol = "sparse"

[source.crates-io]
replace-with = "mirror"

[source.mirror]
registry = "sparse+https://mirror.acme.dev/index/"

[source.vendored]
directory = "/home/me/vendor"

[source.other]
replace-with = "vendored"

[build]
rustflags = ["-Cfoo"]
"#;

    fn sample() -> LocalCargoConfig {
        LocalCargoConfig {
            merged: toml::from_str(SAMPLE).unwrap(),
            workspace_registries: ["projectreg".to_owned()].into(),
            ..Default::default()
        }
    }

    #[test]
    fn extracts_registry_definitions_only() {
        let entries = sample().registries_config();
        assert_eq!(
            entries,
            [
                "registries.\"acme\".index = \"sparse+https://registry.acme.dev/index/\"",
                "registries.\"crates-io\".protocol = \"sparse\"",
                "registry.default = \"acme\"",
                "source.\"crates-io\".replace-with = \"mirror\"",
                "source.\"mirror\".registry = \"sparse+https://mirror.acme.dev/index/\"",
            ]
        );
        let text = entries.join("\n");
        assert!(!text.contains("secret") && !text.contains("credential-provider"));
        assert!(!text.contains("rustflags") && !text.contains("vendor"));
        // Every entry is a valid `--config` value.
        for e in &entries {
            toml::from_str::<Table>(e).unwrap();
        }
    }

    #[test]
    fn finds_names_indexes_and_providers() {
        let c = sample();
        assert_eq!(
            c.registry_name("https://registry.acme.dev/index")
                .as_deref(),
            Some("acme")
        );
        assert_eq!(
            c.registry_index("acme").as_deref(),
            Some("sparse+https://registry.acme.dev/index/")
        );
        assert_eq!(c.credential_providers("acme"), [["cargo:token"]]);
        assert_eq!(
            c.credential_providers("other"),
            [
                vec!["/usr/bin/other", "--flag"],
                vec!["/opt/my provider", "--x"],
                vec!["cargo:token"],
            ]
        );
    }

    #[test]
    fn merges_files_with_cargo_precedence() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("cargo-home");
        let ws = dir.path().join("a/ws");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(ws.join(".cargo")).unwrap();
        fs::create_dir_all(dir.path().join("a/.cargo")).unwrap();
        fs::write(
            home.join("config"),
            "include = ['extra.toml']\n[registries.y]\nindex = 'y'\n",
        )
        .unwrap();
        fs::write(
            home.join("extra.toml"),
            "[registries.x]\nindex = 'home'\n[registries.z]\nindex = 'z'\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("a/.cargo/config.toml"),
            "[registries.x]\nindex = 'above'\n",
        )
        .unwrap();
        fs::write(
            ws.join(".cargo/config.toml"),
            "[registries.y]\nindex = 'project'\n",
        )
        .unwrap();
        let c = LocalCargoConfig::load_from(&ws, Some(home));
        assert_eq!(c.registry_index("x").as_deref(), Some("above"));
        // y is defined by the workspace's own (synced) config.
        assert_eq!(
            c.registries_config(),
            [
                "registries.\"x\".index = \"above\"",
                "registries.\"z\".index = \"z\""
            ]
        );
    }
}
