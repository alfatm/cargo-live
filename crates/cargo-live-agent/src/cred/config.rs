//! Agent-side credential configuration in agent.toml: `[[credentials]]`
//! providers and `[tokens.<name>]` policies.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use zeroize::Zeroizing;

use cargo_live_proto::cred::{glob_match, CredMatch, Kind, Phase, Secret};
use cargo_live_proto::is_token_name;

use crate::Result;

/// One `[[credentials]]` table as written. Provider-specific keys are
/// validated in [`AgentCreds::from_config`].
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    name: String,
    #[serde(rename = "match")]
    matcher: CredMatch,
    provider: String,
    allow_tokens: Option<Vec<String>>,
    #[serde(default)]
    phases: Option<Vec<Phase>>,
    // exec
    #[serde(default)]
    command: Option<Vec<String>>,
    #[serde(default)]
    timeout: Option<u64>,
    // file
    #[serde(default)]
    path: Option<PathBuf>,
    // file, env
    #[serde(default)]
    username: Option<String>,
    // env
    #[serde(default)]
    var: Option<String>,
    // github-app
    #[serde(default)]
    app_id: Option<u64>,
    #[serde(default)]
    private_key: Option<toml::Value>,
    #[serde(default)]
    installation_id: Option<u64>,
    #[serde(default)]
    api_url: Option<String>,
    #[serde(default)]
    permissions: Option<BTreeMap<String, String>>,
}

/// `[tokens.<name>]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenPolicy {
    /// Whether builds of this token may ask the client for credentials.
    #[serde(default = "yes")]
    pub allow_client: bool,
    /// Whether builds of this token may tunnel network connections
    /// through the client.
    #[serde(default = "yes")]
    pub allow_tunnel: bool,
}

fn yes() -> bool {
    true
}

impl Default for TokenPolicy {
    fn default() -> Self {
        Self {
            allow_client: true,
            allow_tunnel: true,
        }
    }
}

/// Where a root secret comes from. Inline literals are not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretRef {
    File(PathBuf),
    Env(String),
}

impl SecretRef {
    pub fn parse(value: &toml::Value, base: &Path) -> std::result::Result<Self, String> {
        const HELP: &str = "secrets must be references: { file = \"/run/secrets/...\" } or \
                            { env = \"NAME\" }; inline secret values are not allowed";
        let table = value.as_table().ok_or(HELP)?;
        match (table.len(), table.get("file"), table.get("env")) {
            (1, Some(toml::Value::String(file)), None) => {
                let path = PathBuf::from(file);
                Ok(SecretRef::File(if path.is_relative() {
                    base.join(path)
                } else {
                    path
                }))
            }
            (1, None, Some(toml::Value::String(var))) if !var.is_empty() => {
                Ok(SecretRef::Env(var.clone()))
            }
            _ => Err(HELP.into()),
        }
    }

    pub fn load(&self) -> std::result::Result<Secret, String> {
        let value = match self {
            SecretRef::File(path) => Zeroizing::new(
                std::fs::read_to_string(path)
                    .map_err(|e| format!("cannot read {}: {e}", path.display()))?,
            ),
            SecretRef::Env(var) => Zeroizing::new(
                std::env::var(var).map_err(|_| format!("environment variable {var} is not set"))?,
            ),
        };
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(format!("{self} is empty"));
        }
        Ok(Secret::new(trimmed))
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretRef::File(p) => write!(f, "file {}", p.display()),
            SecretRef::Env(v) => write!(f, "${v}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GithubApp {
    pub app_id: u64,
    pub private_key: SecretRef,
    pub installation_id: Option<u64>,
    pub api_url: String,
    pub permissions: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub enum ProviderKind {
    /// Runs a command (no shell); stdin JSON request, stdout JSON
    /// `{secret, username?, expires_at?}`.
    Exec {
        command: Vec<String>,
        timeout: Duration,
    },
    /// Reads the secret from a file (e.g. a Docker/Kubernetes secret).
    File {
        path: SecretRef,
        username: Option<String>,
    },
    /// Reads the secret from an environment variable of the agent.
    Env {
        var: SecretRef,
        username: Option<String>,
    },
    /// Mints short-lived GitHub App installation tokens.
    GithubApp(GithubApp),
}

#[derive(Debug, Clone)]
pub struct Provider {
    pub name: String,
    pub matcher: CredMatch,
    pub allow_tokens: Vec<String>,
    pub phases: Option<Vec<Phase>>,
    pub kind: ProviderKind,
}

impl Provider {
    pub fn allows_token(&self, token: &str) -> bool {
        self.allow_tokens.iter().any(|p| glob_match(p, token))
    }

    pub fn allows_phase(&self, phase: Phase) -> bool {
        self.phases.as_ref().is_none_or(|p| p.contains(&phase))
    }

    pub fn type_name(&self) -> &'static str {
        match self.kind {
            ProviderKind::Exec { .. } => "exec",
            ProviderKind::File { .. } => "file",
            ProviderKind::Env { .. } => "env",
            ProviderKind::GithubApp(_) => "github-app",
        }
    }
}

#[derive(Debug, Default)]
pub struct AgentCreds {
    pub providers: Vec<Provider>,
    pub tokens: BTreeMap<String, TokenPolicy>,
}

const DEFAULT_EXEC_TIMEOUT: u64 = 30;

impl AgentCreds {
    pub fn from_config(
        raw: Vec<ProviderConfig>,
        tokens: BTreeMap<String, TokenPolicy>,
        base: &Path,
    ) -> Result<Self> {
        let mut providers: Vec<Provider> = Vec::new();
        for c in raw {
            let name = c.name.clone();
            let provider =
                Self::provider(c, base).map_err(|e| format!("[[credentials]] {name:?}: {e}"))?;
            if providers.iter().any(|p| p.name == provider.name) {
                return Err(format!("duplicate [[credentials]] name {:?}", provider.name).into());
            }
            providers.push(provider);
        }
        for name in tokens.keys() {
            if !is_token_name(name) {
                return Err(format!("invalid token name [tokens.{name:?}]").into());
            }
        }
        Ok(Self { providers, tokens })
    }

    fn provider(c: ProviderConfig, base: &Path) -> std::result::Result<Provider, String> {
        if !is_token_name(&c.name) {
            return Err("name may contain letters, digits, '-', '_' and '.'".into());
        }
        c.matcher.validate()?;
        let allow_tokens = c
            .allow_tokens
            .ok_or("allow_tokens is required (e.g. [\"*\"] for every token)")?;
        if c.phases.as_ref().is_some_and(Vec::is_empty) {
            return Err("phases must not be empty".into());
        }
        let abs = |p: PathBuf| if p.is_relative() { base.join(p) } else { p };
        let mut used: Vec<&str> = Vec::new();
        let kind = match c.provider.as_str() {
            "exec" => {
                used.extend(["command", "timeout"]);
                let command = c.command.clone().ok_or("exec needs command = [...]")?;
                if command.is_empty() || command[0].is_empty() {
                    return Err("command must not be empty".into());
                }
                let mut command = command;
                if command[0].contains('/') {
                    command[0] = abs(PathBuf::from(&command[0]))
                        .to_string_lossy()
                        .into_owned();
                }
                ProviderKind::Exec {
                    command,
                    timeout: Duration::from_secs(c.timeout.unwrap_or(DEFAULT_EXEC_TIMEOUT).max(1)),
                }
            }
            "file" => {
                used.extend(["path", "username"]);
                ProviderKind::File {
                    path: SecretRef::File(abs(c
                        .path
                        .clone()
                        .ok_or("file needs path = \"...\"")?)),
                    username: c.username.clone(),
                }
            }
            "env" => {
                used.extend(["var", "username"]);
                let var = c.var.clone().filter(|v| !v.is_empty());
                ProviderKind::Env {
                    var: SecretRef::Env(var.ok_or("env needs var = \"NAME\"")?),
                    username: c.username.clone(),
                }
            }
            "github-app" => {
                used.extend([
                    "app_id",
                    "private_key",
                    "installation_id",
                    "api_url",
                    "permissions",
                ]);
                if c.matcher.kind != Kind::Git {
                    return Err("github-app only provides git credentials".into());
                }
                let key = c
                    .private_key
                    .as_ref()
                    .ok_or("github-app needs private_key = { file = ... } or { env = ... }")?;
                let api_url = c
                    .api_url
                    .clone()
                    .unwrap_or_else(|| "https://api.github.com".into());
                if !(api_url.starts_with("https://") || api_url.starts_with("http://")) {
                    return Err("api_url must be an http(s) URL".into());
                }
                ProviderKind::GithubApp(GithubApp {
                    app_id: c.app_id.ok_or("github-app needs app_id")?,
                    private_key: SecretRef::parse(key, base)?,
                    installation_id: c.installation_id,
                    api_url: api_url.trim_end_matches('/').to_owned(),
                    permissions: c.permissions.clone().unwrap_or_default(),
                })
            }
            other => {
                return Err(format!(
                    "unknown provider {other:?} (expected exec, file, env or github-app)"
                ))
            }
        };
        let given = [
            ("command", c.command.is_some()),
            ("timeout", c.timeout.is_some()),
            ("path", c.path.is_some()),
            ("username", c.username.is_some()),
            ("var", c.var.is_some()),
            ("app_id", c.app_id.is_some()),
            ("private_key", c.private_key.is_some()),
            ("installation_id", c.installation_id.is_some()),
            ("api_url", c.api_url.is_some()),
            ("permissions", c.permissions.is_some()),
        ];
        for (key, present) in given {
            if present && !used.contains(&key) {
                return Err(format!("{key} is not used by provider {:?}", c.provider));
            }
        }
        Ok(Provider {
            name: c.name,
            matcher: c.matcher,
            allow_tokens,
            phases: c.phases,
            kind,
        })
    }

    pub fn token_policy(&self, token: &str) -> TokenPolicy {
        self.tokens.get(token).cloned().unwrap_or_default()
    }

    /// Environment variables that hold root secrets; removed from the
    /// environment of Cargo and everything it starts.
    pub fn secret_env_vars(&self) -> Vec<String> {
        let mut vars = Vec::new();
        for p in &self.providers {
            let r = match &p.kind {
                ProviderKind::Env { var, .. } => Some(var),
                ProviderKind::GithubApp(app) => Some(&app.private_key),
                _ => None,
            };
            if let Some(SecretRef::Env(v)) = r {
                vars.push(v.clone());
            }
        }
        vars
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct File {
        #[serde(default)]
        credentials: Vec<ProviderConfig>,
        #[serde(default)]
        tokens: BTreeMap<String, TokenPolicy>,
    }

    fn parse(text: &str) -> Result<AgentCreds> {
        let file: File = toml::from_str(text)?;
        AgentCreds::from_config(file.credentials, file.tokens, Path::new("/etc/agent"))
    }

    #[test]
    fn parses_all_providers() {
        let creds = parse(
            r#"
[[credentials]]
name = "acme-github"
match = { kind = "git", host = "github.com", path = "acme/*" }
provider = "github-app"
app_id = 123456
private_key = { file = "gh-app.pem" }
permissions = { contents = "read" }
allow_tokens = ["*"]
phases = ["fetch"]

[[credentials]]
name = "gitlab-deploy"
match = { kind = "git", host = "gitlab.acme.dev" }
provider = "file"
path = "/run/secrets/gitlab-deploy-token"
username = "deploy-bot"
allow_tokens = ["ci", "dreo"]

[[credentials]]
name = "acme-registry"
match = { kind = "cargo", registry = "acme" }
provider = "exec"
command = ["/usr/local/bin/registry-token", "--json"]
allow_tokens = ["*"]

[[credentials]]
name = "ghcr"
match = { kind = "docker", host = "ghcr.io" }
provider = "env"
var = "GHCR_TOKEN"
username = "bot"
allow_tokens = ["dreo"]

[tokens.ci]
allow_client = false
allow_tunnel = false
"#,
        )
        .unwrap();
        assert_eq!(creds.providers.len(), 4);
        let ProviderKind::GithubApp(app) = &creds.providers[0].kind else {
            panic!()
        };
        assert_eq!(
            app.private_key,
            SecretRef::File("/etc/agent/gh-app.pem".into())
        );
        assert_eq!(app.api_url, "https://api.github.com");
        assert!(creds.providers[1].allows_token("dreo"));
        assert!(!creds.providers[1].allows_token("alice"));
        assert!(creds.providers[0].allows_phase(Phase::Fetch));
        assert!(!creds.providers[0].allows_phase(Phase::Build));
        assert!(creds.providers[1].allows_phase(Phase::Build));
        assert!(!creds.token_policy("ci").allow_client);
        assert!(creds.token_policy("dreo").allow_client);
        assert!(!creds.token_policy("ci").allow_tunnel);
        assert!(creds.token_policy("dreo").allow_tunnel);
        assert_eq!(creds.secret_env_vars(), ["GHCR_TOKEN"]);
    }

    #[test]
    fn secret_refs_reject_inline_literals() {
        let base = Path::new("/b");
        let v = |s: &str| -> toml::Value {
            toml::from_str::<toml::Table>(&format!("k = {s}")).unwrap()["k"].clone()
        };
        assert!(SecretRef::parse(&v("\"-----BEGIN RSA PRIVATE KEY-----\""), base).is_err());
        assert!(SecretRef::parse(&v("{ value = \"x\" }"), base).is_err());
        assert!(SecretRef::parse(&v("{ file = \"a\", env = \"B\" }"), base).is_err());
        assert!(SecretRef::parse(&v("{ env = \"\" }"), base).is_err());
        assert_eq!(
            SecretRef::parse(&v("{ env = \"KEY\" }"), base).unwrap(),
            SecretRef::Env("KEY".into())
        );
        let err = parse(
            r#"
[[credentials]]
name = "x"
match = { kind = "git", host = "github.com" }
provider = "github-app"
app_id = 1
private_key = "-----BEGIN RSA PRIVATE KEY-----"
allow_tokens = ["*"]
"#,
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("inline secret values are not allowed"),
            "{err}"
        );
    }

    #[test]
    fn rejects_invalid_provider_tables() {
        for text in [
            // allow_tokens is required.
            "[[credentials]]\nname='a'\nmatch={kind='git'}\nprovider='file'\npath='/x'\n",
            // Unknown provider.
            "[[credentials]]\nname='a'\nmatch={kind='git'}\nprovider='vault'\nallow_tokens=['*']\n",
            // Key of another provider.
            "[[credentials]]\nname='a'\nmatch={kind='git'}\nprovider='file'\npath='/x'\nvar='Y'\nallow_tokens=['*']\n",
            // Wrong match field for the kind.
            "[[credentials]]\nname='a'\nmatch={kind='cargo',host='x'}\nprovider='file'\npath='/x'\nallow_tokens=['*']\n",
            // github-app for cargo.
            "[[credentials]]\nname='a'\nmatch={kind='cargo'}\nprovider='github-app'\napp_id=1\nprivate_key={env='K'}\nallow_tokens=['*']\n",
            // Duplicate names.
            "[[credentials]]\nname='a'\nmatch={kind='git'}\nprovider='env'\nvar='X'\nallow_tokens=['*']\n\
             [[credentials]]\nname='a'\nmatch={kind='git'}\nprovider='env'\nvar='X'\nallow_tokens=['*']\n",
            // Unknown key.
            "[[credentials]]\nname='a'\nmatch={kind='git'}\nprovider='env'\nvar='X'\nallow_tokens=['*']\nsecret='x'\n",
        ] {
            assert!(parse(text).is_err(), "{text}");
        }
    }
}
