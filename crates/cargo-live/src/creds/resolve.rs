//! Resolvers for forwarded credential requests. Every request is checked
//! against `[forward]` here, whatever the agent says.
//!
//! - a matching `[[forward.command]]`, else by kind:
//! - git: `git credential fill`;
//! - cargo: `CARGO_REGISTRIES_<NAME>_TOKEN`, `$CARGO_HOME/credentials.toml`,
//!   then the registry's credential providers from the local Cargo config
//!   (spoken to with the credential provider protocol);
//! - docker: `credHelpers[host]`, `auths[host].auth`, then `credsStore`
//!   from `~/.docker/config.json`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use serde::Deserialize;
use zeroize::Zeroizing;

use cargo_live_proto::cred::{
    normalize_docker_host, parse_command_output, run_command, Credential, Scope, Secret,
};

use super::registries::LocalCargoConfig;
use super::{Forward, ForwardCommand};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
const INTERACTIVE_TIMEOUT: Duration = Duration::from_secs(300);

pub struct ClientResolver {
    pub forward: Forward,
    pub cargo: LocalCargoConfig,
    pub docker_config: Option<PathBuf>,
}

impl ClientResolver {
    pub fn new(forward: Forward, cargo: LocalCargoConfig) -> Self {
        let docker_config = std::env::var_os("DOCKER_CONFIG")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".docker")));
        Self {
            forward,
            cargo,
            docker_config,
        }
    }

    fn command_for(&self, scope: &Scope) -> Option<&ForwardCommand> {
        let mut best: Option<&ForwardCommand> = None;
        for c in self
            .forward
            .command
            .iter()
            .filter(|c| c.matcher.matches(scope))
        {
            if best.is_none_or(|b| c.matcher.specificity() > b.matcher.specificity()) {
                best = Some(c);
            }
        }
        best
    }

    /// Resolves a forwarded request. Errors are short and contain no
    /// secrets; they are shown in the build output.
    pub fn resolve(&self, scope: &Scope) -> Result<Credential, String> {
        scope.validate()?;
        if !self.forward.allowlist().allows(scope) {
            return Err("not in [forward] on this machine".into());
        }
        if let Some(command) = self.command_for(scope) {
            return run_forward_command(command, scope);
        }
        match scope {
            Scope::Git {
                protocol,
                host,
                path,
            } => git_fill(protocol, host, path, self.forward.interactive),
            Scope::Cargo { name, index } => self.cargo_token(name.as_deref(), index.as_deref()),
            Scope::Docker { host } => self.docker(host),
        }
    }

    /// For `creds explain`: whether this machine would answer, and how.
    pub fn describe(&self, scope: &Scope) -> String {
        let Some(entry) = self.forward.allowlist().allowing(scope).map(str::to_owned) else {
            return "not in [forward]: this machine refuses to forward it".into();
        };
        let resolver = match (self.command_for(scope), scope) {
            (Some(c), _) => format!("forward.command {:?}", c.command.join(" ")),
            (None, Scope::Git { .. }) => "git credential fill".into(),
            (None, Scope::Cargo { .. }) => {
                "CARGO_REGISTRIES_<NAME>_TOKEN, credentials.toml, credential providers".into()
            }
            (None, Scope::Docker { .. }) => "~/.docker/config.json helpers".into(),
        };
        format!("in [forward] via {entry:?}; resolver: {resolver}")
    }

    fn cargo_token(&self, name: Option<&str>, index: Option<&str>) -> Result<Credential, String> {
        let name = name
            .map(str::to_owned)
            .or_else(|| index.and_then(|i| self.cargo.registry_name(i)))
            .ok_or("registry has no name in the local Cargo config")?;
        let token = |s: &str| {
            Ok(Credential {
                username: None,
                secret: Secret::new(s),
                expires_at: None,
            })
        };
        // 1. Environment.
        let var = if name == "crates-io" {
            "CARGO_REGISTRY_TOKEN".to_owned()
        } else {
            format!(
                "CARGO_REGISTRIES_{}_TOKEN",
                name.to_ascii_uppercase().replace('-', "_")
            )
        };
        if let Some(value) = std::env::var(&var).ok().filter(|v| !v.is_empty()) {
            return token(&Zeroizing::new(value));
        }
        // 2. $CARGO_HOME/credentials.toml (or credentials).
        if let Some(home) = &self.cargo.cargo_home {
            if let Some(value) = credentials_file_token(home, &name) {
                return token(&value);
            }
        }
        // 3. Credential providers from the local Cargo config.
        let index = index
            .map(str::to_owned)
            .or_else(|| self.cargo.registry_index(&name))
            .ok_or("registry has no index URL")?;
        let mut tried = Vec::new();
        for argv in self.cargo.credential_providers(&name) {
            match run_cargo_provider(&argv, &index, &name) {
                Ok(Some(c)) => return Ok(c),
                Ok(None) => {}
                Err(e) => tried.push(e),
            }
        }
        if tried.is_empty() {
            Err(format!("no token for registry {name:?} on this machine"))
        } else {
            Err(tried.join("; "))
        }
    }

    fn docker(&self, host: &str) -> Result<Credential, String> {
        let dir = self
            .docker_config
            .as_ref()
            .ok_or("no Docker config directory")?;
        let text = std::fs::read_to_string(dir.join("config.json"))
            .map_err(|_| format!("no {}", dir.join("config.json").display()))?;
        let config: DockerConfig =
            serde_json::from_str(&text).map_err(|_| "invalid Docker config.json")?;
        docker_lookup(&config, host)
    }
}

fn run_forward_command(command: &ForwardCommand, scope: &Scope) -> Result<Credential, String> {
    let stdin = serde_json::Value::Object(scope.to_json()).to_string();
    let timeout = command
        .timeout
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_TIMEOUT);
    let out = run_command(&command.command, stdin.as_bytes(), timeout, &[])?;
    parse_command_output(&out, true).map_err(|e| format!("{}: {e}", command.command[0]))
}

/// Parses `git credential fill` output.
pub fn parse_git_fill(out: &str) -> Result<Credential, String> {
    let mut username = None;
    let mut password = None;
    let mut expiry = None;
    for line in out.lines() {
        match line.split_once('=') {
            Some(("username", v)) => username = Some(v.to_owned()),
            Some(("password", v)) => password = Some(Secret::new(v)),
            Some(("password_expiry_utc", v)) => expiry = v.parse().ok(),
            _ => {}
        }
    }
    let secret = password
        .filter(|p| !p.is_empty())
        .ok_or("git credential fill returned no password")?;
    Ok(Credential {
        username,
        secret,
        expires_at: expiry,
    })
}

fn git_fill(
    protocol: &str,
    host: &str,
    path: &str,
    interactive: bool,
) -> Result<Credential, String> {
    let input = format!("protocol={protocol}\nhost={host}\npath={path}\n\n");
    let mut env = vec![];
    if !interactive {
        env.push(("GIT_TERMINAL_PROMPT", "0"));
        env.push(("GCM_INTERACTIVE", "never"));
    }
    let timeout = if interactive {
        INTERACTIVE_TIMEOUT
    } else {
        DEFAULT_TIMEOUT
    };
    let argv = ["git", "credential", "fill"].map(String::from);
    let out = run_command(&argv, input.as_bytes(), timeout, &env)
        .map_err(|e| format!("git credential fill: {e}"))?;
    let text = std::str::from_utf8(&out).map_err(|_| "git credential fill: not UTF-8")?;
    parse_git_fill(text)
}

fn credentials_file_token(home: &Path, name: &str) -> Option<Zeroizing<String>> {
    let path = ["credentials.toml", "credentials"]
        .iter()
        .map(|n| home.join(n))
        .find(|p| p.is_file())?;
    let text = Zeroizing::new(std::fs::read_to_string(path).ok()?);
    let table: toml::Table = toml::from_str(&text).ok()?;
    let entry = if name == "crates-io" {
        table.get("registry")
    } else {
        table.get("registries")?.get(name)
    };
    let token = entry?.get("token")?.as_str()?;
    Some(Zeroizing::new(token.to_owned()))
}

#[derive(Deserialize)]
enum ProviderResponse {
    Ok(ProviderOk),
    Err(ProviderErr),
}

#[derive(Deserialize)]
struct ProviderOk {
    token: Secret,
    #[serde(default)]
    cache: Option<String>,
    #[serde(default)]
    expiration: Option<i64>,
}

#[derive(Deserialize)]
struct ProviderErr {
    kind: String,
    #[serde(default)]
    message: Option<String>,
}

/// Runs one credential provider for a `get`/`read` request. `Ok(None)`
/// means "not found / not supported" (try the next one).
fn run_cargo_provider(
    argv: &[String],
    index: &str,
    name: &str,
) -> Result<Option<Credential>, String> {
    let program = argv.first().ok_or("empty credential provider")?;
    match program.as_str() {
        // Handled by the environment and credentials.toml lookups.
        "cargo:token" => return Ok(None),
        "cargo:token-from-stdout" => {
            let out = run_command(
                &argv[1..],
                b"",
                DEFAULT_TIMEOUT,
                &[
                    ("CARGO_REGISTRY_INDEX_URL", index),
                    ("CARGO_REGISTRY_NAME_OPT", name),
                ],
            )?;
            return parse_command_output(&out, true).map(Some);
        }
        p if p.starts_with("cargo:") => {
            return Err(format!(
                "built-in provider {p} is not supported for forwarding (use forward.command)"
            ))
        }
        _ => {}
    }
    let request = serde_json::json!({
        "v": 1,
        "kind": "get",
        "operation": "read",
        "registry": { "index-url": index, "name": name },
        "args": &argv[1..],
    });
    let command = vec![program.clone(), "--cargo-plugin".into()];
    let out = run_command(
        &command,
        format!("{request}\n").as_bytes(),
        DEFAULT_TIMEOUT,
        &[],
    )?;
    parse_provider_output(&out).map_err(|e| format!("{program}: {e}"))
}

/// Parses a provider's hello line and its response to one `get` request.
pub fn parse_provider_output(out: &[u8]) -> Result<Option<Credential>, String> {
    let text = std::str::from_utf8(out).map_err(|_| "output is not UTF-8")?;
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let hello: serde_json::Value = lines
        .next()
        .and_then(|l| serde_json::from_str(l).ok())
        .ok_or("no hello message")?;
    if !hello["v"]
        .as_array()
        .is_some_and(|v| v.iter().any(|x| x == 1))
    {
        return Err("provider does not speak protocol version 1".into());
    }
    let response: ProviderResponse = lines
        .next()
        .and_then(|l| serde_json::from_str(l).ok())
        .ok_or("no valid response")?;
    match response {
        ProviderResponse::Ok(ok) => Ok(Some(Credential {
            username: None,
            expires_at: if ok.cache.as_deref() == Some("expires") {
                ok.expiration
            } else {
                None
            },
            secret: ok.token,
        })),
        ProviderResponse::Err(e) => match e.kind.as_str() {
            "not-found" | "url-not-supported" | "operation-not-supported" => Ok(None),
            _ => Err(e.message.unwrap_or(e.kind)),
        },
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct DockerConfig {
    #[serde(default, rename = "credHelpers")]
    cred_helpers: std::collections::BTreeMap<String, String>,
    #[serde(default, rename = "credsStore")]
    creds_store: Option<String>,
    #[serde(default)]
    auths: std::collections::BTreeMap<String, DockerAuth>,
}

#[derive(Debug, Default, Deserialize)]
struct DockerAuth {
    #[serde(default)]
    auth: Option<String>,
}

#[derive(Deserialize)]
struct HelperOutput {
    #[serde(rename = "Username", default)]
    username: String,
    #[serde(rename = "Secret")]
    secret: Secret,
}

/// The server URL key Docker uses for `host`.
fn docker_server(host: &str) -> String {
    if host == "docker.io" {
        "https://index.docker.io/v1/".into()
    } else {
        host.into()
    }
}

pub fn docker_lookup(config: &DockerConfig, host: &str) -> Result<Credential, String> {
    let find = |key: &String| normalize_docker_host(key) == host;
    if let Some((server, helper)) = config.cred_helpers.iter().find(|(k, _)| find(k)) {
        return docker_helper(helper, server);
    }
    if let Some(auth) = config
        .auths
        .iter()
        .find(|(k, _)| find(k))
        .and_then(|(_, a)| a.auth.as_deref())
        .filter(|a| !a.is_empty())
    {
        let decoded = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(auth.trim())
                .map_err(|_| "invalid auths entry in Docker config.json")?,
        );
        let text = std::str::from_utf8(&decoded).map_err(|_| "invalid auths entry")?;
        let (user, pass) = text.split_once(':').ok_or("invalid auths entry")?;
        return Ok(Credential {
            username: Some(user.to_owned()),
            secret: Secret::new(pass),
            expires_at: None,
        });
    }
    if let Some(store) = &config.creds_store {
        return docker_helper(store, &docker_server(host));
    }
    Err(format!("no Docker credentials for {host} on this machine"))
}

fn docker_helper(helper: &str, server: &str) -> Result<Credential, String> {
    if helper.is_empty() || helper.contains('/') {
        return Err("invalid Docker credential helper name".into());
    }
    let program = format!("docker-credential-{helper}");
    let out = run_command(
        std::slice::from_ref(&program),
        format!("{server}\n").as_bytes(),
        DEFAULT_TIMEOUT,
        &[],
    )?;
    let parsed: HelperOutput =
        serde_json::from_slice(&out).map_err(|_| format!("{program}: unexpected output"))?;
    Ok(Credential {
        username: Some(parsed.username).filter(|u| !u.is_empty()),
        secret: parsed.secret,
        expires_at: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_git_fill_output() {
        let c = parse_git_fill(
            "protocol=https\nhost=h\nusername=me\npassword=pw\npassword_expiry_utc=99\n",
        )
        .unwrap();
        assert_eq!(
            (c.username.as_deref(), c.secret.expose(), c.expires_at),
            (Some("me"), "pw", Some(99))
        );
        assert!(parse_git_fill("username=me\n").is_err());
    }

    #[test]
    fn parses_cargo_provider_responses() {
        let ok = parse_provider_output(
            b"{\"v\":[1]}\n{\"Ok\":{\"kind\":\"get\",\"token\":\"t\",\"cache\":\"expires\",\"expiration\":5,\"operation_independent\":true}}\n",
        )
        .unwrap()
        .unwrap();
        assert_eq!((ok.secret.expose(), ok.expires_at), ("t", Some(5)));
        let session = parse_provider_output(
            b"{\"v\":[1]}\n{\"Ok\":{\"kind\":\"get\",\"token\":\"t\",\"cache\":\"session\",\"operation_independent\":true}}\n",
        )
        .unwrap()
        .unwrap();
        assert_eq!(session.expires_at, None);
        assert!(
            parse_provider_output(b"{\"v\":[1]}\n{\"Err\":{\"kind\":\"not-found\"}}\n")
                .unwrap()
                .is_none()
        );
        let err = parse_provider_output(
            b"{\"v\":[1]}\n{\"Err\":{\"kind\":\"other\",\"message\":\"boom\"}}\n",
        )
        .unwrap_err();
        assert_eq!(err, "boom");
        assert!(parse_provider_output(b"{\"v\":[2]}\n").is_err());
    }

    #[test]
    fn docker_auths_and_helper_names() {
        let config: DockerConfig = serde_json::from_str(
            r#"{"auths": {"https://index.docker.io/v1/": {"auth": "dXNlcjpwYXNz"}, "ghcr.io": {}},
                "credHelpers": {"evil.io": "../../bin/sh"}}"#,
        )
        .unwrap();
        let c = docker_lookup(&config, "docker.io").unwrap();
        assert_eq!(
            (c.username.as_deref(), c.secret.expose()),
            (Some("user"), "pass")
        );
        assert!(docker_lookup(&config, "ghcr.io").is_err());
        assert!(docker_lookup(&config, "evil.io").is_err());
    }

    #[test]
    fn refuses_scopes_outside_forward() {
        let resolver = ClientResolver::new(
            Forward {
                git: vec!["github.com/alfatm/*".into()],
                ..Default::default()
            },
            LocalCargoConfig::default(),
        );
        let err = resolver
            .resolve(&Scope::git("https", "github.com", "acme/foo"))
            .unwrap_err();
        assert!(err.contains("not in [forward]"), "{err}");
        assert!(resolver
            .describe(&Scope::git("https", "github.com", "alfatm/x"))
            .contains("git credential fill"));
    }
}
