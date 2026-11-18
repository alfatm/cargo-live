//! Credential broker types shared by the client and the agent: secrets,
//! scopes, rules, the forwarding allowlist and their matching logic.

use std::fmt;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// A secret value (token or password). `Debug` and `Display` never show
/// it, and the memory is zeroed on drop.
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The secret value. Call sites are the only places a secret leaves
    /// this type: the helper output written to git/cargo/docker, provider
    /// HTTP headers, and the protocol encoder.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Clone for Secret {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        // Only used by tests and protocol round trips; constant time anyway.
        let (a, b) = (self.0.as_bytes(), other.0.as_bytes());
        a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }
}

impl Eq for Secret {}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Serialize for Secret {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Secret)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Git,
    Cargo,
    Docker,
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Kind::Git => "git",
            Kind::Cargo => "cargo",
            Kind::Docker => "docker",
        })
    }
}

/// Build steps. `Fetch` is `cargo fetch` (no third-party code runs);
/// `Build` is `cargo build/run/check`, which runs build scripts and proc
/// macros.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Fetch,
    Build,
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Phase::Fetch => "fetch",
            Phase::Build => "build",
        })
    }
}

/// Phases a scope gets credentials in unless a user rule says otherwise.
pub const DEFAULT_PHASES: &[Phase] = &[Phase::Fetch];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// Providers configured on the agent.
    Agent,
    /// Forwarded from the developer's machine.
    Client,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Source::Agent => "agent",
            Source::Client => "client",
        })
    }
}

/// What a credential is for.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Scope {
    /// A git repository; `host` is lowercase (with `:port` if any), `path`
    /// has no leading/trailing `/` and no `.git` suffix.
    Git {
        protocol: String,
        host: String,
        path: String,
    },
    /// A Cargo registry, by configured name and/or index URL.
    Cargo {
        name: Option<String>,
        index: Option<String>,
    },
    /// A Docker registry host.
    Docker { host: String },
}

impl Scope {
    pub fn git(protocol: &str, host: &str, path: &str) -> Self {
        Scope::Git {
            protocol: protocol.to_ascii_lowercase(),
            host: host.to_ascii_lowercase(),
            path: normalize_repo_path(path),
        }
    }

    pub fn cargo(name: Option<&str>, index: Option<&str>) -> Self {
        Scope::Cargo {
            name: name.filter(|n| !n.is_empty()).map(str::to_owned),
            index: index.filter(|i| !i.is_empty()).map(str::to_owned),
        }
    }

    pub fn docker(server: &str) -> Self {
        Scope::Docker {
            host: normalize_docker_host(server),
        }
    }

    pub fn kind(&self) -> Kind {
        match self {
            Scope::Git { .. } => Kind::Git,
            Scope::Cargo { .. } => Kind::Cargo,
            Scope::Docker { .. } => Kind::Docker,
        }
    }

    /// Rejects values that could not have come from a real request and
    /// that would be unsafe to hand to helpers (line-based protocols).
    pub fn validate(&self) -> Result<(), String> {
        let fields: Vec<&str> = match self {
            Scope::Git {
                protocol,
                host,
                path,
            } => {
                if host.is_empty() {
                    return Err("git scope without a host".into());
                }
                vec![protocol, host, path]
            }
            Scope::Cargo { name, index } => {
                if name.is_none() && index.is_none() {
                    return Err("cargo scope without a registry name or index".into());
                }
                name.iter()
                    .chain(index.iter())
                    .map(String::as_str)
                    .collect()
            }
            Scope::Docker { host } => {
                if host.is_empty() {
                    return Err("docker scope without a host".into());
                }
                vec![host]
            }
        };
        for field in fields {
            if field.len() > 2048 || field.chars().any(|c| c.is_control()) {
                return Err("invalid characters in credential scope".into());
            }
        }
        Ok(())
    }

    /// Fields as a flat JSON object (`kind` plus the scope fields), used
    /// as the stdin of `exec` providers and `forward.command` resolvers.
    pub fn to_json(&self) -> serde_json::Map<String, serde_json::Value> {
        use serde_json::Value;
        let mut map = serde_json::Map::new();
        map.insert("kind".into(), Value::String(self.kind().to_string()));
        match self {
            Scope::Git {
                protocol,
                host,
                path,
            } => {
                map.insert("protocol".into(), protocol.clone().into());
                map.insert("host".into(), host.clone().into());
                map.insert("path".into(), path.clone().into());
            }
            Scope::Cargo { name, index } => {
                map.insert("registry".into(), name.clone().into());
                map.insert("index".into(), index.clone().into());
            }
            Scope::Docker { host } => {
                map.insert("host".into(), host.clone().into());
            }
        }
        map
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Scope::Git { host, path, .. } if path.is_empty() => write!(f, "{host}"),
            Scope::Git { host, path, .. } => write!(f, "{host}/{path}"),
            Scope::Cargo {
                name: Some(name), ..
            } => write!(f, "{name}"),
            Scope::Cargo {
                index: Some(index), ..
            } => write!(f, "{index}"),
            Scope::Cargo { .. } => write!(f, "?"),
            Scope::Docker { host } => write!(f, "{host}"),
        }
    }
}

/// `/acme/foo.git/` -> `acme/foo`.
pub fn normalize_repo_path(path: &str) -> String {
    let path = path.trim_matches('/');
    path.strip_suffix(".git").unwrap_or(path).to_owned()
}

/// `https://index.docker.io/v1/` -> `docker.io`, `ghcr.io:443/x` -> `ghcr.io:443`.
pub fn normalize_docker_host(server: &str) -> String {
    let s = server.trim();
    let s = s.split_once("://").map_or(s, |(_, rest)| rest);
    let host = s.split('/').next().unwrap_or("").to_ascii_lowercase();
    match host.as_str() {
        "index.docker.io" | "registry-1.docker.io" | "registry.hub.docker.com" => {
            "docker.io".into()
        }
        _ => host,
    }
}

/// Strips `sparse+`/`registry+` and a trailing `/` from an index URL.
pub fn normalize_index(index: &str) -> &str {
    let i = index
        .strip_prefix("sparse+")
        .or_else(|| index.strip_prefix("registry+"))
        .unwrap_or(index);
    i.trim_end_matches('/')
}

/// Parses a git remote given as a URL, an scp-like `user@host:path`, or
/// `host/path`. Used by `cargo live creds explain git`.
pub fn parse_git_target(target: &str) -> Result<Scope, String> {
    let target = target.trim();
    if let Some((scheme, rest)) = target.split_once("://") {
        let rest = rest.split_once('@').map_or(rest, |(_, r)| r);
        let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
        let protocol = match scheme {
            "http" => "http",
            _ => "https",
        };
        return Ok(Scope::git(protocol, host, path));
    }
    if let Some((user_host, path)) = target.split_once(':') {
        if !user_host.contains('/') && user_host.contains('@') {
            let host = user_host.split_once('@').map_or(user_host, |(_, h)| h);
            return Ok(Scope::git("https", host, path));
        }
    }
    let (host, path) = target
        .split_once('/')
        .ok_or_else(|| format!("expected a git URL or host/path, got {target:?}"))?;
    Ok(Scope::git("https", host, path))
}

/// A credential: secret plus optional username and expiry (Unix seconds).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    pub username: Option<String>,
    pub secret: Secret,
    pub expires_at: Option<i64>,
}

/// Glob matching where `*` matches any run of characters (including `/`)
/// and `?` exactly one character.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
        } else if let Some((sp, st)) = star {
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

fn literal_len(pattern: &str) -> usize {
    pattern.chars().filter(|c| *c != '*' && *c != '?').count()
}

/// The `match = { ... }` table of a rule or provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredMatch {
    pub kind: Kind,
    /// git and docker: host glob (lowercase).
    #[serde(default)]
    pub host: Option<String>,
    /// git: repository path glob, e.g. `acme/*`.
    #[serde(default)]
    pub path: Option<String>,
    /// cargo: registry name glob.
    #[serde(default)]
    pub registry: Option<String>,
    /// cargo: index URL glob (`sparse+` prefix optional).
    #[serde(default)]
    pub index: Option<String>,
}

impl CredMatch {
    pub fn validate(&self) -> Result<(), String> {
        let bad = match self.kind {
            Kind::Git => self.registry.is_some() || self.index.is_some(),
            Kind::Cargo => self.host.is_some() || self.path.is_some(),
            Kind::Docker => self.path.is_some() || self.registry.is_some() || self.index.is_some(),
        };
        if bad {
            return Err(format!(
                "match for kind {} accepts only {}",
                self.kind,
                match self.kind {
                    Kind::Git => "host and path",
                    Kind::Cargo => "registry and index",
                    Kind::Docker => "host",
                }
            ));
        }
        for v in [&self.host, &self.path, &self.registry, &self.index]
            .into_iter()
            .flatten()
        {
            if v.is_empty() || v.chars().any(|c| c.is_control()) {
                return Err("match values must be nonempty single-line strings".into());
            }
        }
        Ok(())
    }

    pub fn matches(&self, scope: &Scope) -> bool {
        if self.kind != scope.kind() {
            return false;
        }
        let host_ok = |host: &str| {
            self.host
                .as_deref()
                .is_none_or(|p| glob_match(&p.to_ascii_lowercase(), host))
        };
        match scope {
            Scope::Git { host, path, .. } => {
                host_ok(host)
                    && self
                        .path
                        .as_deref()
                        .is_none_or(|p| glob_match(&normalize_repo_path(p), path))
            }
            Scope::Cargo { name, index } => {
                let name_ok = match (&self.registry, name) {
                    (None, _) => true,
                    (Some(p), Some(n)) => glob_match(p, n),
                    (Some(_), None) => false,
                };
                let index_ok = match (&self.index, index) {
                    (None, _) => true,
                    (Some(p), Some(i)) => glob_match(normalize_index(p), normalize_index(i)),
                    (Some(_), None) => false,
                };
                name_ok && index_ok
            }
            Scope::Docker { host } => self
                .host
                .as_deref()
                .is_none_or(|p| glob_match(&normalize_docker_host(p), host)),
        }
    }

    /// Higher is more specific: more fields given, then more literal
    /// (non-wildcard) characters.
    pub fn specificity(&self) -> (usize, usize) {
        let fields = [&self.host, &self.path, &self.registry, &self.index];
        let given = fields.iter().filter(|f| f.is_some()).count();
        let literal = fields
            .iter()
            .filter_map(|f| f.as_deref())
            .map(literal_len)
            .sum();
        (given, literal)
    }

    /// The host, if it is a literal (no wildcard). Used for git URL rewrites.
    pub fn literal_host(&self) -> Option<&str> {
        self.host
            .as_deref()
            .filter(|h| !h.contains(['*', '?']) && self.kind == Kind::Git)
    }
}

impl fmt::Display for CredMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "kind={}", self.kind)?;
        for (name, value) in [
            ("host", &self.host),
            ("path", &self.path),
            ("registry", &self.registry),
            ("index", &self.index),
        ] {
            if let Some(v) = value {
                write!(f, " {name}={v}")?;
            }
        }
        Ok(())
    }
}

/// A client-side rule: which sources to try, in order, for matching scopes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    #[serde(rename = "match")]
    pub matcher: CredMatch,
    pub sources: Vec<Source>,
    /// Phases the scope may get credentials in. Default: fetch only.
    #[serde(default)]
    pub phases: Option<Vec<Phase>>,
}

impl Rule {
    pub fn validate(&self) -> Result<(), String> {
        self.matcher.validate()?;
        if self.sources.is_empty() {
            return Err("a credentials rule needs at least one source".into());
        }
        if self.phases.as_ref().is_some_and(Vec::is_empty) {
            return Err("phases must not be empty (omit it for the default [\"fetch\"])".into());
        }
        Ok(())
    }

    pub fn phases(&self) -> &[Phase] {
        self.phases.as_deref().unwrap_or(DEFAULT_PHASES)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleOrigin {
    /// `$XDG_CONFIG_HOME/cargo-live/config.toml`.
    User,
    /// `.cargo/live.toml` of the workspace (hints: sources only).
    Project,
}

impl fmt::Display for RuleOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RuleOrigin::User => "user",
            RuleOrigin::Project => "project",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    pub origin: RuleOrigin,
    /// 1-based position within its origin, for messages.
    pub index: usize,
    pub rule: Rule,
}

/// What the client machine may hand out (`[forward]`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardAllowlist {
    /// `host/path` globs; an entry without `/` means the whole host.
    #[serde(default)]
    pub git: Vec<String>,
    /// Registry name or index URL globs.
    #[serde(default)]
    pub cargo: Vec<String>,
    /// Registry host globs.
    #[serde(default)]
    pub docker: Vec<String>,
}

impl ForwardAllowlist {
    /// The allowlist entry that permits `scope`, if any.
    pub fn allowing(&self, scope: &Scope) -> Option<&str> {
        match scope {
            Scope::Git { host, path, .. } => {
                let target = format!("{host}/{path}");
                self.git.iter().map(String::as_str).find(|entry| {
                    let entry = entry.to_ascii_lowercase();
                    if entry.contains('/') {
                        let (h, p) = entry.split_once('/').unwrap_or((&entry, ""));
                        glob_match(&format!("{h}/{}", normalize_repo_path(p)), &target)
                            || glob_match(&entry, &target)
                    } else {
                        glob_match(&entry, host)
                    }
                })
            }
            Scope::Cargo { name, index } => self.cargo.iter().map(String::as_str).find(|entry| {
                name.as_deref().is_some_and(|n| glob_match(entry, n))
                    || index
                        .as_deref()
                        .is_some_and(|i| glob_match(normalize_index(entry), normalize_index(i)))
            }),
            Scope::Docker { host } => self
                .docker
                .iter()
                .map(String::as_str)
                .find(|entry| glob_match(&normalize_docker_host(entry), host)),
        }
    }

    pub fn allows(&self, scope: &Scope) -> bool {
        self.allowing(scope).is_some()
    }

    /// Literal git hosts mentioned by the allowlist.
    pub fn literal_git_hosts(&self) -> impl Iterator<Item = &str> {
        self.git
            .iter()
            .map(|e| e.split('/').next().unwrap_or(""))
            .filter(|h| !h.is_empty() && !h.contains(['*', '?']))
    }
}

/// Sent by the client after `Opened` (and before `Explain`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialPolicy {
    /// User rules first, then project hints, each in file order.
    pub rules: Vec<PolicyRule>,
    pub forward: ForwardAllowlist,
    /// `--config` entries with `[registries]`, `[source]` and
    /// `registry.default` from the client's Cargo home configuration.
    pub registries_config: Vec<String>,
}

impl CredentialPolicy {
    /// The rule that applies to `scope`: user rules before project hints;
    /// within an origin the most specific match; ties go to the first.
    pub fn best_rule(&self, scope: &Scope) -> Option<&PolicyRule> {
        for origin in [RuleOrigin::User, RuleOrigin::Project] {
            let mut best: Option<&PolicyRule> = None;
            for rule in self
                .rules
                .iter()
                .filter(|r| r.origin == origin && r.rule.matcher.matches(scope))
            {
                if best
                    .is_none_or(|b| rule.rule.matcher.specificity() > b.rule.matcher.specificity())
                {
                    best = Some(rule);
                }
            }
            if best.is_some() {
                return best;
            }
        }
        None
    }

    pub fn validate(&self) -> Result<(), String> {
        for rule in &self.rules {
            rule.rule.validate()?;
            if rule.origin == RuleOrigin::Project && rule.rule.phases.is_some() {
                return Err("project credential hints cannot set phases".into());
            }
        }
        Ok(())
    }
}

/// A credential decision, reported to the client for its stderr line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredEvent {
    pub scope: Scope,
    pub phase: Phase,
    pub outcome: CredOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredOutcome {
    /// `source` is `agent:<provider name>` or `client`.
    Served {
        source: String,
        expires_at: Option<i64>,
    },
    /// Every source tried, as `"<source> → <reason>"`.
    Failed { chain: Vec<String> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Info,
    Allowed,
    NotAllowed,
    WouldTry,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Verdict::Info => "info",
            Verdict::Allowed => "allowed",
            Verdict::NotAllowed => "not allowed",
            Verdict::WouldTry => "would try",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplainStep {
    pub label: String,
    pub verdict: Verdict,
    pub reason: String,
}

/// The JSON a provider command prints (`exec` providers and
/// `forward.command`): `{secret, username?, expires_at?}`.
#[derive(Deserialize)]
struct CommandOutput {
    secret: Secret,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    expires_at: Option<serde_json::Value>,
}

/// Parses provider command output. With `allow_plain`, output that is not
/// a JSON object is taken as the secret itself (trimmed).
pub fn parse_command_output(stdout: &[u8], allow_plain: bool) -> Result<Credential, String> {
    let text = std::str::from_utf8(stdout).map_err(|_| "output is not UTF-8".to_string())?;
    let trimmed = text.trim();
    if trimmed.starts_with('{') {
        let out: CommandOutput = serde_json::from_str(trimmed).map_err(|e| {
            format!(
                "invalid JSON output (line {}, column {})",
                e.line(),
                e.column()
            )
        })?;
        if out.secret.is_empty() {
            return Err("empty secret".into());
        }
        let expires_at = match out.expires_at {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::Number(n)) => {
                Some(n.as_i64().ok_or("expires_at must be an integer")?)
            }
            Some(serde_json::Value::String(s)) => Some(
                parse_rfc3339(&s)
                    .or_else(|| s.parse().ok())
                    .ok_or("expires_at must be Unix seconds or RFC 3339")?,
            ),
            Some(_) => return Err("expires_at must be Unix seconds or RFC 3339".into()),
        };
        return Ok(Credential {
            username: out.username.filter(|u| !u.is_empty()),
            secret: out.secret,
            expires_at,
        });
    }
    if !allow_plain {
        return Err("expected a JSON object {secret, username?, expires_at?}".into());
    }
    if trimmed.is_empty() {
        return Err("empty output".into());
    }
    if trimmed.contains('\n') {
        return Err("expected a single line (the secret) or a JSON object".into());
    }
    Ok(Credential {
        username: None,
        secret: Secret::new(trimmed),
        expires_at: None,
    })
}

/// Runs `argv` without a shell, writes `stdin`, and returns stdout (at most
/// 1 MiB). Kills the process after `timeout`. stderr is inherited. Error
/// messages never contain the output.
pub fn run_command(
    argv: &[String],
    stdin: &[u8],
    timeout: Duration,
    env: &[(&str, &str)],
) -> Result<Zeroizing<Vec<u8>>, String> {
    let (program, args) = argv.split_first().ok_or("empty command")?;
    let mut child = Command::new(program)
        .args(args)
        .envs(env.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("cannot run {program}: {e}"))?;
    let mut child_stdin = child.stdin.take().expect("piped");
    let input = Zeroizing::new(stdin.to_vec());
    let writer = std::thread::spawn(move || {
        let _ = child_stdin.write_all(&input);
    });
    let mut stdout = child.stdout.take().expect("piped");
    let reader = std::thread::spawn(move || {
        let mut out = Zeroizing::new(Vec::new());
        let mut buf = Zeroizing::new([0u8; 8192]);
        loop {
            match stdout.read(&mut buf[..]) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if out.len() + n > 1 << 20 {
                        return Err(());
                    }
                    out.extend_from_slice(&buf[..n]);
                }
            }
        }
        Ok(out)
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = writer.join();
                return Err(format!("{program} timed out after {}s", timeout.as_secs()));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(e) => return Err(format!("waiting for {program}: {e}")),
        }
    };
    let _ = writer.join();
    let out = reader
        .join()
        .map_err(|_| "reader thread panicked".to_string())?
        .map_err(|_| format!("{program} printed more than 1 MiB"))?;
    if !status.success() {
        return Err(format!("{program} failed ({status})"));
    }
    Ok(out)
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Unix seconds as RFC 3339 in UTC, e.g. `2016-07-11T22:14:10Z`.
pub fn format_rfc3339(secs: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| secs.to_string())
}

/// Parses an RFC 3339 timestamp (any offset) into Unix seconds.
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    time::OffsetDateTime::parse(s.trim(), &time::format_description::well_known::Rfc3339)
        .ok()
        .map(|t| t.unix_timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(origin: RuleOrigin, index: usize, m: CredMatch, sources: &[Source]) -> PolicyRule {
        PolicyRule {
            origin,
            index,
            rule: Rule {
                matcher: m,
                sources: sources.to_vec(),
                phases: None,
            },
        }
    }

    fn git(host: Option<&str>, path: Option<&str>) -> CredMatch {
        CredMatch {
            kind: Kind::Git,
            host: host.map(Into::into),
            path: path.map(Into::into),
            registry: None,
            index: None,
        }
    }

    #[test]
    fn secret_is_redacted() {
        let s = Secret::new("hunter2-very-secret");
        assert!(!format!("{s:?}").contains("hunter2"));
        assert!(!format!("{s}").contains("hunter2"));
        let c = Credential {
            username: Some("u".into()),
            secret: s.clone(),
            expires_at: None,
        };
        assert!(!format!("{c:?}").contains("hunter2"));
        assert!(!format!("{c:#?}").contains("hunter2"));
        assert_eq!(s.expose(), "hunter2-very-secret");
        assert_eq!(s, Secret::new("hunter2-very-secret"));
    }

    #[test]
    fn globs() {
        assert!(glob_match("acme/*", "acme/foo"));
        assert!(glob_match("acme/*", "acme/foo/bar"));
        assert!(!glob_match("acme/*", "acmex/foo"));
        assert!(glob_match("*", ""));
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "ac"));
        assert!(glob_match("*.acme.dev", "git.acme.dev"));
        assert!(glob_match("a*b*c", "axxbyyc"));
        assert!(!glob_match("a*b*c", "axxbyy"));
    }

    #[test]
    fn scopes_normalize() {
        assert_eq!(
            Scope::git("HTTPS", "GitHub.com", "/acme/foo.git/"),
            Scope::Git {
                protocol: "https".into(),
                host: "github.com".into(),
                path: "acme/foo".into()
            }
        );
        assert_eq!(
            Scope::docker("https://index.docker.io/v1/"),
            Scope::Docker {
                host: "docker.io".into()
            }
        );
        assert_eq!(
            Scope::docker("ghcr.io"),
            Scope::docker("https://ghcr.io/v2/")
        );
        for (input, expected) in [
            ("https://github.com/acme/foo.git", "github.com/acme/foo"),
            ("git@github.com:acme/foo.git", "github.com/acme/foo"),
            ("ssh://git@github.com/acme/foo", "github.com/acme/foo"),
            ("github.com/acme/foo", "github.com/acme/foo"),
            ("http://127.0.0.1:8080/x/y.git", "127.0.0.1:8080/x/y"),
        ] {
            assert_eq!(parse_git_target(input).unwrap().to_string(), expected);
        }
        assert!(Scope::git("https", "h", "a\nb").validate().is_err());
        assert!(Scope::cargo(None, None).validate().is_err());
    }

    #[test]
    fn rule_precedence_user_project_specificity_ties() {
        let foo = Scope::git("https", "github.com", "acme/foo");
        let policy = CredentialPolicy {
            rules: vec![
                rule(
                    RuleOrigin::User,
                    1,
                    git(Some("github.com"), None),
                    &[Source::Agent],
                ),
                rule(
                    RuleOrigin::User,
                    2,
                    git(Some("github.com"), Some("acme/*")),
                    &[Source::Client],
                ),
                rule(
                    RuleOrigin::User,
                    3,
                    git(Some("github.com"), Some("acme/*")),
                    &[Source::Agent],
                ),
                rule(
                    RuleOrigin::Project,
                    1,
                    git(Some("github.com"), Some("acme/foo")),
                    &[Source::Agent, Source::Client],
                ),
                rule(
                    RuleOrigin::Project,
                    2,
                    git(Some("gitlab.com"), None),
                    &[Source::Client],
                ),
            ],
            ..Default::default()
        };
        // User rules win over a more specific project hint; among user
        // rules the more specific wins; ties go to the first.
        let best = policy.best_rule(&foo).unwrap();
        assert_eq!((best.origin, best.index), (RuleOrigin::User, 2));
        // Project hints apply when no user rule matches.
        let gl = Scope::git("https", "gitlab.com", "x/y");
        let best = policy.best_rule(&gl).unwrap();
        assert_eq!((best.origin, best.index), (RuleOrigin::Project, 2));
        // No rule at all.
        assert!(policy
            .best_rule(&Scope::git("https", "example.com", "a/b"))
            .is_none());
        // Literal beats glob of the same shape.
        let more = git(Some("github.com"), Some("acme/foo"));
        assert!(more.specificity() > git(Some("github.com"), Some("acme/*")).specificity());
        assert!(
            git(Some("*"), Some("*")).specificity() > git(Some("github.com"), None).specificity()
        );
    }

    #[test]
    fn matcher_kinds_and_cargo_fields() {
        let m = CredMatch {
            kind: Kind::Cargo,
            host: None,
            path: None,
            registry: Some("acme".into()),
            index: None,
        };
        assert!(m.matches(&Scope::cargo(Some("acme"), Some("sparse+https://r/"))));
        assert!(!m.matches(&Scope::cargo(None, Some("sparse+https://r/"))));
        assert!(!m.matches(&Scope::git("https", "acme", "")));
        let by_index = CredMatch {
            registry: None,
            index: Some("https://r/index".into()),
            ..m.clone()
        };
        assert!(by_index.matches(&Scope::cargo(None, Some("sparse+https://r/index/"))));
        let invalid = CredMatch {
            host: Some("x".into()),
            ..m
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn forward_allowlist() {
        let fwd = ForwardAllowlist {
            git: vec!["github.com/alfatm/*".into(), "gitlab.acme.dev".into()],
            cargo: vec!["acme".into()],
            docker: vec!["ghcr.io".into()],
        };
        assert!(fwd.allows(&Scope::git("https", "github.com", "alfatm/x.git")));
        assert!(!fwd.allows(&Scope::git("https", "github.com", "acme/x")));
        assert!(fwd.allows(&Scope::git("https", "gitlab.acme.dev", "a/b/c")));
        assert!(fwd.allows(&Scope::cargo(Some("acme"), None)));
        assert!(!fwd.allows(&Scope::cargo(Some("other"), None)));
        assert!(fwd.allows(&Scope::docker("https://ghcr.io/v2/")));
        assert!(!fwd.allows(&Scope::docker("docker.io")));
        assert_eq!(
            fwd.literal_git_hosts().collect::<Vec<_>>(),
            ["github.com", "gitlab.acme.dev"]
        );
    }

    #[test]
    fn command_output_parsing() {
        let c = parse_command_output(b"tok123\n", true).unwrap();
        assert_eq!(c.secret.expose(), "tok123");
        assert!(parse_command_output(b"tok123\n", false).is_err());
        assert!(parse_command_output(b"", true).is_err());
        assert!(parse_command_output(b"a\nb\n", true).is_err());
        let c = parse_command_output(
            br#"{"secret":"s","username":"u","expires_at":"2030-01-01T00:00:00Z"}"#,
            false,
        )
        .unwrap();
        assert_eq!(c.username.as_deref(), Some("u"));
        assert_eq!(c.expires_at, Some(1_893_456_000));
        let c = parse_command_output(br#"{"secret":"s","expires_at":5}"#, false).unwrap();
        assert_eq!(c.expires_at, Some(5));
        let err = parse_command_output(br#"{"secret":"leak-me","bogus":"#, false).unwrap_err();
        assert!(!err.contains("leak-me"), "{err}");
        assert!(parse_command_output(br#"{"secret":""}"#, false).is_err());
    }

    #[test]
    fn run_command_timeout_and_failures() {
        let sh = |script: &str| vec!["sh".to_string(), "-c".to_string(), script.to_string()];
        let out = run_command(&sh("cat"), b"hello", Duration::from_secs(5), &[]).unwrap();
        assert_eq!(&out[..], b"hello");
        let started = Instant::now();
        let err = run_command(&sh("sleep 5"), b"", Duration::from_millis(300), &[]).unwrap_err();
        assert!(err.contains("timed out"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(4));
        let err = run_command(
            &sh("echo secret-out; exit 3"),
            b"",
            Duration::from_secs(5),
            &[],
        )
        .unwrap_err();
        assert!(!err.contains("secret-out"), "{err}");
        assert!(run_command(&["/nonexistent/x".into()], b"", Duration::from_secs(1), &[]).is_err());
    }

    #[test]
    fn rfc3339_round_trip() {
        for secs in [0, 951_782_400, 1_795_000_000, 1_893_456_000] {
            assert_eq!(parse_rfc3339(&format_rfc3339(secs)), Some(secs));
        }
        assert_eq!(parse_rfc3339("2016-07-11T22:14:10Z"), Some(1_468_275_250));
        assert_eq!(
            parse_rfc3339("2016-07-11T22:14:10.123+01:00"),
            Some(1_468_271_650)
        );
        assert_eq!(parse_rfc3339("nope"), None);
    }
}
