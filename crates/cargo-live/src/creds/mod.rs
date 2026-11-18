//! Client side of the credential broker: the user's credential config
//! (`$XDG_CONFIG_HOME/cargo-live/config.toml`), project hints from
//! `.cargo/live.toml`, registry definitions from the local Cargo config,
//! and the resolvers that serve forwarded requests.

pub mod registries;
pub mod resolve;

use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

use cargo_live_proto::cred::{
    CredEvent, CredMatch, CredOutcome, CredentialPolicy, ExplainStep, ForwardAllowlist, PolicyRule,
    Rule, RuleOrigin, Scope, Source, Verdict,
};

use crate::{error, store, Result};

/// `$XDG_CONFIG_HOME/cargo-live/config.toml`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserConfig {
    #[serde(default)]
    pub forward: Forward,
    #[serde(default)]
    pub credentials: Vec<Rule>,
}

/// `[forward]`: what this machine may hand out, and how.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Forward {
    #[serde(default)]
    pub git: Vec<String>,
    #[serde(default)]
    pub cargo: Vec<String>,
    #[serde(default)]
    pub docker: Vec<String>,
    /// Allow git credential helpers to prompt on a terminal.
    #[serde(default)]
    pub interactive: bool,
    #[serde(default)]
    pub command: Vec<ForwardCommand>,
}

impl Forward {
    pub fn allowlist(&self) -> ForwardAllowlist {
        ForwardAllowlist {
            git: self.git.clone(),
            cargo: self.cargo.clone(),
            docker: self.docker.clone(),
        }
    }
}

/// `[[forward.command]]`: a custom resolver for matching scopes.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardCommand {
    #[serde(rename = "match")]
    pub matcher: CredMatch,
    /// argv (no shell). stdin: JSON request; stdout: the secret or JSON
    /// `{secret, username?, expires_at?}`.
    pub command: Vec<String>,
    /// Seconds (default 60).
    #[serde(default)]
    pub timeout: Option<u64>,
}

/// `[[credentials]]` in `.cargo/live.toml`: hints with sources only. They
/// rank below user rules and cannot extend `[forward]` or set phases.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectRule {
    #[serde(rename = "match")]
    pub matcher: CredMatch,
    pub sources: Vec<Source>,
}

impl ProjectRule {
    pub fn validate(&self) -> Result<()> {
        self.to_rule().validate().map_err(error)?;
        Ok(())
    }

    fn to_rule(&self) -> Rule {
        Rule {
            matcher: self.matcher.clone(),
            sources: self.sources.clone(),
            phases: None,
        }
    }
}

pub fn user_config_path() -> Result<PathBuf> {
    Ok(store::config_dir()?.join("config.toml"))
}

impl UserConfig {
    pub fn load() -> Result<Self> {
        let path = user_config_path()?;
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(error(format!("cannot read {}: {e}", path.display())).into()),
        };
        Self::parse(&text).map_err(|e| error(format!("invalid {}: {e}", path.display())).into())
    }

    pub fn parse(text: &str) -> Result<Self> {
        let config: Self = toml::from_str(text)?;
        for rule in &config.credentials {
            rule.validate().map_err(error)?;
        }
        for command in &config.forward.command {
            command.matcher.validate().map_err(error)?;
            if command.command.is_empty() || command.command[0].is_empty() {
                return Err(error("forward.command needs a nonempty command").into());
            }
        }
        Ok(config)
    }
}

/// User rules first, then project hints.
pub fn policy(
    user: &UserConfig,
    project: &[ProjectRule],
    registries_config: Vec<String>,
) -> CredentialPolicy {
    let mut rules: Vec<PolicyRule> = user
        .credentials
        .iter()
        .enumerate()
        .map(|(i, rule)| PolicyRule {
            origin: RuleOrigin::User,
            index: i + 1,
            rule: rule.clone(),
        })
        .collect();
    rules.extend(project.iter().enumerate().map(|(i, hint)| PolicyRule {
        origin: RuleOrigin::Project,
        index: i + 1,
        rule: hint.to_rule(),
    }));
    CredentialPolicy {
        rules,
        forward: user.forward.allowlist(),
        registries_config,
    }
}

fn source_label(source: &str) -> String {
    match source.strip_prefix("agent:") {
        Some(name) => format!("agent ({name})"),
        None => source.to_owned(),
    }
}

/// The stderr line for a credential decision.
pub fn event_line(event: &CredEvent) -> String {
    let kind = event.scope.kind();
    match &event.outcome {
        CredOutcome::Served { source, .. } => format!(
            "cargo-live: credential for {kind} {} from {} ({} phase)",
            event.scope,
            source_label(source),
            event.phase
        ),
        CredOutcome::Failed { chain } => format!(
            "cargo-live: no credential for {kind} {}: {}",
            event.scope,
            chain.join("; ")
        ),
    }
}

/// `cargo live creds explain` output.
pub fn explain_text(
    scope: &Scope,
    agent: &str,
    steps: &[ExplainStep],
    resolver: &resolve::ClientResolver,
) -> String {
    let mut out = format!(
        "credentials for {} {} (agent {agent})\n",
        scope.kind(),
        scope
    );
    let width = steps
        .iter()
        .map(|s| s.label.len())
        .max()
        .unwrap_or(0)
        .max("this machine".len());
    for step in steps {
        let verdict = match step.verdict {
            Verdict::Info => String::new(),
            v => format!("[{v}] "),
        };
        out.push_str(&format!(
            "  {:width$}  {verdict}{}\n",
            step.label, step.reason
        ));
    }
    out.push_str(&format!(
        "  {:width$}  {}\n",
        "this machine",
        resolver.describe(scope)
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use cargo_live_proto::cred::{Kind, Phase};

    #[test]
    fn parses_user_config_from_the_readme() {
        let config = UserConfig::parse(
            r#"
[forward]
git = ["github.com/alfatm/*", "gitlab.acme.dev/*"]
cargo = ["acme"]
docker = []

[[forward.command]]
match = { kind = "git", host = "gitlab.acme.dev" }
command = ["glab", "auth", "token"]

[[credentials]]
match = { kind = "git", host = "github.com", path = "acme/*" }
sources = ["agent"]
[[credentials]]
match = { kind = "git", host = "github.com", path = "alfatm/*" }
sources = ["client"]
[[credentials]]
match = { kind = "cargo", registry = "acme" }
sources = ["agent", "client"]
phases = ["fetch"]
"#,
        )
        .unwrap();
        assert_eq!(config.credentials.len(), 3);
        assert_eq!(config.forward.command[0].command, ["glab", "auth", "token"]);
        assert!(!config.forward.interactive);
        let project = vec![ProjectRule {
            matcher: CredMatch {
                kind: Kind::Docker,
                host: Some("ghcr.io".into()),
                path: None,
                registry: None,
                index: None,
            },
            sources: vec![Source::Client],
        }];
        let policy = policy(&config, &project, vec![]);
        assert_eq!(policy.rules.len(), 4);
        assert_eq!(policy.rules[3].origin, RuleOrigin::Project);
        assert_eq!(
            policy.rules[2].rule.phases.as_deref(),
            Some(&[Phase::Fetch][..])
        );
        assert!(policy.validate().is_ok());

        for bad in [
            "[[credentials]]\nmatch = { kind = 'git' }\nsources = []\n",
            "[[credentials]]\nmatch = { kind = 'git', registry = 'x' }\nsources = ['agent']\n",
            "[forward]\nunknown = 1\n",
            "[[forward.command]]\nmatch = { kind = 'git' }\ncommand = []\n",
        ] {
            assert!(UserConfig::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn formats_event_lines() {
        let scope = Scope::git("https", "github.com", "acme/foo");
        let served = CredEvent {
            scope: scope.clone(),
            phase: Phase::Fetch,
            outcome: CredOutcome::Served {
                source: "agent:acme-github".into(),
                expires_at: None,
            },
        };
        assert_eq!(
            event_line(&served),
            "cargo-live: credential for git github.com/acme/foo from agent (acme-github) (fetch phase)"
        );
        let failed = CredEvent {
            scope,
            phase: Phase::Fetch,
            outcome: CredOutcome::Failed {
                chain: vec![
                    "agent → not allowed for token".into(),
                    "client → not in [forward]".into(),
                ],
            },
        };
        assert_eq!(
            event_line(&failed),
            "cargo-live: no credential for git github.com/acme/foo: agent → not allowed for token; client → not in [forward]"
        );
    }
}
