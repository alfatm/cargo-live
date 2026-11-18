//! Per-session credential resolution.
//!
//! For each request:
//! 1. The best client rule (user rules, then project hints; most specific
//!    match; first on ties). Without a rule: sources `[agent, client]`,
//!    phases `["fetch"]` (`client` only applies if the scope is in the
//!    client's `[forward]`).
//! 2. The current phase must be in the rule's phases.
//! 3. Sources in order; `agent` is the first provider whose match fits,
//!    whose `allow_tokens` includes the token and whose `phases` allow the
//!    phase; `client` asks the client unless the token has
//!    `allow_client = false` or the scope is not in `[forward]`.
//! 4. The first success wins and is cached for the session (until shortly
//!    before it expires). Failures are not cached.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use cargo_live_proto::cred::{
    now_unix, CredEvent, CredOutcome, Credential, CredentialPolicy, ExplainStep, Phase, PolicyRule,
    Scope, Source, Verdict, DEFAULT_PHASES,
};

use super::audit;
use super::config::{AgentCreds, Provider};
use super::providers;

/// Cached credentials are dropped this long before they expire.
const EXPIRY_MARGIN: i64 = 60;
/// How long the agent waits for the client to resolve a credential.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(180);

/// Messages from brokers to the session's job loop, which owns the
/// connection to the client.
pub enum ToClient {
    Request {
        scope: Scope,
        phase: Phase,
        reply: oneshot::Sender<Result<Credential, String>>,
    },
    Event(CredEvent),
}

pub struct CredSession {
    pub token: String,
    workspace: Mutex<String>,
    policy: Mutex<CredentialPolicy>,
    creds: Arc<AgentCreds>,
    audit_log: PathBuf,
    /// Successful resolutions with their source label.
    cache: Mutex<HashMap<Scope, (String, Credential)>>,
    /// Index URL → registry name for the current job, so a request that
    /// only carries an index (e.g. a `[source]` replacement of crates.io)
    /// matches rules and `[forward]` entries written with the name.
    registry_indexes: Mutex<HashMap<String, String>>,
}

struct Plan {
    rule: Option<PolicyRule>,
    sources: Vec<Source>,
    phases: Vec<Phase>,
}

impl Plan {
    fn describe(&self) -> String {
        match &self.rule {
            Some(r) => format!("{} rule #{} (match {})", r.origin, r.index, r.rule.matcher),
            None => "default (no matching rule)".into(),
        }
    }
}

fn list<T: std::fmt::Display>(items: &[T]) -> String {
    let items: Vec<String> = items.iter().map(|i| format!("\"{i}\"")).collect();
    format!("[{}]", items.join(", "))
}

impl CredSession {
    pub fn new(token: String, creds: Arc<AgentCreds>, audit_log: PathBuf) -> Self {
        Self {
            token,
            workspace: Mutex::new(String::new()),
            policy: Mutex::new(CredentialPolicy::default()),
            creds,
            audit_log,
            cache: Mutex::new(HashMap::new()),
            registry_indexes: Mutex::new(HashMap::new()),
        }
    }

    pub fn set_workspace(&self, id: &str) {
        *self.workspace.lock().unwrap() = id.to_owned();
    }

    pub fn set_policy(&self, policy: CredentialPolicy) {
        *self.policy.lock().unwrap() = policy;
        // Decisions depend on the policy.
        self.cache.lock().unwrap().clear();
    }

    pub fn set_registry_indexes(&self, indexes: HashMap<String, String>) {
        *self.registry_indexes.lock().unwrap() = indexes;
    }

    /// Fills in the registry name of a cargo scope that only has an index.
    fn named(&self, scope: &Scope) -> Scope {
        match scope {
            Scope::Cargo {
                name: None,
                index: Some(index),
            } => Scope::Cargo {
                name: self.registry_indexes.lock().unwrap().get(index).cloned(),
                index: Some(index.clone()),
            },
            other => other.clone(),
        }
    }

    pub fn registries_config(&self) -> Vec<String> {
        self.policy.lock().unwrap().registries_config.clone()
    }

    /// Whether any scope may get credentials during the build step, i.e.
    /// whether the broker stays open for it.
    pub fn build_phase_enabled(&self) -> bool {
        self.policy
            .lock()
            .unwrap()
            .rules
            .iter()
            .any(|r| r.rule.phases().contains(&Phase::Build))
    }

    /// Literal git hosts mentioned by rules, providers and `[forward]`,
    /// plus github.com: their SSH URLs are rewritten to HTTPS.
    pub fn git_hosts(&self) -> Vec<String> {
        let policy = self.policy.lock().unwrap();
        let mut hosts = vec!["github.com".to_owned()];
        let candidates = policy
            .rules
            .iter()
            .filter_map(|r| r.rule.matcher.literal_host())
            .chain(
                self.creds
                    .providers
                    .iter()
                    .filter_map(|p| p.matcher.literal_host()),
            )
            .chain(policy.forward.literal_git_hosts());
        for host in candidates {
            let host = host.to_ascii_lowercase();
            if !host.contains(':') && !hosts.contains(&host) {
                hosts.push(host);
            }
        }
        hosts
    }

    fn plan(&self, policy: &CredentialPolicy, scope: &Scope) -> Plan {
        match policy.best_rule(scope) {
            Some(rule) => {
                let mut sources = Vec::new();
                for s in &rule.rule.sources {
                    if !sources.contains(s) {
                        sources.push(*s);
                    }
                }
                Plan {
                    phases: rule.rule.phases().to_vec(),
                    sources,
                    rule: Some(rule.clone()),
                }
            }
            None => Plan {
                rule: None,
                sources: vec![Source::Agent, Source::Client],
                phases: DEFAULT_PHASES.to_vec(),
            },
        }
    }

    /// The agent provider to use, or why there is none.
    fn select_provider(&self, scope: &Scope, phase: Phase) -> Result<&Provider, String> {
        let mut rejection = None;
        for p in self
            .creds
            .providers
            .iter()
            .filter(|p| p.matcher.matches(scope))
        {
            if !p.allows_token(&self.token) {
                rejection.get_or_insert_with(|| {
                    format!("not allowed for token {:?} ({})", self.token, p.name)
                });
            } else if !p.allows_phase(phase) {
                rejection
                    .get_or_insert_with(|| format!("not enabled for phase {phase} ({})", p.name));
            } else {
                return Ok(p);
            }
        }
        Err(rejection.unwrap_or_else(|| "no agent provider matches".into()))
    }

    fn client_gate(&self, policy: &CredentialPolicy, scope: &Scope) -> Result<(), String> {
        if !self.creds.token_policy(&self.token).allow_client {
            return Err(format!(
                "disabled for token {:?} (allow_client = false)",
                self.token
            ));
        }
        if !policy.forward.allows(scope) {
            return Err("not in [forward]".into());
        }
        Ok(())
    }

    fn cached(&self, scope: &Scope) -> Option<(String, Credential)> {
        let mut cache = self.cache.lock().unwrap();
        let fresh = cache
            .get(scope)
            .is_some_and(|(_, c)| c.expires_at.is_none_or(|e| e - EXPIRY_MARGIN > now_unix()));
        if !fresh {
            cache.remove(scope);
            return None;
        }
        cache.get(scope).cloned()
    }

    fn audit(
        &self,
        scope: &Scope,
        phase: Phase,
        source: &str,
        outcome: &str,
        expires_at: Option<i64>,
        chain: Vec<String>,
    ) {
        let workspace = self.workspace.lock().unwrap().clone();
        audit::record(
            &self.audit_log,
            &audit::Entry {
                ts: crate::log::now_rfc3339(),
                token: &self.token,
                workspace: &workspace,
                kind: scope.kind().to_string(),
                scope: scope.to_string(),
                phase: phase.to_string(),
                source,
                outcome,
                expires_at: audit::expires(expires_at),
                chain,
            },
        );
    }

    async fn notify(
        client: &mpsc::Sender<ToClient>,
        scope: &Scope,
        phase: Phase,
        outcome: CredOutcome,
    ) {
        let _ = client
            .send(ToClient::Event(CredEvent {
                scope: scope.clone(),
                phase,
                outcome,
            }))
            .await;
    }

    async fn fail(
        &self,
        client: &mpsc::Sender<ToClient>,
        scope: &Scope,
        phase: Phase,
        chain: Vec<String>,
    ) -> Option<Credential> {
        self.audit(scope, phase, "none", "denied", None, chain.clone());
        Self::notify(client, scope, phase, CredOutcome::Failed { chain }).await;
        None
    }

    /// Resolves a credential for a broker request. `None` means no source
    /// provided one; the reasons are in the agent log, the audit log and
    /// the client's output, not in the helper's answer.
    pub async fn resolve(
        &self,
        scope: &Scope,
        phase: Phase,
        client: &mpsc::Sender<ToClient>,
    ) -> Option<Credential> {
        let scope = &self.named(scope);
        if let Err(e) = scope.validate() {
            return self.fail(client, scope, phase, vec![e]).await;
        }
        let policy = self.policy.lock().unwrap().clone();
        let plan = self.plan(&policy, scope);
        if !plan.phases.contains(&phase) {
            let reason = format!(
                "phase {phase} not allowed (phases = {}, {})",
                list(&plan.phases),
                plan.describe()
            );
            return self.fail(client, scope, phase, vec![reason]).await;
        }
        if let Some((source, c)) = self.cached(scope) {
            self.audit(scope, phase, &source, "cached", c.expires_at, Vec::new());
            return Some(c);
        }
        let mut chain = Vec::new();
        for source in &plan.sources {
            let result = match source {
                Source::Agent => match self.select_provider(scope, phase) {
                    Err(reason) => Err(format!("agent → {reason}")),
                    Ok(p) => providers::fetch(p, scope, &self.token, phase)
                        .await
                        .map(|c| (format!("agent:{}", p.name), c))
                        .map_err(|e| format!("agent ({}) → {e}", p.name)),
                },
                Source::Client => match self.client_gate(&policy, scope) {
                    Err(reason) => Err(format!("client → {reason}")),
                    Ok(()) => self
                        .ask_client(client, scope, phase)
                        .await
                        .map(|c| ("client".to_owned(), c))
                        .map_err(|e| format!("client → {e}")),
                },
            };
            match result {
                Ok((label, credential)) => {
                    self.audit(
                        scope,
                        phase,
                        &label,
                        "served",
                        credential.expires_at,
                        Vec::new(),
                    );
                    Self::notify(
                        client,
                        scope,
                        phase,
                        CredOutcome::Served {
                            source: label.clone(),
                            expires_at: credential.expires_at,
                        },
                    )
                    .await;
                    self.cache
                        .lock()
                        .unwrap()
                        .insert(scope.clone(), (label, credential.clone()));
                    return Some(credential);
                }
                Err(reason) => chain.push(reason),
            }
        }
        self.fail(client, scope, phase, chain).await
    }

    async fn ask_client(
        &self,
        client: &mpsc::Sender<ToClient>,
        scope: &Scope,
        phase: Phase,
    ) -> Result<Credential, String> {
        let (reply, answer) = oneshot::channel();
        client
            .send(ToClient::Request {
                scope: scope.clone(),
                phase,
                reply,
            })
            .await
            .map_err(|_| "build step already finished".to_string())?;
        match tokio::time::timeout(CLIENT_TIMEOUT, answer).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err("connection to the client closed".into()),
            Err(_) => Err(format!("no answer within {}s", CLIENT_TIMEOUT.as_secs())),
        }
    }

    /// Dry run: what would be tried for `scope`, without minting tokens or
    /// running client resolvers.
    pub fn explain(&self, scope: &Scope) -> Vec<ExplainStep> {
        let policy = self.policy.lock().unwrap().clone();
        let plan = self.plan(&policy, scope);
        let mut steps = vec![ExplainStep {
            label: "rule".into(),
            verdict: Verdict::Info,
            reason: format!(
                "{}: sources = {}, phases = {}",
                plan.describe(),
                list(&plan.sources),
                list(&plan.phases)
            ),
        }];
        if let Err(e) = scope.validate() {
            steps.push(ExplainStep {
                label: "scope".into(),
                verdict: Verdict::NotAllowed,
                reason: e,
            });
            return steps;
        }
        for phase in [Phase::Fetch, Phase::Build] {
            if !plan.phases.contains(&phase) {
                steps.push(ExplainStep {
                    label: format!("{phase} phase"),
                    verdict: Verdict::NotAllowed,
                    reason: format!("phase {phase} is not in phases"),
                });
                continue;
            }
            for source in &plan.sources {
                let (verdict, reason) = match source {
                    Source::Agent => match self.select_provider(scope, phase) {
                        Ok(p) => (
                            Verdict::Allowed,
                            format!("would use provider {:?} ({})", p.name, p.type_name()),
                        ),
                        Err(reason) => (Verdict::NotAllowed, reason),
                    },
                    Source::Client => match self.client_gate(&policy, scope) {
                        Ok(()) => (
                            Verdict::WouldTry,
                            "would ask the client (in [forward])".into(),
                        ),
                        Err(reason) => (Verdict::NotAllowed, reason),
                    },
                };
                steps.push(ExplainStep {
                    label: format!("{phase} phase: {source}"),
                    verdict,
                    reason,
                });
            }
        }
        steps
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cred::config::{ProviderKind, SecretRef, TokenPolicy};
    use cargo_live_proto::cred::{CredMatch, ForwardAllowlist, Kind, Rule, RuleOrigin};

    #[test]
    fn index_only_cargo_scopes_get_the_registry_name() {
        let session = CredSession::new(
            "t".into(),
            Arc::new(AgentCreds::default()),
            PathBuf::from("/nonexistent/audit.log"),
        );
        let index = "sparse+https://crates.example/api/v1/cratesio/";
        session.set_registry_indexes(HashMap::from([(index.to_owned(), "mirror".to_owned())]));
        assert_eq!(
            session.named(&Scope::cargo(None, Some(index))),
            Scope::cargo(Some("mirror"), Some(index))
        );
        let other = Scope::cargo(None, Some("sparse+https://other/"));
        assert_eq!(session.named(&other), other);
    }

    fn provider(
        name: &str,
        host: &str,
        tokens: &[&str],
        phases: Option<Vec<Phase>>,
        file: &std::path::Path,
    ) -> Provider {
        Provider {
            name: name.into(),
            matcher: CredMatch {
                kind: Kind::Git,
                host: Some(host.into()),
                path: None,
                registry: None,
                index: None,
            },
            allow_tokens: tokens.iter().map(|t| t.to_string()).collect(),
            phases,
            kind: ProviderKind::File {
                path: SecretRef::File(file.into()),
                username: Some(name.into()),
            },
        }
    }

    fn session(
        token: &str,
        providers: Vec<Provider>,
        allow_client: bool,
        dir: &std::path::Path,
    ) -> CredSession {
        let mut tokens = std::collections::BTreeMap::new();
        tokens.insert(
            "ci".to_owned(),
            TokenPolicy {
                allow_client: false,
            },
        );
        if !allow_client {
            tokens.insert(
                token.to_owned(),
                TokenPolicy {
                    allow_client: false,
                },
            );
        }
        CredSession::new(
            token.into(),
            Arc::new(AgentCreds { providers, tokens }),
            dir.join("audit.log"),
        )
    }

    fn user_rule(host: &str, sources: &[Source], phases: Option<Vec<Phase>>) -> PolicyRule {
        PolicyRule {
            origin: RuleOrigin::User,
            index: 1,
            rule: Rule {
                matcher: CredMatch {
                    kind: Kind::Git,
                    host: Some(host.into()),
                    path: None,
                    registry: None,
                    index: None,
                },
                sources: sources.to_vec(),
                phases,
            },
        }
    }

    /// Answers client requests with `answer` and collects events.
    fn fake_client(
        answer: Option<&'static str>,
    ) -> (mpsc::Sender<ToClient>, Arc<Mutex<Vec<CredEvent>>>) {
        let (tx, mut rx) = mpsc::channel::<ToClient>(8);
        let events = Arc::new(Mutex::new(Vec::new()));
        let seen = events.clone();
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                match msg {
                    ToClient::Request { reply, .. } => {
                        let _ = reply.send(match answer {
                            Some(s) => Ok(Credential {
                                username: None,
                                secret: cargo_live_proto::cred::Secret::new(s),
                                expires_at: None,
                            }),
                            None => Err("refused".into()),
                        });
                    }
                    ToClient::Event(e) => seen.lock().unwrap().push(e),
                }
            }
        });
        (tx, events)
    }

    /// Waits for the event of the last resolution and takes it.
    async fn take_event(events: &Arc<Mutex<Vec<CredEvent>>>) -> CredEvent {
        for _ in 0..500 {
            {
                let mut events = events.lock().unwrap();
                if !events.is_empty() {
                    return events.remove(0);
                }
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        panic!("no credential event");
    }

    async fn failed_chain(events: &Arc<Mutex<Vec<CredEvent>>>) -> Vec<String> {
        match take_event(events).await.outcome {
            CredOutcome::Failed { chain } => chain,
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn allow_tokens_and_fallback_to_client() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("s");
        std::fs::write(&secret, "agent-secret").unwrap();
        let s = session(
            "alice",
            vec![provider("only-bob", "h", &["bob"], None, &secret)],
            true,
            dir.path(),
        );
        s.set_policy(CredentialPolicy {
            forward: ForwardAllowlist {
                git: vec!["h/*".into()],
                ..Default::default()
            },
            ..Default::default()
        });
        let scope = Scope::git("https", "h", "a/b");
        let (tx, events) = fake_client(Some("client-secret"));
        let c = s.resolve(&scope, Phase::Fetch, &tx).await.unwrap();
        assert_eq!(c.secret.expose(), "client-secret");
        assert!(matches!(
            take_event(&events).await.outcome,
            CredOutcome::Served { source, .. } if source == "client"
        ));
        // Not in [forward] -> refused with the full chain.
        s.set_policy(CredentialPolicy::default());
        assert!(s.resolve(&scope, Phase::Fetch, &tx).await.is_none());
        let chain = failed_chain(&events).await;
        assert_eq!(chain.len(), 2);
        assert!(
            chain[0].starts_with("agent → not allowed for token"),
            "{chain:?}"
        );
        assert_eq!(chain[1], "client → not in [forward]");
        let audit = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
        assert!(!audit.contains("client-secret") && !audit.contains("agent-secret"));
        assert_eq!(audit.lines().count(), 2);
    }

    #[tokio::test]
    async fn allow_client_false_blocks_forwarding() {
        let dir = tempfile::tempdir().unwrap();
        let s = session("ci", vec![], true, dir.path());
        s.set_policy(CredentialPolicy {
            rules: vec![user_rule("h", &[Source::Client], None)],
            forward: ForwardAllowlist {
                git: vec!["h".into()],
                ..Default::default()
            },
            ..Default::default()
        });
        let (tx, events) = fake_client(Some("x"));
        assert!(s
            .resolve(&Scope::git("https", "h", "a/b"), Phase::Fetch, &tx)
            .await
            .is_none());
        assert_eq!(
            failed_chain(&events).await,
            ["client → disabled for token \"ci\" (allow_client = false)"]
        );
    }

    #[tokio::test]
    async fn phases_intersect_rule_and_provider_cap() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("s");
        std::fs::write(&secret, "agent-secret").unwrap();
        let providers = vec![
            provider(
                "fetch-only",
                "capped",
                &["*"],
                Some(vec![Phase::Fetch]),
                &secret,
            ),
            provider("any", "open", &["*"], None, &secret),
        ];
        let s = session("alice", providers, true, dir.path());
        let (tx, events) = fake_client(None);
        // Default phases: fetch only.
        let open = Scope::git("https", "open", "a/b");
        assert!(s.resolve(&open, Phase::Fetch, &tx).await.is_some());
        take_event(&events).await;
        assert!(s.resolve(&open, Phase::Build, &tx).await.is_none());
        assert!(failed_chain(&events).await[0].contains("phase build not allowed"));
        assert!(!s.build_phase_enabled());
        // A user rule opts the scope into build...
        s.set_policy(CredentialPolicy {
            rules: vec![
                user_rule(
                    "open",
                    &[Source::Agent],
                    Some(vec![Phase::Fetch, Phase::Build]),
                ),
                user_rule("capped", &[Source::Agent], Some(vec![Phase::Build])),
            ],
            ..Default::default()
        });
        assert!(s.build_phase_enabled());
        assert!(s.resolve(&open, Phase::Build, &tx).await.is_some());
        take_event(&events).await;
        // ...but the provider's cap still applies, and the rule's phases
        // exclude fetch for "capped".
        let capped = Scope::git("https", "capped", "a/b");
        assert!(s.resolve(&capped, Phase::Build, &tx).await.is_none());
        assert!(failed_chain(&events).await[0].contains("not enabled for phase build"));
        assert!(s.resolve(&capped, Phase::Fetch, &tx).await.is_none());
        assert!(failed_chain(&events).await[0].contains("phase fetch not allowed"));
    }

    #[test]
    fn explain_reports_each_source() {
        let dir = tempfile::tempdir().unwrap();
        let s = session(
            "ci",
            vec![provider("p", "h", &["bob"], None, &dir.path().join("x"))],
            false,
            dir.path(),
        );
        let steps = s.explain(&Scope::git("https", "h", "a/b"));
        assert!(
            steps[0].reason.starts_with("default (no matching rule)"),
            "{steps:?}"
        );
        let fetch: Vec<_> = steps
            .iter()
            .filter(|s| s.label.starts_with("fetch"))
            .collect();
        assert_eq!(fetch.len(), 2);
        assert_eq!(fetch[0].verdict, Verdict::NotAllowed);
        assert!(fetch[0].reason.contains("not allowed for token"));
        assert!(fetch[1].reason.contains("allow_client = false"));
        assert!(steps
            .iter()
            .any(|s| s.label == "build phase" && s.verdict == Verdict::NotAllowed));
        assert!(
            !dir.path().join("audit.log").exists(),
            "explain must not audit"
        );
    }
}
