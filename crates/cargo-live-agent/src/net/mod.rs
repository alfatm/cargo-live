//! Network access of build steps.
//!
//! A build step may get a per-job HTTP proxy ([`proxy::Proxy`]): `cargo
//! fetch` when the session needs one ([`NetSession::proxy_needed`]: the
//! client sent `[tunnel]` hosts or `[[network]]` rules, or the agent's
//! `[network] direct` is not the default `["*"]`), the build step only when
//! a rule opts into it. Otherwise the step's environment is left alone. For
//! every destination the proxy asks the session's [`NetSession`], which
//! follows the client's `[[network]]` rules (or the defaults: `client` then
//! `agent` for destinations in the client's `[tunnel]`, `agent` for
//! everything else):
//!
//! - `agent`: connect directly from the agent, if the agent's
//!   `[network] direct` allows the destination (DNS lookup and connect
//!   within [`DIRECT_CONNECT_TIMEOUT`]);
//! - `client`: open a `forwarded-tcpip` SSH channel to the client, which
//!   connects itself, unless the token has `allow_tunnel = false`, the
//!   destination is not in the client's `[tunnel]`, or the phase is not in
//!   the rule's `phases`.
//!
//! The first source that connects wins; refusals and DNS/connect failures
//! fall through to the next one. This is policy for proxied traffic, not a
//! security boundary: build processes can open sockets themselves.

pub mod peer;
pub mod proxy;

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::server::{Handle, Msg};
use russh::{ChannelOpenFailure, ChannelStream};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};

use cargo_live_proto::cred::{ExplainStep, Phase, Source, Verdict};
use cargo_live_proto::net::{
    connect_with_timeout, first_match, Destination, HostPattern, NetEvent, NetOutcome, NetPlan,
    RoutingPolicy, DIRECT_CONNECT_TIMEOUT, MAX_TUNNELS, TUNNEL_CONNECT_TIMEOUT,
};

use crate::cred::audit;
use crate::cred::ToClient;

/// How long a connection waits for a free tunnel slot.
const TUNNEL_SLOT_WAIT: Duration = Duration::from_secs(30);

/// The upstream side of a proxied connection.
pub enum Upstream {
    Direct(TcpStream),
    /// A channel to the client; the permit is the session's tunnel slot.
    Tunnel(ChannelStream<Msg>, OwnedSemaphorePermit),
}

pub struct NetSession {
    token: String,
    workspace: Mutex<String>,
    /// Replaced as a whole when the client sends a new policy; connections
    /// take a reference, never a copy.
    policy: Mutex<Arc<RoutingPolicy>>,
    /// The agent's `[network] direct`.
    direct: Arc<Vec<HostPattern>>,
    allow_tunnel: bool,
    audit_log: PathBuf,
    /// Opens channels to the client; `None` in unit tests.
    handle: Option<Handle>,
    tunnels: Arc<Semaphore>,
    slot_wait: Duration,
    /// Destinations already reported to the client in this build, by
    /// phase and outcome (`true` = failure).
    announced: Mutex<HashSet<(Destination, Phase, bool)>>,
}

fn list<T: std::fmt::Display>(items: &[T]) -> String {
    let items: Vec<String> = items.iter().map(|i| format!("\"{i}\"")).collect();
    format!("[{}]", items.join(", "))
}

impl NetSession {
    pub fn new(
        token: String,
        direct: Arc<Vec<HostPattern>>,
        allow_tunnel: bool,
        audit_log: PathBuf,
        handle: Option<Handle>,
    ) -> Self {
        Self {
            token,
            workspace: Mutex::new(String::new()),
            policy: Mutex::new(Arc::default()),
            direct,
            allow_tunnel,
            audit_log,
            handle,
            tunnels: Arc::new(Semaphore::new(MAX_TUNNELS)),
            slot_wait: TUNNEL_SLOT_WAIT,
            announced: Mutex::new(HashSet::new()),
        }
    }

    pub fn set_workspace(&self, id: &str) {
        *self.workspace.lock().unwrap() = id.to_owned();
    }

    pub fn set_policy(&self, policy: RoutingPolicy) {
        *self.policy.lock().unwrap() = Arc::new(policy);
    }

    fn policy(&self) -> Arc<RoutingPolicy> {
        self.policy.lock().unwrap().clone()
    }

    /// Starts a new build: destinations are reported to the client again.
    pub fn begin_build(&self) {
        self.announced.lock().unwrap().clear();
    }

    /// Whether `cargo fetch` needs the proxy: the client sent `[tunnel]`
    /// hosts or `[[network]]` rules, or the agent restricts direct
    /// connections. Otherwise the fetch step's environment is left alone
    /// (an agent behind an egress proxy keeps using it).
    pub fn proxy_needed(&self) -> bool {
        !self.policy().is_empty() || !self.direct_allows_everything()
    }

    fn direct_allows_everything(&self) -> bool {
        self.direct.iter().any(HostPattern::matches_everything)
    }

    /// Whether the proxy also runs during the build step.
    pub fn build_phase_enabled(&self) -> bool {
        self.policy().build_phase_enabled()
    }

    /// The `[network] direct` entry that allows `dest`, if any.
    pub fn direct_allowing(&self, dest: &Destination) -> Option<&HostPattern> {
        first_match(&self.direct, dest)
    }

    /// Whether `client` may be used for `dest` in `phase`; returns the
    /// `[tunnel]` entry that allows it.
    fn client_gate<'p>(
        &self,
        policy: &'p RoutingPolicy,
        plan: &NetPlan<'_>,
        dest: &Destination,
        phase: Phase,
    ) -> Result<&'p HostPattern, String> {
        if !self.allow_tunnel {
            return Err(format!(
                "disabled for token {:?} (allow_tunnel = false)",
                self.token
            ));
        }
        let entry = policy
            .tunnel_allowing(dest)
            .ok_or("not in [tunnel] on the client")?;
        if !plan.phases.contains(&phase) {
            return Err(format!(
                "phase {phase} not allowed (phases = {}, {})",
                list(plan.phases),
                plan.describe()
            ));
        }
        Ok(entry)
    }

    /// Connects to `dest` following the plan. Every source refused or
    /// failed is appended to `chain` as it happens (so the caller still has
    /// it if this future is dropped midway); `None` when nothing connected.
    /// The caller writes the audit entry.
    pub async fn connect(
        &self,
        dest: &Destination,
        phase: Phase,
        origin_port: u16,
        events: &mpsc::Sender<ToClient>,
        chain: &mut Vec<String>,
    ) -> Option<(Source, Upstream)> {
        if let Err(e) = dest.validate() {
            chain.push(e);
            return None;
        }
        let policy = self.policy();
        let plan = policy.plan(dest);
        for source in plan.via {
            match source {
                Source::Agent => {
                    if self.direct_allowing(dest).is_none() {
                        chain.push("agent → denied by the agent's [network] direct".to_owned());
                        continue;
                    }
                    match connect_with_timeout(dest, DIRECT_CONNECT_TIMEOUT).await {
                        Ok(stream) => return Some((Source::Agent, Upstream::Direct(stream))),
                        Err(e) => chain.push(format!("agent → {e}")),
                    }
                }
                Source::Client => {
                    if let Err(reason) = self.client_gate(&policy, &plan, dest, phase) {
                        chain.push(format!("client → {reason}"));
                        continue;
                    }
                    match self.open_tunnel(dest, origin_port).await {
                        Ok(upstream) => {
                            self.announce(dest, phase, NetOutcome::Tunneled, events)
                                .await;
                            return Some((Source::Client, upstream));
                        }
                        Err(e) => chain.push(format!("client → {e}")),
                    }
                }
            }
        }
        self.announce(
            dest,
            phase,
            NetOutcome::Failed {
                chain: chain.clone(),
            },
            events,
        )
        .await;
        None
    }

    async fn announce(
        &self,
        dest: &Destination,
        phase: Phase,
        outcome: NetOutcome,
        events: &mpsc::Sender<ToClient>,
    ) {
        let key = (
            dest.clone(),
            phase,
            matches!(outcome, NetOutcome::Failed { .. }),
        );
        if !self.announced.lock().unwrap().insert(key) {
            return;
        }
        let _ = events
            .send(ToClient::Net(NetEvent {
                destination: dest.clone(),
                phase,
                outcome,
            }))
            .await;
    }

    /// Waits for a tunnel slot (at most [`MAX_TUNNELS`] per session).
    async fn tunnel_slot(&self) -> Result<OwnedSemaphorePermit, String> {
        match tokio::time::timeout(self.slot_wait, self.tunnels.clone().acquire_owned()).await {
            Ok(Ok(permit)) => Ok(permit),
            _ => Err(format!(
                "all {MAX_TUNNELS} tunnels of this session stayed busy for {}s",
                self.slot_wait.as_secs()
            )),
        }
    }

    async fn open_tunnel(&self, dest: &Destination, origin_port: u16) -> Result<Upstream, String> {
        let permit = self.tunnel_slot().await?;
        let handle = self
            .handle
            .as_ref()
            .ok_or("no SSH connection to the client")?;
        let wait = TUNNEL_CONNECT_TIMEOUT + Duration::from_secs(5);
        let opened = tokio::time::timeout(
            wait,
            handle.channel_open_forwarded_tcpip(
                dest.host.clone(),
                u32::from(dest.port),
                "127.0.0.1",
                u32::from(origin_port),
            ),
        )
        .await;
        match opened {
            Ok(Ok(channel)) => Ok(Upstream::Tunnel(channel.into_stream(), permit)),
            Ok(Err(russh::Error::ChannelOpenFailure(reason))) => Err(match reason {
                ChannelOpenFailure::ConnectFailed => {
                    "this machine could not connect (see its output)".to_owned()
                }
                ChannelOpenFailure::ResourceShortage => {
                    "this machine's tunnel limit was reached".to_owned()
                }
                ChannelOpenFailure::AdministrativelyProhibited => {
                    "refused by this machine (see its output)".to_owned()
                }
                other => format!("refused by this machine ({other:?})"),
            }),
            Ok(Err(e)) => Err(format!("cannot open a channel to the client: {e}")),
            Err(_) => Err(format!(
                "no answer from the client within {}s",
                wait.as_secs()
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn audit(
        &self,
        dest: &Destination,
        phase: Phase,
        via: &str,
        outcome: &str,
        bytes_up: u64,
        bytes_down: u64,
        chain: Vec<String>,
    ) {
        let workspace = self.workspace.lock().unwrap().clone();
        audit::record_net(
            &self.audit_log,
            &audit::NetEntry {
                ts: crate::log::now_rfc3339(),
                token: &self.token,
                workspace: &workspace,
                kind: "network",
                host: &dest.host,
                port: dest.port,
                phase: phase.to_string(),
                via,
                outcome,
                bytes_up,
                bytes_down,
                chain,
            },
        );
    }

    /// Dry run: what the proxy would do for `dest`, without connecting.
    pub fn explain(&self, dest: &Destination) -> Vec<ExplainStep> {
        let policy = self.policy();
        let plan = policy.plan(dest);
        let mut steps = vec![ExplainStep {
            label: "rule".into(),
            verdict: Verdict::Info,
            reason: format!(
                "{}: via = {}, phases = {}",
                plan.describe(),
                list(plan.via),
                list(plan.phases)
            ),
        }];
        if let Err(e) = dest.validate() {
            steps.push(ExplainStep {
                label: "destination".into(),
                verdict: Verdict::NotAllowed,
                reason: e,
            });
            return steps;
        }
        for source in plan.via {
            match source {
                Source::Agent => steps.push(match self.direct_allowing(dest) {
                    Some(entry) => ExplainStep {
                        label: "agent".into(),
                        verdict: Verdict::WouldTry,
                        reason: format!(
                            "would connect directly from the agent ([network] direct {:?}); \
                             the next source is tried only if the DNS lookup or connect fails \
                             within {}s",
                            entry.as_str(),
                            DIRECT_CONNECT_TIMEOUT.as_secs()
                        ),
                    },
                    None => ExplainStep {
                        label: "agent".into(),
                        verdict: Verdict::NotAllowed,
                        reason: "denied by the agent's [network] direct".into(),
                    },
                }),
                Source::Client => {
                    for phase in [Phase::Fetch, Phase::Build] {
                        let (verdict, reason) = match self.client_gate(&policy, &plan, dest, phase)
                        {
                            Ok(entry) => (
                                Verdict::WouldTry,
                                format!(
                                    "would tunnel through this machine ([tunnel] via {:?})",
                                    entry.as_str()
                                ),
                            ),
                            Err(reason) => (Verdict::NotAllowed, reason),
                        };
                        steps.push(ExplainStep {
                            label: format!("{phase} phase: client"),
                            verdict,
                            reason,
                        });
                    }
                }
            }
        }
        steps.push(ExplainStep {
            label: "fetch step".into(),
            verdict: Verdict::Info,
            reason: if self.proxy_needed() {
                "cargo fetch runs with the proxy".into()
            } else {
                "no proxy during cargo fetch (no [tunnel] hosts or [[network]] rules, and the \
                 agent allows every direct connection): git and Cargo connect as configured \
                 on the agent"
                    .into()
            },
        });
        steps.push(ExplainStep {
            label: "build step".into(),
            verdict: Verdict::Info,
            reason: if policy.build_phase_enabled() {
                "the proxy also runs during the build (a [[network]] rule has \"build\" in phases)"
                    .into()
            } else {
                "no proxy during the build (no [[network]] rule has \"build\" in phases)".into()
            },
        });
        steps
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use cargo_live_proto::cred::RuleOrigin;
    use cargo_live_proto::net::{parse_patterns, NetMatch, NetPolicyRule, NetRule, NetworkPolicy};

    pub fn direct(patterns: &[&str]) -> Arc<Vec<HostPattern>> {
        let patterns: Vec<String> = patterns.iter().map(|s| s.to_string()).collect();
        Arc::new(parse_patterns(&patterns, None, "direct").unwrap())
    }

    fn session(patterns: &[&str], allow_tunnel: bool, dir: &std::path::Path) -> NetSession {
        NetSession::new(
            "alice".into(),
            direct(patterns),
            allow_tunnel,
            dir.join("audit.log"),
            None,
        )
    }

    pub fn user_rule(host: &str, via: &[Source], phases: Option<Vec<Phase>>) -> NetPolicyRule {
        NetPolicyRule {
            origin: RuleOrigin::User,
            index: 1,
            rule: NetRule {
                matcher: NetMatch {
                    host: host.into(),
                    port: None,
                },
                via: via.to_vec(),
                phases,
            },
        }
    }

    pub fn set(s: &NetSession, rules: Vec<NetPolicyRule>, tunnel: Vec<String>) {
        s.set_policy(NetworkPolicy { rules, tunnel }.compile().unwrap());
    }

    fn events() -> (mpsc::Sender<ToClient>, mpsc::Receiver<ToClient>) {
        mpsc::channel(16)
    }

    async fn connect(
        s: &NetSession,
        dest: &Destination,
        phase: Phase,
        tx: &mpsc::Sender<ToClient>,
    ) -> Result<Source, Vec<String>> {
        let mut chain = Vec::new();
        match s.connect(dest, phase, 1, tx, &mut chain).await {
            Some((source, _)) => Ok(source),
            None => Err(chain),
        }
    }

    #[test]
    fn direct_egress_policy() {
        let dir = tempfile::tempdir().unwrap();
        let s = session(&["*.crates.io", "10.0.0.1:443"], true, dir.path());
        let d = |s: &str| Destination::parse(s, Some(443)).unwrap();
        let allowing = |dest: &str| s.direct_allowing(&d(dest)).map(HostPattern::to_string);
        assert_eq!(allowing("index.crates.io").as_deref(), Some("*.crates.io"));
        assert_eq!(
            allowing("index.crates.io:8080").as_deref(),
            Some("*.crates.io")
        );
        assert_eq!(allowing("10.0.0.1").as_deref(), Some("10.0.0.1:443"));
        assert!(allowing("10.0.0.1:80").is_none());
        assert!(allowing("gitlab.volka.com").is_none());
        assert!(session(&[], true, dir.path())
            .direct_allowing(&d("x"))
            .is_none());
    }

    #[test]
    fn proxy_only_when_needed() {
        let dir = tempfile::tempdir().unwrap();
        // Default agent, no client network config: no proxy.
        let s = session(&["*"], true, dir.path());
        assert!(!s.proxy_needed());
        // A [tunnel] host or any rule needs it.
        set(&s, vec![], vec!["gitlab.example.com".into()]);
        assert!(s.proxy_needed());
        set(&s, vec![user_rule("x", &[Source::Agent], None)], vec![]);
        assert!(s.proxy_needed());
        set(&s, vec![], vec![]);
        assert!(!s.proxy_needed());
        // So does an agent that restricts direct connections.
        assert!(session(&["*.crates.io"], true, dir.path()).proxy_needed());
        assert!(session(&[], true, dir.path()).proxy_needed());
        assert!(session(&["*:443"], true, dir.path()).proxy_needed());
    }

    #[tokio::test]
    async fn denied_direct_falls_through_and_reports_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let dest = Destination::new("127.0.0.1", port);
        let (tx, mut rx) = events();

        // Allowed: direct connection.
        let s = session(&["127.0.0.1"], true, dir.path());
        assert_eq!(
            connect(&s, &dest, Phase::Fetch, &tx).await,
            Ok(Source::Agent)
        );

        // Denied direct, then the client: not in [tunnel], no handle.
        let s = session(&[], true, dir.path());
        set(
            &s,
            vec![user_rule(
                "127.0.0.1",
                &[Source::Agent, Source::Client],
                None,
            )],
            vec![],
        );
        let chain = connect(&s, &dest, Phase::Fetch, &tx).await.unwrap_err();
        assert_eq!(
            chain,
            [
                "agent → denied by the agent's [network] direct",
                "client → not in [tunnel] on the client"
            ]
        );
        let Some(ToClient::Net(event)) = rx.recv().await else {
            panic!("no event")
        };
        assert_eq!(event.outcome, NetOutcome::Failed { chain });
        // Reported once per destination and phase.
        assert!(connect(&s, &dest, Phase::Fetch, &tx).await.is_err());
        assert!(rx.try_recv().is_err());

        // In [tunnel]: the client source is tried (and fails without SSH).
        set(
            &s,
            vec![user_rule("127.0.0.1", &[Source::Client], None)],
            vec![format!("127.0.0.1:{port}")],
        );
        let chain = connect(&s, &dest, Phase::Fetch, &tx).await.unwrap_err();
        assert_eq!(chain, ["client → no SSH connection to the client"]);
        // The build phase is not in the rule's phases.
        let chain = connect(&s, &dest, Phase::Build, &tx).await.unwrap_err();
        assert!(
            chain[0].starts_with("client → phase build not allowed"),
            "{chain:?}"
        );

        // allow_tunnel = false; the default for a [tunnel] host falls back
        // to a direct connection, which is denied too.
        let s = session(&[], false, dir.path());
        set(&s, vec![], vec![format!("127.0.0.1:{port}")]);
        let chain = connect(&s, &dest, Phase::Fetch, &tx).await.unwrap_err();
        assert_eq!(
            chain,
            [
                "client → disabled for token \"alice\" (allow_tunnel = false)",
                "agent → denied by the agent's [network] direct"
            ]
        );
        // connect() itself writes no audit entries (the proxy does).
        assert!(!dir.path().join("audit.log").exists());
    }

    #[tokio::test]
    async fn tunnel_hosts_fall_back_to_direct_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let dest = Destination::new("127.0.0.1", port);
        let (tx, _rx) = events();
        // allow_tunnel = false, the host in [tunnel], direct allowed: the
        // client is refused, then the agent connects.
        let s = session(&["127.0.0.1"], false, dir.path());
        set(&s, vec![], vec![format!("127.0.0.1:{port}")]);
        let mut chain = Vec::new();
        let (source, _) = s
            .connect(&dest, Phase::Fetch, 1, &tx, &mut chain)
            .await
            .unwrap();
        assert_eq!(source, Source::Agent);
        assert_eq!(
            chain,
            ["client → disabled for token \"alice\" (allow_tunnel = false)"]
        );
        // The build phase is not in the default phases: direct again.
        let s = session(&["127.0.0.1"], true, dir.path());
        set(&s, vec![], vec![format!("127.0.0.1:{port}")]);
        let mut chain = Vec::new();
        let (source, _) = s
            .connect(&dest, Phase::Build, 1, &tx, &mut chain)
            .await
            .unwrap();
        assert_eq!(source, Source::Agent);
        assert!(chain[0].starts_with("client → phase build not allowed"));
    }

    #[tokio::test]
    async fn direct_connect_failure_falls_back() {
        let dir = tempfile::tempdir().unwrap();
        // A port nobody listens on.
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let s = session(&["*"], true, dir.path());
        set(
            &s,
            vec![user_rule(
                "127.0.0.1",
                &[Source::Agent, Source::Client],
                None,
            )],
            vec![format!("127.0.0.1:{port}")],
        );
        let (tx, _rx) = events();
        let chain = connect(&s, &Destination::new("127.0.0.1", port), Phase::Fetch, &tx)
            .await
            .unwrap_err();
        assert!(chain[0].starts_with("agent → cannot connect"), "{chain:?}");
        assert_eq!(chain[1], "client → no SSH connection to the client");
        let chain = connect(
            &s,
            &Destination::new("does-not-exist.invalid", 443),
            Phase::Fetch,
            &tx,
        )
        .await
        .unwrap_err();
        assert!(chain[0].starts_with("agent → cannot resolve"), "{chain:?}");
    }

    #[tokio::test]
    async fn tunnel_slots_are_limited() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = session(&[], true, dir.path());
        s.slot_wait = Duration::from_millis(50);
        let mut permits = Vec::new();
        for _ in 0..MAX_TUNNELS {
            permits.push(s.tunnel_slot().await.unwrap());
        }
        let err = s.tunnel_slot().await.unwrap_err();
        assert!(err.contains("32 tunnels"), "{err}");
        permits.pop();
        assert!(s.tunnel_slot().await.is_ok());
    }

    #[test]
    fn explain_lists_sources_and_phases() {
        let dir = tempfile::tempdir().unwrap();
        let s = session(&["*.crates.io"], true, dir.path());
        set(
            &s,
            vec![user_rule(
                "gitlab.volka.com",
                &[Source::Agent, Source::Client],
                None,
            )],
            vec!["gitlab.volka.com".into(), "intra.example".into()],
        );
        let steps = s.explain(&Destination::new("gitlab.volka.com", 443));
        assert!(steps[0]
            .reason
            .starts_with("user rule #1 (match host=gitlab.volka.com)"));
        assert_eq!(steps[1].label, "agent");
        assert_eq!(steps[1].verdict, Verdict::NotAllowed);
        assert_eq!(steps[2].label, "fetch phase: client");
        assert_eq!(steps[2].verdict, Verdict::WouldTry);
        assert_eq!(steps[3].verdict, Verdict::NotAllowed);
        assert!(steps[3].reason.contains("phase build not allowed"));
        assert_eq!(steps[4].reason, "cargo fetch runs with the proxy");
        assert!(steps[5].reason.starts_with("no proxy during the build"));
        let steps = s.explain(&Destination::new("index.crates.io", 443));
        assert!(steps[0].reason.contains("not in [tunnel]"));
        assert_eq!(steps[1].verdict, Verdict::WouldTry);
        // The default for a [tunnel] host: client, then agent.
        let steps = s.explain(&Destination::new("intra.example", 443));
        assert!(
            steps[0]
                .reason
                .contains("in [tunnel] via \"intra.example\"): via = [\"client\", \"agent\"]"),
            "{}",
            steps[0].reason
        );
        assert_eq!(steps[1].label, "fetch phase: client");
        assert_eq!(steps[3].label, "agent");
        assert!(
            !dir.path().join("audit.log").exists(),
            "explain must not audit"
        );
        let s = session(&["*"], true, dir.path());
        let steps = s.explain(&Destination::new("index.crates.io", 443));
        assert!(steps.iter().any(
            |s| s.label == "fetch step" && s.reason.starts_with("no proxy during cargo fetch")
        ));
    }
}
