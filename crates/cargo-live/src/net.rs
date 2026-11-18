//! Client side of build network access: the user's `[tunnel]` allowlist and
//! `[[network]]` rules, project hints, and serving the agent's tunnel
//! channels.
//!
//! The agent opens a `forwarded-tcpip` SSH channel for each connection its
//! build proxy routes through this machine. A channel is accepted only
//! while a build is running and only if the destination is in `[tunnel]`
//! (checked here for every channel, whatever the agent decided); this
//! machine then resolves and connects the destination itself, with the
//! system resolver, so VPN DNS (e.g. NetBird) applies.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use russh::client::{ChannelOpenHandle, Msg};
use russh::{Channel, ChannelOpenFailure};
use serde::Deserialize;
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};

use cargo_live_proto::cred::{ExplainStep, RuleOrigin, Source, Verdict};
use cargo_live_proto::net::{
    connect_with_timeout, first_match, parse_tunnel_hosts, relay, Destination, HostPattern,
    NetEvent, NetMatch, NetOutcome, NetPolicyRule, NetRule, NetworkPolicy, IDLE_TIMEOUT,
    MAX_TUNNELS, TUNNEL_CONNECT_TIMEOUT,
};

use crate::{error, Result};

/// `[tunnel]` in the user config, parsed when loaded.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(try_from = "RawTunnel")]
pub struct Tunnel {
    /// `host[:port]` globs (port 443 when absent) this machine connects to
    /// on behalf of the agent, as written (sent to the agent).
    pub hosts: Vec<String>,
    patterns: Vec<HostPattern>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTunnel {
    #[serde(default)]
    hosts: Vec<String>,
}

impl TryFrom<RawTunnel> for Tunnel {
    type Error = String;

    fn try_from(raw: RawTunnel) -> std::result::Result<Self, String> {
        Self::new(raw.hosts)
    }
}

impl Tunnel {
    pub fn new(hosts: Vec<String>) -> std::result::Result<Self, String> {
        let patterns = parse_tunnel_hosts(&hosts)?;
        Ok(Self { hosts, patterns })
    }

    pub fn patterns(&self) -> &[HostPattern] {
        &self.patterns
    }
}

/// `[[network]]` in `.cargo/live.toml`: hints with `match` and `via` only.
/// They rank below user rules, cannot set phases and cannot extend
/// `[tunnel]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectNetRule {
    #[serde(rename = "match")]
    pub matcher: NetMatch,
    pub via: Vec<Source>,
}

impl ProjectNetRule {
    fn to_rule(&self) -> NetRule {
        NetRule {
            matcher: self.matcher.clone(),
            via: self.via.clone(),
            phases: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.to_rule().validate().map_err(error)?;
        Ok(())
    }
}

/// User rules first, then project hints.
pub fn policy(tunnel: &Tunnel, user: &[NetRule], project: &[ProjectNetRule]) -> NetworkPolicy {
    let mut rules: Vec<NetPolicyRule> = user
        .iter()
        .enumerate()
        .map(|(i, rule)| NetPolicyRule {
            origin: RuleOrigin::User,
            index: i + 1,
            rule: rule.clone(),
        })
        .collect();
    rules.extend(project.iter().enumerate().map(|(i, hint)| NetPolicyRule {
        origin: RuleOrigin::Project,
        index: i + 1,
        rule: hint.to_rule(),
    }));
    NetworkPolicy {
        rules,
        tunnel: tunnel.hosts.clone(),
    }
}

/// The stderr line for a network decision.
pub fn event_line(event: &NetEvent) -> String {
    match &event.outcome {
        NetOutcome::Tunneled => format!(
            "cargo-live: tunneling {} through this machine ({} phase)",
            event.destination, event.phase
        ),
        NetOutcome::Failed { chain } => format!(
            "cargo-live: no route to {} ({} phase): {}",
            event.destination,
            event.phase,
            chain.join("; ")
        ),
    }
}

/// `cargo live net explain` output.
pub fn explain_text(
    dest: &Destination,
    agent: &str,
    steps: &[ExplainStep],
    tunnel: &Tunnel,
) -> String {
    let mut out = format!("network access to {dest} (agent {agent})\n");
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
    let local = match first_match(tunnel.patterns(), dest) {
        Some(entry) => format!(
            "in [tunnel] via {:?}: connects with the system resolver when the agent asks",
            entry.as_str()
        ),
        None => "not in [tunnel]: this machine refuses to tunnel it".into(),
    };
    out.push_str(&format!("  {:width$}  {local}\n", "this machine"));
    out
}

/// Decides on the agent's tunnel channels for one connection.
pub struct TunnelGate {
    hosts: Vec<HostPattern>,
    active: AtomicBool,
    /// Bumped when a build ends; open tunnels close.
    epoch: watch::Sender<u64>,
    slots: Arc<Semaphore>,
}

impl TunnelGate {
    pub fn new(hosts: Vec<HostPattern>) -> Arc<Self> {
        Arc::new(Self {
            hosts,
            active: AtomicBool::new(false),
            epoch: watch::Sender::new(0),
            slots: Arc::new(Semaphore::new(MAX_TUNNELS)),
        })
    }

    /// A build is running: tunnels may be opened.
    pub fn activate(&self) {
        self.active.store(true, Ordering::SeqCst);
    }

    /// The build ended: refuse new tunnels and close open ones.
    pub fn deactivate(&self) {
        self.active.store(false, Ordering::SeqCst);
        self.epoch.send_modify(|e| *e += 1);
    }

    /// Checks a channel request; on success returns the destination and a
    /// tunnel slot.
    pub fn admit(
        &self,
        host: &str,
        port: u32,
    ) -> std::result::Result<(Destination, OwnedSemaphorePermit), (ChannelOpenFailure, String)>
    {
        let prohibited = |m: String| (ChannelOpenFailure::AdministrativelyProhibited, m);
        let port = u16::try_from(port).map_err(|_| prohibited(format!("invalid port {port}")))?;
        let dest = Destination::new(host, port);
        dest.validate().map_err(prohibited)?;
        if !self.active.load(Ordering::SeqCst) {
            return Err(prohibited(format!("{dest}: no build is running")));
        }
        if first_match(&self.hosts, &dest).is_none() {
            return Err(prohibited(format!("{dest} is not in [tunnel]")));
        }
        let permit = self.slots.clone().try_acquire_owned().map_err(|_| {
            (
                ChannelOpenFailure::ResourceShortage,
                format!("{dest}: more than {MAX_TUNNELS} tunnels open"),
            )
        })?;
        Ok((dest, permit))
    }
}

/// Handles one `forwarded-tcpip` channel request from the agent. Never
/// blocks the SSH session: connecting happens in a task, which then
/// accepts or rejects the channel.
pub async fn handle_channel(
    gate: Option<&Arc<TunnelGate>>,
    channel: Channel<Msg>,
    host: &str,
    port: u32,
    reply: ChannelOpenHandle,
) {
    let Some(gate) = gate else {
        eprintln!("cargo-live: refused a tunnel channel from the agent (no build)");
        drop(reply);
        return;
    };
    match gate.admit(host, port) {
        Err((reason, message)) => {
            eprintln!("cargo-live: refused a tunnel requested by the agent: {message}");
            reply.reject(reason).await;
        }
        Ok((dest, permit)) => {
            tokio::spawn(serve(gate.clone(), dest, channel, reply, permit));
        }
    }
}

async fn serve(
    gate: Arc<TunnelGate>,
    dest: Destination,
    channel: Channel<Msg>,
    reply: ChannelOpenHandle,
    _permit: OwnedSemaphorePermit,
) {
    let mut epoch = gate.epoch.subscribe();
    let tcp = match connect_with_timeout(&dest, TUNNEL_CONNECT_TIMEOUT).await {
        Ok(tcp) => tcp,
        Err(e) => {
            eprintln!("cargo-live: tunnel to {dest}: {e}");
            reply.reject(ChannelOpenFailure::ConnectFailed).await;
            return;
        }
    };
    // The build may have ended while connecting.
    if !gate.active.load(Ordering::SeqCst) {
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        return;
    }
    reply.accept().await;
    let (up, down) = (AtomicU64::new(0), AtomicU64::new(0));
    tokio::select! {
        _ = relay(channel.into_stream(), tcp, IDLE_TIMEOUT, &up, &down) => {}
        _ = epoch.changed() => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cargo_live_proto::cred::Phase;

    #[test]
    fn gate_requires_an_active_build_the_allowlist_and_a_slot() {
        let gate = TunnelGate::new(
            parse_tunnel_hosts(&["gitlab.volka.com".into(), "*.internal:8443".into()]).unwrap(),
        );
        let err = gate.admit("gitlab.volka.com", 443).unwrap_err();
        assert_eq!(err.0, ChannelOpenFailure::AdministrativelyProhibited);
        assert!(err.1.contains("no build is running"), "{}", err.1);
        gate.activate();
        let (dest, permit) = gate.admit("GitLab.Volka.com", 443).unwrap();
        assert_eq!(dest, Destination::new("gitlab.volka.com", 443));
        drop(permit);
        assert!(gate
            .admit("gitlab.volka.com", 22)
            .unwrap_err()
            .1
            .contains("not in [tunnel]"));
        assert!(gate.admit("a.internal", 8443).is_ok());
        assert!(gate.admit("a.internal", 443).is_err());
        assert!(gate.admit("evil.example", 443).is_err());
        assert!(gate.admit("gitlab.volka.com", 70000).is_err());
        assert!(gate.admit("bad host", 443).is_err());
        let mut permits = Vec::new();
        for _ in 0..MAX_TUNNELS {
            permits.push(gate.admit("gitlab.volka.com", 443).unwrap().1);
        }
        let err = gate.admit("gitlab.volka.com", 443).unwrap_err();
        assert_eq!(err.0, ChannelOpenFailure::ResourceShortage);
        permits.clear();
        gate.deactivate();
        assert!(gate.admit("gitlab.volka.com", 443).is_err());
    }

    #[test]
    fn builds_policy_and_formats_lines() {
        let tunnel = Tunnel::new(vec!["gitlab.volka.com".into()]).unwrap();
        let user = vec![NetRule {
            matcher: NetMatch {
                host: "gitlab.volka.com".into(),
                port: None,
            },
            via: vec![Source::Client],
            phases: None,
        }];
        let project = vec![ProjectNetRule {
            matcher: NetMatch {
                host: "*".into(),
                port: None,
            },
            via: vec![Source::Agent, Source::Client],
        }];
        let p = policy(&tunnel, &user, &project);
        assert_eq!(p.rules[1].origin, RuleOrigin::Project);
        assert!(p.validate().is_ok());
        let dest = Destination::new("gitlab.volka.com", 443);
        assert_eq!(
            event_line(&NetEvent {
                destination: dest.clone(),
                phase: Phase::Fetch,
                outcome: NetOutcome::Tunneled
            }),
            "cargo-live: tunneling gitlab.volka.com:443 through this machine (fetch phase)"
        );
        assert_eq!(
            event_line(&NetEvent {
                destination: dest.clone(),
                phase: Phase::Fetch,
                outcome: NetOutcome::Failed {
                    chain: vec!["agent → x".into(), "client → not in [tunnel]".into()]
                }
            }),
            "cargo-live: no route to gitlab.volka.com:443 (fetch phase): agent → x; client → not in [tunnel]"
        );
        let text = explain_text(&dest, "a:1", &[], &tunnel);
        assert!(
            text.contains("in [tunnel] via \"gitlab.volka.com\""),
            "{text}"
        );
        let text = explain_text(&Destination::new("x", 443), "a:1", &[], &tunnel);
        assert!(text.contains("not in [tunnel]"), "{text}");
        assert!(Tunnel::new(vec!["h:0".into()]).is_err());
    }
}
