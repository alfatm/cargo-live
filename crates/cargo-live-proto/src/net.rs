//! Network access of build steps: destinations, `host[:port]` patterns,
//! the client's `[tunnel]` allowlist and `[[network]]` rules, and the
//! connect and byte relay helpers both ends use for tunnels.
//!
//! During `cargo fetch` the agent runs a per-job HTTP proxy (when the
//! session has network rules, `[tunnel]` hosts, or the agent restricts
//! direct connections). For each destination it follows the best matching
//! rule's `via` list: `agent` connects directly from the agent, `client`
//! opens an SSH channel to the client, which connects itself (with its own
//! VPN and DNS). Fallback to the next source happens only when a DNS
//! lookup or TCP connect fails (or a source is not allowed); an HTTP error
//! behind TLS cannot be detected.
//!
//! Patterns are parsed once ([`NetworkPolicy::compile`],
//! [`parse_patterns`]); invalid entries are rejected there, never skipped
//! when matching.

use std::fmt;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::cred::{glob_match, literal_len, Phase, RuleOrigin, Source, DEFAULT_PHASES};

/// Port of `[tunnel]` entries without one.
pub const DEFAULT_TUNNEL_PORT: u16 = 443;
/// Concurrent client tunnels per session (enforced by both ends).
pub const MAX_TUNNELS: usize = 32;
/// How long the agent tries a direct connection before falling back.
pub const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the client tries to connect a tunnel's destination.
pub const TUNNEL_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Proxied connections without traffic in either direction are closed.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Sources for a destination in `[tunnel]` without a matching rule: the
/// client first, then a direct connection.
pub const DEFAULT_TUNNEL_VIA: &[Source] = &[Source::Client, Source::Agent];
/// Sources for every other destination without a matching rule.
pub const DEFAULT_VIA: &[Source] = &[Source::Agent];

/// A destination of a proxied connection: lowercase host (IPv6 literals
/// without brackets) and port.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Destination {
    pub host: String,
    pub port: u16,
}

/// Lowercases, strips IPv6 brackets and a trailing dot.
pub fn normalize_host(host: &str) -> String {
    let host = host.trim();
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// Splits `host`, `host:port`, `[v6]` or `[v6]:port` (an unbracketed
/// IPv6 literal is all host). The port part is returned unparsed.
fn split_host_port(s: &str) -> Result<(&str, Option<&str>), String> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| format!("unterminated '[' in {s:?}"))?;
        return match after {
            "" => Ok((host, None)),
            p => Ok((
                host,
                Some(
                    p.strip_prefix(':')
                        .ok_or_else(|| format!("expected ':' after ']' in {s:?}"))?,
                ),
            )),
        };
    }
    match s.matches(':').count() {
        1 => {
            let (h, p) = s.split_once(':').expect("one colon");
            Ok((h, Some(p)))
        }
        _ => Ok((s, None)),
    }
}

fn parse_port(p: &str) -> Result<u16, String> {
    p.parse::<u16>()
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| format!("invalid port {p:?}"))
}

impl Destination {
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            host: normalize_host(host),
            port,
        }
    }

    /// Parses `host[:port]`; `default_port` applies when there is none.
    pub fn parse(s: &str, default_port: Option<u16>) -> Result<Self, String> {
        if s.chars().any(|c| c.is_control()) {
            return Err(format!("invalid destination {s:?}"));
        }
        let (host, port) = split_host_port(s)?;
        let port = match (port, default_port) {
            (Some(p), _) => parse_port(p)?,
            (None, Some(d)) => d,
            (None, None) => return Err(format!("{s:?} has no port")),
        };
        let dest = Self::new(host, port);
        dest.validate()?;
        Ok(dest)
    }

    /// Hosts are DNS names or IP literals: no empty, oversized or odd
    /// values (they end up in log lines and SSH channel requests).
    pub fn validate(&self) -> Result<(), String> {
        let ok = !self.host.is_empty()
            && self.host.len() <= 253
            && !self.host.starts_with(['-', '.'])
            && self
                .host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'));
        if !ok {
            return Err(format!("invalid host name {:?}", self.host));
        }
        if self.port == 0 {
            return Err("port 0 is not a destination".into());
        }
        Ok(())
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// DNS lookup and TCP connect to `dest` within `timeout`, trying every
/// address in turn. Errors are messages for the user.
pub async fn connect_with_timeout(
    dest: &Destination,
    timeout: Duration,
) -> Result<TcpStream, String> {
    let attempt = async {
        let addrs: Vec<_> = tokio::net::lookup_host((dest.host.as_str(), dest.port))
            .await
            .map_err(|e| format!("cannot resolve {}: {e}", dest.host))?
            .collect();
        let mut last = format!("{} has no addresses", dest.host);
        for addr in addrs {
            match TcpStream::connect(addr).await {
                Ok(stream) => {
                    let _ = stream.set_nodelay(true);
                    return Ok(stream);
                }
                Err(e) => last = format!("cannot connect to {addr}: {e}"),
            }
        }
        Err(last)
    };
    tokio::time::timeout(timeout, attempt)
        .await
        .unwrap_or_else(|_| Err(format!("no connection within {}s", timeout.as_secs())))
}

/// A parsed `host[:port]` glob. `*` in the host matches any run of
/// characters; the port is a number or `*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPattern {
    /// As written, for messages.
    raw: String,
    /// Normalized: lowercase, IPv6 brackets stripped.
    host: String,
    /// `None` matches every port.
    port: Option<u16>,
}

impl HostPattern {
    /// `default_port` applies to patterns without a port (`None`: any).
    pub fn parse(s: &str, default_port: Option<u16>) -> Result<Self, String> {
        let (host, port) = split_host_port(s)?;
        let port = match port {
            Some("*") => None,
            Some(p) => Some(parse_port(p).map_err(|e| format!("{e} in {s:?}"))?),
            None => default_port,
        };
        Self::build(s, host, port)
    }

    /// A host glob that must not contain a port (`match.host`, whose port
    /// is a separate field). `[v6]` is accepted and matched without its
    /// brackets; `host:port` and `[v6]:port` are rejected.
    pub fn host_only(s: &str, port: Option<u16>) -> Result<Self, String> {
        let (host, port_part) = split_host_port(s)?;
        if port_part.is_some() {
            return Err(format!(
                "match.host {s:?} must not contain a port; use port = ... \
                 (and [brackets] without a port for IPv6)"
            ));
        }
        if port == Some(0) {
            return Err("match.port must not be 0".into());
        }
        Self::build(s, host, port)
    }

    fn build(raw: &str, host: &str, port: Option<u16>) -> Result<Self, String> {
        let host = normalize_host(host);
        if host.is_empty() || host.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(format!("invalid host pattern {raw:?}"));
        }
        Ok(Self {
            raw: raw.trim().to_owned(),
            host,
            port,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub fn matches(&self, dest: &Destination) -> bool {
        self.port.is_none_or(|p| p == dest.port) && glob_match(&self.host, &dest.host)
    }

    /// Whether this pattern matches every destination (`*` on any port).
    pub fn matches_everything(&self) -> bool {
        self.port.is_none() && self.host.chars().all(|c| c == '*')
    }

    /// Higher is more specific: a port given, then more literal host
    /// characters.
    pub fn specificity(&self) -> (usize, usize) {
        (
            1 + usize::from(self.port.is_some()),
            literal_len(&self.host),
        )
    }
}

impl fmt::Display for HostPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

/// Parses a list of `host[:port]` globs; the error names `what` (e.g.
/// `[tunnel] hosts`) and the bad entry.
pub fn parse_patterns(
    entries: &[String],
    default_port: Option<u16>,
    what: &str,
) -> Result<Vec<HostPattern>, String> {
    entries
        .iter()
        .map(|e| HostPattern::parse(e, default_port).map_err(|err| format!("{what}: {err}")))
        .collect()
}

/// `[tunnel] hosts`: port 443 when absent.
pub fn parse_tunnel_hosts(entries: &[String]) -> Result<Vec<HostPattern>, String> {
    parse_patterns(entries, Some(DEFAULT_TUNNEL_PORT), "[tunnel] hosts")
}

/// The first pattern that matches `dest`.
pub fn first_match<'a>(patterns: &'a [HostPattern], dest: &Destination) -> Option<&'a HostPattern> {
    patterns.iter().find(|p| p.matches(dest))
}

/// `match = { host = "...", port = 443 }` of a `[[network]]` rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetMatch {
    /// Host glob, without a port.
    pub host: String,
    /// Optional port; any port when absent.
    #[serde(default)]
    pub port: Option<u16>,
}

impl NetMatch {
    /// The parsed pattern (host glob and port).
    pub fn pattern(&self) -> Result<HostPattern, String> {
        HostPattern::host_only(&self.host, self.port)
    }

    pub fn validate(&self) -> Result<(), String> {
        self.pattern().map(drop)
    }
}

impl fmt::Display for NetMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "host={}", self.host)?;
        if let Some(port) = self.port {
            write!(f, " port={port}")?;
        }
        Ok(())
    }
}

/// A `[[network]]` rule: which sources to try, in order, for matching
/// destinations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetRule {
    #[serde(rename = "match")]
    pub matcher: NetMatch,
    pub via: Vec<Source>,
    /// Phases in which `client` may be used. Default: fetch only.
    #[serde(default)]
    pub phases: Option<Vec<Phase>>,
}

impl NetRule {
    pub fn validate(&self) -> Result<(), String> {
        self.matcher.validate()?;
        if self.via.is_empty() {
            return Err("a [[network]] rule needs at least one entry in via".into());
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetPolicyRule {
    pub origin: RuleOrigin,
    /// 1-based position within its origin, for messages.
    pub index: usize,
    pub rule: NetRule,
}

/// Sent by the client after its credential policy. Plain data; compile it
/// into a [`RoutingPolicy`] to use it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPolicy {
    /// User rules first, then project hints, each in file order.
    pub rules: Vec<NetPolicyRule>,
    /// The client's `[tunnel] hosts`: `host[:port]` globs (port 443 when
    /// absent) it is willing to connect to for the agent.
    pub tunnel: Vec<String>,
}

impl NetworkPolicy {
    /// Parses every pattern; the first invalid entry is an error.
    pub fn compile(&self) -> Result<RoutingPolicy, String> {
        let tunnel = parse_tunnel_hosts(&self.tunnel)?;
        let mut routes = Vec::with_capacity(self.rules.len());
        for r in &self.rules {
            r.rule.validate()?;
            if r.origin == RuleOrigin::Project && r.rule.phases.is_some() {
                return Err("project [[network]] hints cannot set phases".into());
            }
            let mut via = Vec::new();
            for s in &r.rule.via {
                if !via.contains(s) {
                    via.push(*s);
                }
            }
            routes.push(Route {
                origin: r.origin,
                index: r.index,
                pattern: r.rule.matcher.pattern()?,
                matcher: r.rule.matcher.clone(),
                via,
                phases: r.rule.phases().to_vec(),
            });
        }
        Ok(RoutingPolicy { routes, tunnel })
    }

    pub fn validate(&self) -> Result<(), String> {
        self.compile().map(drop)
    }
}

/// A compiled `[[network]]` rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub origin: RuleOrigin,
    pub index: usize,
    /// As configured, for messages.
    pub matcher: NetMatch,
    pattern: HostPattern,
    /// Deduplicated, in order.
    pub via: Vec<Source>,
    pub phases: Vec<Phase>,
}

/// A [`NetworkPolicy`] with every pattern parsed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoutingPolicy {
    routes: Vec<Route>,
    tunnel: Vec<HostPattern>,
}

/// What to do for one destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetPlan<'a> {
    pub rule: Option<&'a Route>,
    pub via: &'a [Source],
    pub phases: &'a [Phase],
    /// For the default plan: the `[tunnel]` entry, if any.
    pub tunnel_entry: Option<&'a HostPattern>,
}

impl NetPlan<'_> {
    pub fn describe(&self) -> String {
        match (self.rule, self.tunnel_entry) {
            (Some(r), _) => format!("{} rule #{} (match {})", r.origin, r.index, r.matcher),
            (None, Some(entry)) => format!(
                "default (no matching rule; in [tunnel] via {:?})",
                entry.as_str()
            ),
            (None, None) => "default (no matching rule; not in [tunnel])".into(),
        }
    }
}

impl RoutingPolicy {
    /// No rules and no `[tunnel]` hosts.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty() && self.tunnel.is_empty()
    }

    pub fn rule_count(&self) -> usize {
        self.routes.len()
    }

    pub fn tunnel_count(&self) -> usize {
        self.tunnel.len()
    }

    pub fn tunnel_allowing(&self, dest: &Destination) -> Option<&HostPattern> {
        first_match(&self.tunnel, dest)
    }

    /// User rules before project hints; within an origin the most specific
    /// match; ties go to the first.
    pub fn best_rule(&self, dest: &Destination) -> Option<&Route> {
        for origin in [RuleOrigin::User, RuleOrigin::Project] {
            let mut best: Option<&Route> = None;
            for route in self
                .routes
                .iter()
                .filter(|r| r.origin == origin && r.pattern.matches(dest))
            {
                if best.is_none_or(|b| route.pattern.specificity() > b.pattern.specificity()) {
                    best = Some(route);
                }
            }
            if best.is_some() {
                return best;
            }
        }
        None
    }

    /// The rule's sources, or the defaults: [`DEFAULT_TUNNEL_VIA`] (client,
    /// then agent) for destinations in `[tunnel]`, [`DEFAULT_VIA`] (agent)
    /// for everything else.
    pub fn plan(&self, dest: &Destination) -> NetPlan<'_> {
        match self.best_rule(dest) {
            Some(route) => NetPlan {
                rule: Some(route),
                via: &route.via,
                phases: &route.phases,
                tunnel_entry: None,
            },
            None => {
                let entry = self.tunnel_allowing(dest);
                NetPlan {
                    rule: None,
                    via: if entry.is_some() {
                        DEFAULT_TUNNEL_VIA
                    } else {
                        DEFAULT_VIA
                    },
                    phases: DEFAULT_PHASES,
                    tunnel_entry: entry,
                }
            }
        }
    }

    /// Whether the proxy also runs during the build step.
    pub fn build_phase_enabled(&self) -> bool {
        self.routes.iter().any(|r| r.phases.contains(&Phase::Build))
    }
}

/// A network decision, reported to the client for its stderr line. Sent
/// once per destination and phase within a build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetEvent {
    pub destination: Destination,
    pub phase: Phase,
    pub outcome: NetOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetOutcome {
    /// The first connection through a client tunnel succeeded.
    Tunneled,
    /// No source could connect; every source tried, as
    /// `"<source> → <reason>"`.
    Failed { chain: Vec<String> },
}

/// How a relay ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayEnd {
    /// Both sides closed.
    Closed,
    /// No traffic for the idle timeout.
    Idle,
    /// An I/O error on either side.
    Error(String),
}

impl RelayEnd {
    pub fn as_str(&self) -> &str {
        match self {
            RelayEnd::Closed => "closed",
            RelayEnd::Idle => "idle-timeout",
            RelayEnd::Error(_) => "error",
        }
    }
}

/// Copies bytes both ways between `a` and `b` until both directions are
/// closed, an error occurs, or nothing moved for `idle`. An EOF in one
/// direction is passed on as a write shutdown. `up` counts bytes from `a`
/// to `b`, `down` from `b` to `a`; they stay valid if the future is
/// dropped midway.
pub async fn relay<A, B>(a: A, b: B, idle: Duration, up: &AtomicU64, down: &AtomicU64) -> RelayEnd
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let start = Instant::now();
    let last = AtomicU64::new(0);
    let touch = || last.store(start.elapsed().as_millis() as u64, Ordering::Relaxed);
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);

    async fn pump<R, W>(
        r: &mut R,
        w: &mut W,
        count: &AtomicU64,
        touch: &impl Fn(),
    ) -> io::Result<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = r.read(&mut buf).await?;
            touch();
            if n == 0 {
                // Half-close: the other direction may still be busy.
                let _ = w.shutdown().await;
                return Ok(());
            }
            w.write_all(&buf[..n]).await?;
            w.flush().await?;
            count.fetch_add(n as u64, Ordering::Relaxed);
        }
    }

    let both = async {
        tokio::try_join!(
            pump(&mut ar, &mut bw, up, &touch),
            pump(&mut br, &mut aw, down, &touch)
        )
    };
    let watchdog = async {
        let step = idle
            .min(Duration::from_secs(5))
            .max(Duration::from_millis(10));
        loop {
            tokio::time::sleep(step).await;
            let quiet =
                (start.elapsed().as_millis() as u64).saturating_sub(last.load(Ordering::Relaxed));
            if quiet >= idle.as_millis() as u64 {
                return;
            }
        }
    };
    tokio::select! {
        result = both => match result {
            Ok(_) => RelayEnd::Closed,
            Err(e) => RelayEnd::Error(e.to_string()),
        },
        () = watchdog => RelayEnd::Idle,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dest(s: &str) -> Destination {
        Destination::parse(s, Some(443)).unwrap()
    }

    fn rule(
        origin: RuleOrigin,
        index: usize,
        host: &str,
        port: Option<u16>,
        via: &[Source],
    ) -> NetPolicyRule {
        NetPolicyRule {
            origin,
            index,
            rule: NetRule {
                matcher: NetMatch {
                    host: host.into(),
                    port,
                },
                via: via.to_vec(),
                phases: None,
            },
        }
    }

    #[test]
    fn destinations_parse_and_normalize() {
        assert_eq!(
            dest("GitLab.Volka.com."),
            Destination::new("gitlab.volka.com", 443)
        );
        assert_eq!(dest("h:8080").port, 8080);
        assert_eq!(dest("[::1]:22"), Destination::new("::1", 22));
        assert_eq!(dest("[::1]").port, 443);
        assert_eq!(dest("::1").host, "::1");
        assert_eq!(dest("[::1]:22").to_string(), "[::1]:22");
        assert_eq!(dest("h:1").to_string(), "h:1");
        assert!(Destination::parse("h", None).is_err());
        for bad in [
            "", "h:0", "h:x", "h:70000", "a b", "-x", "[::1", "[::1]x", "a/b:1", "a\n:1",
        ] {
            assert!(Destination::parse(bad, Some(443)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn host_patterns_with_ports() {
        let p = |s: &str| HostPattern::parse(s, Some(443)).unwrap();
        assert!(p("gitlab.volka.com").matches(&dest("gitlab.volka.com:443")));
        assert!(!p("gitlab.volka.com").matches(&dest("gitlab.volka.com:22")));
        assert!(p("gitlab.volka.com:22").matches(&dest("gitlab.volka.com:22")));
        assert!(p("*.volka.com:*").matches(&dest("crates.volka.com:8443")));
        assert!(!p("*.volka.com").matches(&dest("volka.com:443")));
        assert!(p("[::1]:8080").matches(&dest("[::1]:8080")));
        assert!(p("GITLAB.volka.com").matches(&dest("gitlab.volka.com")));
        assert_eq!(p(" GITLAB.volka.com ").as_str(), "GITLAB.volka.com");
        // Without a default port, a pattern without one matches any port.
        let any = HostPattern::parse("127.0.0.1", None).unwrap();
        assert!(any.matches(&dest("127.0.0.1:1234")));
        assert!(HostPattern::parse("*", None).unwrap().matches(&dest("x:1")));
        assert!(HostPattern::parse("*", None).unwrap().matches_everything());
        assert!(!HostPattern::parse("*:443", None)
            .unwrap()
            .matches_everything());
        assert!(!HostPattern::parse("*.x", None)
            .unwrap()
            .matches_everything());
        for bad in ["", "h:0", "h:x", "a b", "[::1"] {
            assert!(HostPattern::parse(bad, Some(443)).is_err(), "{bad:?}");
        }
        let list = parse_tunnel_hosts(&["other:443".to_owned(), "*.volka.com".to_owned()]).unwrap();
        assert_eq!(
            first_match(&list, &dest("crates.volka.com")).map(HostPattern::as_str),
            Some("*.volka.com")
        );
        assert_eq!(first_match(&list, &dest("crates.volka.com:80")), None);
        let err = parse_tunnel_hosts(&["ok".to_owned(), "h:0".to_owned()]).unwrap_err();
        assert!(err.starts_with("[tunnel] hosts: invalid port"), "{err}");
    }

    #[test]
    fn bracketed_ipv6_in_tunnel_direct_and_match() {
        let v6 = dest("[fd00::5]:8443");
        assert_eq!(v6.host, "fd00::5");
        // [tunnel] (default port 443) and [network] direct (any port).
        let tunnel = parse_tunnel_hosts(&["[fd00::5]:8443".into(), "[fd00::6]".into()]).unwrap();
        assert!(first_match(&tunnel, &v6).is_some());
        assert!(first_match(&tunnel, &dest("[fd00::5]")).is_none());
        assert!(first_match(&tunnel, &dest("[fd00::6]:443")).is_some());
        assert!(first_match(&tunnel, &dest("[fd00::6]:8443")).is_none());
        let direct = parse_patterns(&["[fd00::5]".into(), "fd00::7".into()], None, "d").unwrap();
        assert!(first_match(&direct, &v6).is_some());
        assert!(first_match(&direct, &dest("[fd00::7]:1")).is_some());
        assert!(parse_patterns(&["[fd00::5]:*".into()], None, "d").unwrap()[0].matches(&v6));

        // match.host: a host only; brackets are stripped for matching.
        let m = |host: &str, port| NetMatch {
            host: host.into(),
            port,
        };
        assert!(m("[fd00::5]", None).pattern().unwrap().matches(&v6));
        assert!(m("[fd00::5]", Some(8443)).pattern().unwrap().matches(&v6));
        assert!(!m("[fd00::5]", Some(443)).pattern().unwrap().matches(&v6));
        assert!(m("fd00::5", None).pattern().unwrap().matches(&v6));
        for bad in ["[fd00::5]:8443", "h:443", "h:", "[fd00::5]x", "[fd00::5"] {
            assert!(m(bad, None).validate().is_err(), "{bad:?}");
        }
        let err = m("[fd00::5]:8443", None).validate().unwrap_err();
        assert!(err.contains("must not contain a port"), "{err}");
    }

    #[test]
    fn rules_defaults_and_precedence() {
        let policy = NetworkPolicy {
            rules: vec![
                rule(
                    RuleOrigin::User,
                    1,
                    "*.volka.com",
                    None,
                    &[Source::Agent, Source::Client],
                ),
                rule(
                    RuleOrigin::User,
                    2,
                    "gitlab.volka.com",
                    None,
                    &[Source::Client],
                ),
                rule(
                    RuleOrigin::User,
                    3,
                    "gitlab.volka.com",
                    Some(22),
                    &[Source::Agent],
                ),
                rule(
                    RuleOrigin::Project,
                    1,
                    "crates.volka.com",
                    Some(443),
                    &[Source::Client],
                ),
                rule(
                    RuleOrigin::Project,
                    2,
                    "example.org",
                    None,
                    &[Source::Client, Source::Client],
                ),
            ],
            tunnel: vec!["gitlab.volka.com".into(), "intra.example:8443".into()],
        };
        let policy = policy.compile().unwrap();
        assert!(!policy.is_empty());
        // Most specific user rule: literal host beats glob, port beats none.
        let p = policy.plan(&dest("gitlab.volka.com"));
        assert_eq!(p.rule.unwrap().index, 2);
        assert_eq!(p.via, [Source::Client]);
        assert_eq!(p.phases, [Phase::Fetch]);
        assert_eq!(
            policy
                .plan(&dest("gitlab.volka.com:22"))
                .rule
                .unwrap()
                .index,
            3
        );
        // A user rule wins over a more specific project hint.
        let p = policy.plan(&dest("crates.volka.com"));
        assert_eq!(
            (p.rule.unwrap().origin, p.via),
            (RuleOrigin::User, &[Source::Agent, Source::Client][..])
        );
        // Project hints apply when no user rule matches; via is deduplicated.
        let p = policy.plan(&dest("example.org"));
        assert_eq!(p.rule.unwrap().origin, RuleOrigin::Project);
        assert_eq!(p.via, [Source::Client]);
        // Defaults: [tunnel] -> client then agent, everything else -> agent.
        let p = policy.plan(&dest("intra.example:8443"));
        assert!(p.rule.is_none());
        assert_eq!(p.via, [Source::Client, Source::Agent]);
        assert_eq!(
            p.tunnel_entry.map(HostPattern::as_str),
            Some("intra.example:8443")
        );
        assert!(p.describe().contains("in [tunnel]"));
        let p = policy.plan(&dest("intra.example:443"));
        assert_eq!(p.via, [Source::Agent]);
        assert!(p.describe().contains("not in [tunnel]"));
        assert!(!policy.build_phase_enabled());
        assert!(NetworkPolicy::default().compile().unwrap().is_empty());
    }

    #[test]
    fn validation() {
        let mut policy = NetworkPolicy {
            tunnel: vec!["h:0".into()],
            ..Default::default()
        };
        assert!(policy.validate().is_err());
        policy.tunnel.clear();
        let mut r = rule(RuleOrigin::Project, 1, "h", None, &[Source::Client]);
        r.rule.phases = Some(vec![Phase::Build]);
        policy.rules = vec![r.clone()];
        assert!(
            policy.validate().is_err(),
            "project hints cannot set phases"
        );
        r.origin = RuleOrigin::User;
        policy.rules = vec![r.clone()];
        assert!(policy.compile().unwrap().build_phase_enabled());
        r.rule.via.clear();
        assert!(r.rule.validate().is_err());
        policy.rules = vec![r];
        assert!(policy.validate().is_err(), "invalid rules fail compiling");
        let m = |host: &str, port| NetMatch {
            host: host.into(),
            port,
        };
        assert!(m("h:443", None).validate().is_err());
        assert!(m("h", Some(0)).validate().is_err());
        assert!(m("[::1]", Some(1)).validate().is_ok());
        let spec = |host: &str, port| m(host, port).pattern().unwrap().specificity();
        assert!(spec("*.x", None) < spec("a.x", None));
        assert!(spec("*", Some(1)) > spec("abc", None));
    }

    #[tokio::test]
    async fn connects_within_the_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let timeout = Duration::from_secs(5);
        assert!(
            connect_with_timeout(&Destination::new("127.0.0.1", port), timeout)
                .await
                .is_ok()
        );
        drop(listener);
        let err = connect_with_timeout(&Destination::new("127.0.0.1", port), timeout)
            .await
            .unwrap_err();
        assert!(err.starts_with("cannot connect to 127.0.0.1:"), "{err}");
        let err = connect_with_timeout(&Destination::new("does-not-exist.invalid", 1), timeout)
            .await
            .unwrap_err();
        assert!(err.starts_with("cannot resolve"), "{err}");
    }

    #[tokio::test]
    async fn relay_counts_bytes_half_closes_and_times_out() {
        let (a_outer, a_inner) = tokio::io::duplex(1024);
        let (b_inner, b_outer) = tokio::io::duplex(1024);
        let (up, down) = (AtomicU64::new(0), AtomicU64::new(0));
        let client = tokio::spawn(async move {
            let mut a = a_outer;
            a.write_all(b"hello").await.unwrap();
            a.shutdown().await.unwrap();
            let mut got = Vec::new();
            a.read_to_end(&mut got).await.unwrap();
            got
        });
        let server = tokio::spawn(async move {
            let mut b = b_outer;
            let mut got = Vec::new();
            b.read_to_end(&mut got).await.unwrap();
            b.write_all(b"world!").await.unwrap();
            b.shutdown().await.unwrap();
            got
        });
        let end = relay(a_inner, b_inner, Duration::from_secs(5), &up, &down).await;
        assert_eq!(end, RelayEnd::Closed);
        assert_eq!(server.await.unwrap(), b"hello");
        assert_eq!(client.await.unwrap(), b"world!");
        assert_eq!(
            (up.load(Ordering::Relaxed), down.load(Ordering::Relaxed)),
            (5, 6)
        );

        let (_a, a_inner) = tokio::io::duplex(64);
        let (b_inner, _b) = tokio::io::duplex(64);
        let started = Instant::now();
        let end = relay(a_inner, b_inner, Duration::from_millis(200), &up, &down).await;
        assert_eq!(end, RelayEnd::Idle);
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}
