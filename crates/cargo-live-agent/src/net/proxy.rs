//! The per-job HTTP proxy.
//!
//! Bound to `127.0.0.1` on an ephemeral port for one build step, it
//! accepts connections only from the step's own processes (see [`peer`]),
//! requires `Proxy-Authorization: Basic` with a random per-step password,
//! and supports `CONNECT host:port` (HTTPS; TLS stays end to end, so the
//! proxy never sees what git or Cargo send inside) and absolute-form plain
//! HTTP requests (`GET http://host/path`). A plain request is rewritten to
//! origin form (`Host` set to the URL's authority, proxy headers removed,
//! `Connection: close`) and forwarded with exactly its `Content-Length`
//! body; after that nothing more is read from the client: the origin's
//! response is relayed until it closes, then the connection is closed. One
//! request per connection, so later requests on the same connection never
//! reach the origin.
//!
//! The step gets `HTTP(S)_PROXY`, `http(s)_proxy`, `CARGO_HTTP_PROXY` and
//! git's `http.proxy`; `NO_PROXY` and `ALL_PROXY` are removed. Dropping
//! the proxy closes the listener and every connection, tunnels included.
//!
//! [`peer`]: super::peer

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};
use zeroize::Zeroizing;

use cargo_live_proto::cred::{Phase, Source};
use cargo_live_proto::net::{relay, Destination, IDLE_TIMEOUT};

use super::peer::{self, JobRoot};
use super::{NetSession, Upstream};
use crate::cred::ToClient;
use crate::{log, Result};

/// User name in the proxy URL; the password is random per step.
pub const PROXY_USER: &str = "cargo-live";
/// Largest accepted request head.
const MAX_HEAD: usize = 64 * 1024;
/// Time a client has to send its request head.
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);
/// How long unread client input is drained (and discarded) before a
/// plain-HTTP connection is closed, so that closing does not reset the
/// connection before the client has read the response.
const LINGER: Duration = Duration::from_secs(2);
/// Environment variables that would bypass or override the proxy.
const CLEARED_ENV: &[&str] = &["NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy"];
const PROXY_AUTHENTICATE: &str = "Proxy-Authenticate: Basic realm=\"cargo-live\"\r\n";

/// A parsed proxy request.
#[derive(Debug, PartialEq, Eq)]
pub struct ProxyRequest {
    pub destination: Destination,
    /// `CONNECT` (tunnel) rather than a forwarded plain HTTP request.
    pub connect: bool,
    /// Length of the request head in the input, including the final
    /// `\r\n\r\n`; bytes after it belong to the tunnel or request body.
    pub head_len: usize,
    /// For plain HTTP: the head to send upstream (origin form, `Host` from
    /// the URL, proxy headers removed, `Connection: close`).
    pub upstream_head: Vec<u8>,
    /// For plain HTTP: the body length (`Content-Length`, 0 without one).
    pub body_len: u64,
    /// The `Proxy-Authorization` header value.
    pub proxy_authorization: Option<Vec<u8>>,
}

/// A request the proxy refuses, with the HTTP status to answer.
#[derive(Debug, PartialEq, Eq)]
pub struct Refusal {
    pub status: u16,
    pub message: String,
}

fn bad_request(message: impl Into<String>) -> Refusal {
    Refusal {
        status: 400,
        message: message.into(),
    }
}

/// Headers that apply to the hop to the proxy, not to the origin, plus
/// `Host`, which is replaced by the URL's authority.
fn dropped_header(name: &str) -> bool {
    [
        "proxy-authorization",
        "proxy-connection",
        "connection",
        "keep-alive",
        "host",
    ]
    .iter()
    .any(|h| name.eq_ignore_ascii_case(h))
}

/// `http://host[:port]/path?query` -> destination, authority, origin form.
fn split_absolute(target: &str) -> Result<(Destination, String, String), Refusal> {
    let scheme_end = target.find("://").unwrap_or(0);
    let scheme = &target[..scheme_end];
    if scheme.eq_ignore_ascii_case("https") {
        return Err(bad_request("https:// URLs must be requested with CONNECT"));
    }
    if !scheme.eq_ignore_ascii_case("http") {
        return Err(bad_request(
            "expected CONNECT or an absolute http:// URL (this is a proxy)",
        ));
    }
    let rest = &target[scheme_end + 3..];
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.contains('@') {
        return Err(bad_request("credentials in proxy URLs are not supported"));
    }
    let destination = Destination::parse(authority, Some(80)).map_err(bad_request)?;
    let path = rest[end..].split('#').next().unwrap_or("");
    let path = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    Ok((destination, authority.to_owned(), path))
}

/// The body length of a plain request: `Content-Length` (all copies must
/// agree), 0 without one. Chunked or other transfer codings are refused:
/// the proxy forwards exactly one request and must know where it ends.
fn body_len(headers: &[httparse::Header<'_>]) -> Result<u64, Refusal> {
    if headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case("transfer-encoding"))
    {
        return Err(Refusal {
            status: 411,
            message: "request bodies need a Content-Length (Transfer-Encoding is not supported)"
                .into(),
        });
    }
    let mut len = None;
    for h in headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("content-length"))
    {
        let value = std::str::from_utf8(h.value)
            .ok()
            .map(str::trim)
            .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|v| v.parse::<u64>().ok())
            .ok_or_else(|| bad_request("invalid Content-Length"))?;
        if len.is_some_and(|l| l != value) {
            return Err(bad_request("conflicting Content-Length headers"));
        }
        len = Some(value);
    }
    Ok(len.unwrap_or(0))
}

/// Parses a request head. `Ok(None)`: incomplete, read more.
pub fn parse_request(buf: &[u8]) -> Result<Option<ProxyRequest>, Refusal> {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut req = httparse::Request::new(&mut headers);
    let head_len = match req.parse(buf) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => return Ok(None),
        Err(e) => return Err(bad_request(format!("malformed request: {e}"))),
    };
    let method = req.method.unwrap_or_default();
    let target = req.path.unwrap_or_default();
    let minor = req.version.unwrap_or(1);
    let proxy_authorization = req
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("proxy-authorization"))
        .map(|h| h.value.to_vec());
    if method.eq_ignore_ascii_case("CONNECT") {
        let destination = Destination::parse(target, None)
            .map_err(|e| bad_request(format!("CONNECT needs host:port: {e}")))?;
        return Ok(Some(ProxyRequest {
            destination,
            connect: true,
            head_len,
            upstream_head: Vec::new(),
            body_len: 0,
            proxy_authorization,
        }));
    }
    let (destination, authority, path) = split_absolute(target)?;
    let body_len = body_len(req.headers)?;
    // RFC 7230 5.4: the Host header of a request with an absolute-form
    // target is replaced by the target's authority.
    let mut head = format!("{method} {path} HTTP/1.{minor}\r\nHost: {authority}\r\n").into_bytes();
    for h in req.headers.iter() {
        if dropped_header(h.name) {
            continue;
        }
        head.extend_from_slice(h.name.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(h.value);
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(b"Connection: close\r\n\r\n");
    Ok(Some(ProxyRequest {
        destination,
        connect: false,
        head_len,
        upstream_head: head,
        body_len,
        proxy_authorization,
    }))
}

/// Checks `Proxy-Authorization: Basic base64(user:password)` in constant
/// time against `expected` (`user:password`).
pub fn authorized(header: Option<&[u8]>, expected: &[u8]) -> bool {
    let Some(value) = header.and_then(|h| std::str::from_utf8(h).ok()) else {
        return false;
    };
    let Some((scheme, credential)) = value.trim().split_once(' ') else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("basic") {
        return false;
    }
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(credential.trim()) else {
        return false;
    };
    let decoded = Zeroizing::new(decoded);
    bool::from(decoded.as_slice().ct_eq(expected))
}

/// A complete response with `Connection: close`.
pub fn response(status: u16, extra_headers: &str, body: &str) -> Vec<u8> {
    let reason = match status {
        200 => "Connection established",
        400 => "Bad Request",
        407 => "Proxy Authentication Required",
        411 => "Length Required",
        502 => "Bad Gateway",
        _ => "Error",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\n{extra_headers}Content-Type: text/plain\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

pub struct Proxy {
    addr: SocketAddr,
    password: Zeroizing<String>,
    task: JoinHandle<()>,
}

/// What every connection of one proxy shares.
struct Context {
    expected: Zeroizing<Vec<u8>>,
    local: SocketAddr,
    phase: Phase,
    net: Arc<NetSession>,
    events: mpsc::Sender<ToClient>,
    job: JobRoot,
}

impl Proxy {
    /// Starts the proxy for one build step. Connections are accepted only
    /// from the process whose pid `job` will hold (the step's Cargo) and
    /// its descendants.
    pub fn start(
        phase: Phase,
        net: Arc<NetSession>,
        events: mpsc::Sender<ToClient>,
        job: JobRoot,
    ) -> Result<Self> {
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0")
            .map_err(|e| format!("cannot start the build proxy: {e}"))?;
        std_listener.set_nonblocking(true)?;
        let listener = TcpListener::from_std(std_listener)?;
        let addr = listener.local_addr()?;
        let mut bytes = Zeroizing::new([0u8; 24]);
        getrandom::fill(&mut bytes[..])
            .map_err(|e| format!("OS random number generator failed: {e}"))?;
        let password = Zeroizing::new(cargo_live_proto::hex(&bytes[..]));
        let ctx = Arc::new(Context {
            expected: Zeroizing::new(format!("{PROXY_USER}:{}", password.as_str()).into_bytes()),
            local: addr,
            phase,
            net,
            events,
            job,
        });
        let task = tokio::spawn(accept_loop(listener, ctx));
        log!("build proxy for the {phase} step listening on {addr}");
        Ok(Self {
            addr,
            password,
            task,
        })
    }

    #[cfg(test)]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `http://cargo-live:<password>@127.0.0.1:<port>`.
    pub fn url(&self) -> Zeroizing<String> {
        Zeroizing::new(format!(
            "http://{PROXY_USER}:{}@{}",
            self.password.as_str(),
            self.addr
        ))
    }

    /// Points the step's HTTP clients at the proxy.
    pub fn configure(&self, cmd: &mut Command) {
        let url = self.url();
        for var in [
            "HTTPS_PROXY",
            "HTTP_PROXY",
            "https_proxy",
            "http_proxy",
            "CARGO_HTTP_PROXY",
        ] {
            cmd.env(var, url.as_str());
        }
        for var in CLEARED_ENV {
            cmd.env_remove(var);
        }
    }

    /// git configuration entries (passed via `GIT_CONFIG_*`).
    pub fn git_entries(&self) -> Vec<(String, String)> {
        vec![
            ("http.proxy".to_owned(), self.url().to_string()),
            ("http.proxyAuthMethod".to_owned(), "basic".to_owned()),
        ]
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        // Dropping the accept loop drops its JoinSet, which aborts every
        // connection; each records an audit entry (`step-ended`, or
        // `aborted` while still connecting).
        self.task.abort();
    }
}

async fn accept_loop(listener: TcpListener, ctx: Arc<Context>) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    let _ = stream.set_nodelay(true);
                    connections.spawn(serve(stream, peer, ctx.clone()));
                }
                Err(e) => {
                    log!("build proxy: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

/// Reads until a complete request head (or a refusal).
async fn read_head(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
) -> std::result::Result<Option<ProxyRequest>, Refusal> {
    loop {
        if let Some(request) = parse_request(buf)? {
            return Ok(Some(request));
        }
        if buf.len() >= MAX_HEAD {
            return Err(bad_request("request head too large"));
        }
        buf.reserve(4096);
        match stream.read_buf(buf).await {
            Ok(0) | Err(_) => return Ok(None),
            Ok(_) => {}
        }
    }
}

/// Source, bytes, refusals and outcome of one proxied connection. Created
/// before connecting; writes exactly one audit entry: when finished, or
/// when dropped earlier (`aborted` while still connecting, e.g. waiting
/// for a tunnel slot or the client's answer; `step-ended` once connected).
struct Tracker {
    net: Arc<NetSession>,
    destination: Destination,
    phase: Phase,
    /// The source that connected, once one did.
    via: Option<Source>,
    /// Sources refused or failed so far.
    chain: Vec<String>,
    up: AtomicU64,
    down: AtomicU64,
    done: bool,
}

impl Tracker {
    fn new(net: Arc<NetSession>, destination: Destination, phase: Phase) -> Self {
        Self {
            net,
            destination,
            phase,
            via: None,
            chain: Vec::new(),
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
            done: false,
        }
    }

    fn finish(&mut self, outcome: &str) {
        if std::mem::replace(&mut self.done, true) {
            return;
        }
        let via = self
            .via
            .map_or_else(|| "none".to_owned(), |s| s.to_string());
        self.net.audit(
            &self.destination,
            self.phase,
            &via,
            outcome,
            self.up.load(Ordering::Relaxed),
            self.down.load(Ordering::Relaxed),
            std::mem::take(&mut self.chain),
        );
    }
}

impl Drop for Tracker {
    fn drop(&mut self) {
        let outcome = if self.via.is_some() {
            "step-ended"
        } else {
            "aborted"
        };
        self.finish(outcome);
    }
}

async fn serve(mut stream: TcpStream, peer: SocketAddr, ctx: Arc<Context>) {
    let mut buf = Vec::new();
    let request = match tokio::time::timeout(HEAD_TIMEOUT, read_head(&mut stream, &mut buf)).await {
        Ok(Ok(Some(request))) => request,
        Ok(Ok(None)) | Err(_) => return,
        Ok(Err(refusal)) => {
            let body = format!("cargo-live proxy: {}\n", refusal.message);
            let _ = stream.write_all(&response(refusal.status, "", &body)).await;
            return;
        }
    };
    if !authorized(request.proxy_authorization.as_deref(), &ctx.expected) {
        let _ = stream
            .write_all(&response(
                407,
                PROXY_AUTHENTICATE,
                "cargo-live proxy: authentication required\n",
            ))
            .await;
        return;
    }
    let mut tracker = Tracker::new(ctx.net.clone(), request.destination.clone(), ctx.phase);
    // Only the step's own processes may use the proxy, password or not.
    let (local, root) = (ctx.local, ctx.job.get().copied());
    let checked = tokio::task::spawn_blocking(move || peer::check(peer, local, root))
        .await
        .unwrap_or_else(|e| Err(format!("peer check failed: {e}")));
    if let Err(reason) = checked {
        log!("build proxy: refused a connection from {peer}: {reason}");
        tracker.chain.push(format!("refused: {reason}"));
        tracker.finish("denied");
        let _ = stream
            .write_all(&response(
                407,
                PROXY_AUTHENTICATE,
                "cargo-live proxy: this connection does not come from the build\n",
            ))
            .await;
        return;
    }
    let leftover = buf.split_off(request.head_len);
    let destination = request.destination.clone();
    let connected = ctx
        .net
        .connect(
            &destination,
            ctx.phase,
            peer.port(),
            &ctx.events,
            &mut tracker.chain,
        )
        .await;
    let Some((via, upstream)) = connected else {
        let body = format!(
            "cargo-live proxy: no route to {destination}: {}\n",
            tracker.chain.join("; ")
        );
        tracker.finish("denied");
        let _ = stream.write_all(&response(502, "", &body)).await;
        return;
    };
    tracker.via = Some(via);
    let outcome = match upstream {
        Upstream::Direct(tcp) => forward(stream, tcp, &request, &leftover, &tracker).await,
        Upstream::Tunnel(channel, _permit) => {
            forward(stream, channel, &request, &leftover, &tracker).await
        }
    };
    tracker.finish(&outcome);
}

/// Answers the client (CONNECT) and relays bytes both ways, or forwards
/// one plain request. Returns the audit outcome.
async fn forward<U>(
    mut client: TcpStream,
    mut upstream: U,
    request: &ProxyRequest,
    leftover: &[u8],
    tracker: &Tracker,
) -> String
where
    U: AsyncRead + AsyncWrite + Unpin,
{
    if !request.connect {
        return forward_plain(client, upstream, request, leftover, tracker).await;
    }
    let start = async {
        client
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await?;
        if !leftover.is_empty() {
            upstream.write_all(leftover).await?;
            tracker
                .up
                .fetch_add(leftover.len() as u64, Ordering::Relaxed);
        }
        upstream.flush().await
    };
    if start.await.is_err() {
        return "error".into();
    }
    relay(client, upstream, IDLE_TIMEOUT, &tracker.up, &tracker.down)
        .await
        .as_str()
        .to_owned()
}

/// Copies from `r` to `w` until EOF, counting bytes; fails after
/// [`IDLE_TIMEOUT`] without input. Never shuts `w` down.
async fn copy_counted<R, W>(r: &mut R, w: &mut W, count: &AtomicU64) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        let n = tokio::time::timeout(IDLE_TIMEOUT, r.read(&mut buf))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        if n == 0 {
            return Ok(());
        }
        w.write_all(&buf[..n]).await?;
        w.flush().await?;
        count.fetch_add(n as u64, Ordering::Relaxed);
    }
}

/// One plain HTTP request: the rewritten head and exactly `body_len`
/// body bytes go upstream; then the response is relayed until the origin
/// closes, and the connection is closed. Client bytes beyond the body
/// (such as a second request on a keep-alive connection) are never
/// forwarded.
async fn forward_plain<U>(
    client: TcpStream,
    upstream: U,
    request: &ProxyRequest,
    leftover: &[u8],
    tracker: &Tracker,
) -> String
where
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_rd, mut client_wr) = client.into_split();
    let (mut up_rd, mut up_wr) = tokio::io::split(upstream);
    let buffered = usize::try_from(request.body_len)
        .unwrap_or(usize::MAX)
        .min(leftover.len());
    let remaining = request.body_len - buffered as u64;
    let start = async {
        for part in [&request.upstream_head[..], &leftover[..buffered]] {
            up_wr.write_all(part).await?;
            tracker.up.fetch_add(part.len() as u64, Ordering::Relaxed);
        }
        up_wr.flush().await
    };
    if start.await.is_err() {
        return "error".into();
    }
    // The rest of the body, concurrently with the response (a client may
    // wait for `100 Continue`). The upstream is not shut down afterwards:
    // some servers treat a half-close as an aborted request.
    let body = async {
        let mut rest = (&mut client_rd).take(remaining);
        let _ = copy_counted(&mut rest, &mut up_wr, &tracker.up).await;
        std::future::pending::<()>().await
    };
    let response = copy_counted(&mut up_rd, &mut client_wr, &tracker.down);
    let outcome = tokio::select! {
        result = response => match result {
            Ok(()) => "closed",
            Err(e) if e.kind() == io::ErrorKind::TimedOut => "idle-timeout",
            Err(_) => "error",
        },
        () = body => unreachable!("pending"),
    };
    let _ = client_wr.shutdown().await;
    // Drain and discard whatever else the client sent, so that closing
    // does not reset the connection before it read the response.
    let drain = async {
        let mut sink = [0u8; 4096];
        while matches!(client_rd.read(&mut sink).await, Ok(n) if n > 0) {}
    };
    let _ = tokio::time::timeout(LINGER, drain).await;
    outcome.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::tests::{direct, set, user_rule};
    use std::sync::{Mutex, OnceLock};

    fn basic(user_pass: &str) -> String {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(user_pass)
        )
    }

    #[test]
    fn parses_connect() {
        let head = b"CONNECT gitlab.volka.com:443 HTTP/1.1\r\nHost: gitlab.volka.com:443\r\n\
                     Proxy-Authorization: Basic eDp5\r\n\r\n\x16\x03\x01";
        let r = parse_request(head).unwrap().unwrap();
        assert!(r.connect);
        assert_eq!(r.destination, Destination::new("gitlab.volka.com", 443));
        assert_eq!(&head[r.head_len..], b"\x16\x03\x01");
        assert_eq!(r.proxy_authorization.as_deref(), Some(&b"Basic eDp5"[..]));
        let r = parse_request(b"CONNECT [::1]:8443 HTTP/1.1\r\n\r\n")
            .unwrap()
            .unwrap();
        assert_eq!(r.destination, Destination::new("::1", 8443));
        // Incomplete heads ask for more input.
        assert_eq!(
            parse_request(b"CONNECT h:443 HTTP/1.1\r\nHost: h").unwrap(),
            None
        );
        for bad in [
            &b"CONNECT h HTTP/1.1\r\n\r\n"[..],
            b"CONNECT h:0 HTTP/1.1\r\n\r\n",
            b"CONNECT h:x HTTP/1.1\r\n\r\n",
            b"CONNECT a b:1 HTTP/1.1\r\n\r\n",
            b"\x00\x01garbage\r\n\r\n",
        ] {
            assert_eq!(parse_request(bad).unwrap_err().status, 400, "{bad:?}");
        }
    }

    #[test]
    fn rewrites_absolute_form_to_origin_form() {
        let head = b"GET http://127.0.0.1:8080/git/a.git/info/refs?service=x HTTP/1.1\r\n\
                     Host: 127.0.0.1:8080\r\nProxy-Authorization: Basic eDp5\r\n\
                     Proxy-Connection: Keep-Alive\r\nConnection: keep-alive\r\n\
                     Authorization: Basic c2VjcmV0\r\nAccept: */*\r\n\r\nBODY";
        let r = parse_request(head).unwrap().unwrap();
        assert!(!r.connect);
        assert_eq!(r.destination, Destination::new("127.0.0.1", 8080));
        assert_eq!(&head[r.head_len..], b"BODY");
        assert_eq!(r.body_len, 0);
        let up = String::from_utf8(r.upstream_head).unwrap();
        assert_eq!(
            up,
            "GET /git/a.git/info/refs?service=x HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\
             Authorization: Basic c2VjcmV0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
        // Default port 80, missing path and Host header.
        let r = parse_request(b"HEAD HTTP://Example.COM?x=1#frag HTTP/1.0\r\n\r\n")
            .unwrap()
            .unwrap();
        assert_eq!(r.destination, Destination::new("example.com", 80));
        assert_eq!(
            String::from_utf8(r.upstream_head).unwrap(),
            "HEAD /?x=1 HTTP/1.0\r\nHost: Example.COM\r\nConnection: close\r\n\r\n"
        );
        for bad in [
            &b"GET /relative HTTP/1.1\r\n\r\n"[..],
            b"GET https://h/ HTTP/1.1\r\n\r\n",
            b"GET ftp://h/ HTTP/1.1\r\n\r\n",
            b"GET http://user:pw@h/ HTTP/1.1\r\n\r\n",
            b"GET http:///x HTTP/1.1\r\n\r\n",
            b"POST http://h/ HTTP/1.1\r\nContent-Length: x\r\n\r\n",
            b"POST http://h/ HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
            b"POST http://h/ HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
        ] {
            assert_eq!(parse_request(bad).unwrap_err().status, 400, "{bad:?}");
        }
    }

    #[test]
    fn host_header_is_the_url_authority() {
        // A client's Host header that differs from the URL is replaced by
        // the authority that was policy-checked.
        let r = parse_request(
            b"GET http://127.0.0.1:8080/x HTTP/1.1\r\nHOST: internal.example\r\n\
              host: other\r\nAccept: */*\r\n\r\n",
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            String::from_utf8(r.upstream_head).unwrap(),
            "GET /x HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn request_bodies_need_a_content_length() {
        let r = parse_request(
            b"POST http://h/ HTTP/1.1\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\nBODY",
        )
        .unwrap()
        .unwrap();
        assert_eq!(r.body_len, 4);
        for chunked in [
            &b"POST http://h/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
            b"POST http://h/ HTTP/1.1\r\nContent-Length: 4\r\ntransfer-encoding: gzip\r\n\r\n",
        ] {
            let refusal = parse_request(chunked).unwrap_err();
            assert_eq!(refusal.status, 411, "{chunked:?}");
        }
        assert!(String::from_utf8(response(411, "", "x"))
            .unwrap()
            .starts_with("HTTP/1.1 411 Length Required\r\n"));
    }

    #[test]
    fn proxy_authorization() {
        let expected = b"cargo-live:s3cret";
        assert!(authorized(
            Some(basic("cargo-live:s3cret").as_bytes()),
            expected
        ));
        assert!(authorized(
            Some(format!("  basic {}", &basic("cargo-live:s3cret")[6..]).as_bytes()),
            expected
        ));
        for bad in [
            basic("cargo-live:wrong"),
            basic("other:s3cret"),
            "Bearer x".to_owned(),
            "Basic !!!".to_owned(),
            "Basic".to_owned(),
            String::new(),
        ] {
            assert!(!authorized(Some(bad.as_bytes()), expected), "{bad}");
        }
        assert!(!authorized(None, expected));
    }

    /// The job root: this test process, so that its own connections count
    /// as the job's.
    fn this_process() -> JobRoot {
        Arc::new(OnceLock::from(std::process::id()))
    }

    fn session(patterns: &[&str], dir: &tempfile::TempDir) -> Arc<NetSession> {
        Arc::new(NetSession::new(
            "t".into(),
            direct(patterns),
            true,
            dir.path().join("audit.log"),
            None,
        ))
    }

    async fn proxy_with(patterns: &[&str]) -> (Proxy, tempfile::TempDir, mpsc::Receiver<ToClient>) {
        let dir = tempfile::tempdir().unwrap();
        let net = session(patterns, &dir);
        let (tx, rx) = mpsc::channel(16);
        let proxy = Proxy::start(Phase::Fetch, net, tx, this_process()).unwrap();
        (proxy, dir, rx)
    }

    async fn roundtrip(addr: SocketAddr, request: &[u8]) -> String {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(request).await.unwrap();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut out)).await;
        String::from_utf8_lossy(&out).into_owned()
    }

    fn auth_header(proxy: &Proxy) -> String {
        format!(
            "Proxy-Authorization: {}\r\n",
            basic(&format!("{PROXY_USER}:{}", proxy.password.as_str()))
        )
    }

    fn audit_entries(dir: &tempfile::TempDir) -> Vec<serde_json::Value> {
        std::fs::read_to_string(dir.path().join("audit.log"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// An origin that records everything it receives on each connection:
    /// it reads the request head, keeps reading for `linger` (to catch
    /// anything sent after it), answers, and closes.
    async fn origin(linger: Duration) -> (u16, Arc<Mutex<Vec<String>>>) {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = upstream.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let record = seen.clone();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = upstream.accept().await.unwrap();
                let record = record.clone();
                tokio::spawn(async move {
                    let mut got = Vec::new();
                    let mut buf = vec![0u8; 4096];
                    while !got.windows(4).any(|w| w == b"\r\n\r\n") && got != b"PING" {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => got.extend_from_slice(&buf[..n]),
                        }
                    }
                    let _ = tokio::time::timeout(linger, async {
                        while let Ok(n) = s.read(&mut buf).await {
                            if n == 0 {
                                break;
                            }
                            got.extend_from_slice(&buf[..n]);
                        }
                    })
                    .await;
                    record
                        .lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&got).into_owned());
                    let _ = s
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await;
                });
            }
        });
        (port, seen)
    }

    #[tokio::test]
    async fn serves_connect_and_plain_http_with_auth() {
        let (port, seen) = origin(Duration::ZERO).await;
        let (proxy, dir, _rx) = proxy_with(&["127.0.0.1"]).await;
        let auth = auth_header(&proxy);

        // No or wrong credentials: 407.
        let out = roundtrip(
            proxy.addr(),
            format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n").as_bytes(),
        )
        .await;
        assert!(out.starts_with("HTTP/1.1 407 "), "{out}");
        assert!(out.contains("Proxy-Authenticate: Basic realm=\"cargo-live\""));
        let wrong = format!(
            "CONNECT 127.0.0.1:{port} HTTP/1.1\r\nProxy-Authorization: {}\r\n\r\n",
            basic("cargo-live:nope")
        );
        assert!(roundtrip(proxy.addr(), wrong.as_bytes())
            .await
            .starts_with("HTTP/1.1 407 "));

        // CONNECT: 200, then raw bytes both ways.
        let req = format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\n{auth}\r\nPING");
        let out = roundtrip(proxy.addr(), req.as_bytes()).await;
        assert!(
            out.starts_with("HTTP/1.1 200 Connection established\r\n\r\nHTTP/1.1 200 OK"),
            "{out}"
        );
        assert!(out.ends_with("ok"));

        // Absolute form: forwarded in origin form without proxy headers.
        let req = format!(
            "GET http://127.0.0.1:{port}/index?q HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{auth}\r\n"
        );
        let out = roundtrip(proxy.addr(), req.as_bytes()).await;
        assert!(out.starts_with("HTTP/1.1 200 OK"), "{out}");
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen[0], "PING");
        assert!(
            seen[1].starts_with("GET /index?q HTTP/1.1\r\n"),
            "{}",
            seen[1]
        );
        assert!(!seen[1].to_ascii_lowercase().contains("proxy-authorization"));
        assert!(seen[1].contains("Connection: close\r\n"));

        // Bad request.
        let out = roundtrip(
            proxy.addr(),
            format!("GET /x HTTP/1.1\r\n{auth}\r\n").as_bytes(),
        )
        .await;
        assert!(out.starts_with("HTTP/1.1 400 "), "{out}");

        let password = proxy.password.to_string();
        drop(proxy);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let audit = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
        let entries = audit_entries(&dir);
        assert_eq!(entries.len(), 2, "{audit}");
        assert!(entries
            .iter()
            .all(|e| e["via"] == "agent" && e["outcome"] == "closed"));
        assert_eq!(entries[0]["bytes_up"], 4);
        assert_eq!(entries[0]["bytes_down"], 59);
        assert!(!audit.contains(&password));
    }

    #[tokio::test]
    async fn one_request_per_connection() {
        // The origin keeps reading for a while after the first request
        // head, so anything else forwarded on the connection would show.
        let (port, seen) = origin(Duration::from_millis(500)).await;
        let (proxy, _dir, _rx) = proxy_with(&["127.0.0.1"]).await;
        let auth = auth_header(&proxy);
        // Two requests on one keep-alive connection, the second with its
        // own Proxy-Authorization; the first with a body and a Host header
        // that differs from the URL.
        let first = format!(
            "POST http://127.0.0.1:{port}/first HTTP/1.1\r\nHost: evil.example\r\n{auth}\
             Proxy-Connection: keep-alive\r\nContent-Length: 4\r\n\r\nBODY"
        );
        let second = format!(
            "GET http://127.0.0.1:{port}/second HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{auth}\r\n"
        );
        let mut s = TcpStream::connect(proxy.addr()).await.unwrap();
        s.write_all(first.as_bytes()).await.unwrap();
        s.write_all(second.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut out))
            .await
            .expect("the proxy closes the connection after one response")
            .unwrap();
        let out = String::from_utf8_lossy(&out);
        assert_eq!(out.matches("HTTP/1.1 200 OK").count(), 1, "{out}");
        let first = seen.lock().unwrap().clone();
        assert_eq!(first.len(), 1, "{first:?}");
        assert_eq!(
            first[0],
            format!(
                "POST /first HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: 4\r\n\
                 Connection: close\r\n\r\nBODY"
            )
        );
        assert!(!first[0].contains("/second"));
        assert!(!first[0]
            .to_ascii_lowercase()
            .contains("proxy-authorization"));

        // A body that arrives after the head is forwarded up to its length.
        let mut s = TcpStream::connect(proxy.addr()).await.unwrap();
        s.write_all(
            format!(
                "PUT http://127.0.0.1:{port}/late HTTP/1.1\r\n{auth}Content-Length: 6\r\n\r\nab"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        s.write_all(format!("cdefGET http://127.0.0.1:{port}/x HTTP/1.1\r\n{auth}\r\n").as_bytes())
            .await
            .unwrap();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut out)).await;
        assert!(String::from_utf8_lossy(&out).starts_with("HTTP/1.1 200 OK"));
        let late = seen.lock().unwrap()[1].clone();
        assert!(late.ends_with("\r\n\r\nabcdef"), "{late:?}");

        // Chunked bodies are refused before anything is forwarded.
        let out = roundtrip(
            proxy.addr(),
            format!(
                "POST http://127.0.0.1:{port}/c HTTP/1.1\r\n{auth}Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
            )
            .as_bytes(),
        )
        .await;
        assert!(out.starts_with("HTTP/1.1 411 "), "{out}");
        assert_eq!(seen.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn refused_destinations_get_502_with_the_chain() {
        let (proxy, dir, mut rx) = proxy_with(&[]).await;
        let auth = auth_header(&proxy);
        let out = roundtrip(
            proxy.addr(),
            format!("CONNECT 127.0.0.1:9 HTTP/1.1\r\n{auth}\r\n").as_bytes(),
        )
        .await;
        assert!(out.starts_with("HTTP/1.1 502 Bad Gateway"), "{out}");
        assert!(
            out.contains("no route to 127.0.0.1:9: agent → denied by the agent's [network] direct"),
            "{out}"
        );
        assert!(matches!(rx.recv().await, Some(ToClient::Net(_))));
        let entries = audit_entries(&dir);
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0]["outcome"], "denied");
        assert_eq!(entries[0]["via"], "none");
        assert_eq!(entries[0]["port"], 9);
        assert_eq!(
            entries[0]["chain"][0],
            "agent → denied by the agent's [network] direct"
        );
    }

    #[tokio::test]
    async fn connections_still_connecting_are_audited_when_the_step_ends() {
        let dir = tempfile::tempdir().unwrap();
        let net = session(&[], &dir);
        // Direct denied, then the client, whose tunnel slots are all busy.
        set(
            &net,
            vec![user_rule(
                "gitlab.example.com",
                &[Source::Agent, Source::Client],
                None,
            )],
            vec!["gitlab.example.com".into()],
        );
        let mut permits = Vec::new();
        for _ in 0..cargo_live_proto::net::MAX_TUNNELS {
            permits.push(net.tunnel_slot().await.unwrap());
        }
        let (tx, _rx) = mpsc::channel(16);
        let proxy = Proxy::start(Phase::Fetch, net, tx, this_process()).unwrap();
        let auth = auth_header(&proxy);
        let mut s = TcpStream::connect(proxy.addr()).await.unwrap();
        s.write_all(format!("CONNECT gitlab.example.com:443 HTTP/1.1\r\n{auth}\r\n").as_bytes())
            .await
            .unwrap();
        // Waiting for a slot: no answer yet, no audit entry yet.
        let mut buf = [0u8; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(500), s.read(&mut buf))
                .await
                .is_err()
        );
        assert!(audit_entries(&dir).is_empty());
        drop(proxy);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let entries = audit_entries(&dir);
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0]["outcome"], "aborted");
        assert_eq!(entries[0]["via"], "none");
        assert_eq!(
            entries[0]["chain"],
            serde_json::json!(["agent → denied by the agent's [network] direct"])
        );
    }

    #[tokio::test]
    async fn only_the_jobs_processes_may_connect() {
        let (port, seen) = origin(Duration::ZERO).await;
        let dir = tempfile::tempdir().unwrap();
        let net = session(&["127.0.0.1"], &dir);
        let (tx, _rx) = mpsc::channel(16);

        // The job is a process that is not an ancestor of this one: this
        // process is outside its tree and is refused, password or not.
        let mut outsider_root = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let job: JobRoot = Arc::new(OnceLock::from(outsider_root.id()));
        let proxy = Proxy::start(Phase::Fetch, net.clone(), tx.clone(), job).unwrap();
        let auth = auth_header(&proxy);
        let out = roundtrip(
            proxy.addr(),
            format!("GET http://127.0.0.1:{port}/outsider HTTP/1.1\r\n{auth}\r\n").as_bytes(),
        )
        .await;
        assert!(out.starts_with("HTTP/1.1 407 "), "{out}");
        assert!(out.contains("does not come from the build"), "{out}");
        assert!(seen.lock().unwrap().is_empty());
        let entries = audit_entries(&dir);
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0]["outcome"], "denied");
        assert!(
            entries[0]["chain"][0]
                .as_str()
                .unwrap()
                .contains("is not part of this build"),
            "{entries:?}"
        );
        drop(proxy);
        outsider_root.kill().unwrap();
        outsider_root.wait().unwrap();

        // A job not started yet: refused.
        let proxy =
            Proxy::start(Phase::Fetch, net.clone(), tx.clone(), JobRoot::default()).unwrap();
        let auth = auth_header(&proxy);
        let out = roundtrip(
            proxy.addr(),
            format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\n{auth}\r\n").as_bytes(),
        )
        .await;
        assert!(out.starts_with("HTTP/1.1 407 "), "{out}");
        drop(proxy);

        // Descendants of the job root are accepted: git (a child of this
        // process) runs git-remote-http (a grandchild), which connects.
        let proxy = Proxy::start(Phase::Fetch, net, tx, this_process()).unwrap();
        let url = proxy.url();
        let output = tokio::process::Command::new("git")
            .args(["-c", &format!("http.proxy={}", url.as_str())])
            .args(["-c", "http.proxyAuthMethod=basic"])
            .args(["ls-remote", &format!("http://127.0.0.1:{port}/repo.git")])
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .await
            .unwrap();
        // The origin is not a git server; what matters is that the request
        // reached it through the proxy.
        let seen = seen.lock().unwrap().clone();
        assert!(
            seen.iter()
                .any(|r| r.starts_with("GET /repo.git/info/refs?service=git-upload-pack ")),
            "{seen:?} {}",
            String::from_utf8_lossy(&output.stderr)
        );
        drop(proxy);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let entries = audit_entries(&dir);
        assert_eq!(entries[1]["outcome"], "denied");
        assert!(entries[1]["chain"][0]
            .as_str()
            .unwrap()
            .contains("has not started"));
        assert!(
            entries[2..]
                .iter()
                .all(|e| e["via"] == "agent" && e["outcome"] == "closed"),
            "{entries:?}"
        );
    }

    #[tokio::test]
    async fn dropping_the_proxy_closes_connections() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = upstream.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (s, _) = upstream.accept().await.unwrap();
            // Hold the connection open.
            tokio::time::sleep(Duration::from_secs(60)).await;
            drop(s);
        });
        let (proxy, dir, _rx) = proxy_with(&["*"]).await;
        let auth = auth_header(&proxy);
        let mut s = TcpStream::connect(proxy.addr()).await.unwrap();
        s.write_all(format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\n{auth}\r\n").as_bytes())
            .await
            .unwrap();
        let mut buf = [0u8; 39];
        s.read_exact(&mut buf).await.unwrap();
        drop(proxy);
        let mut rest = Vec::new();
        let n = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut rest))
            .await
            .expect("connection closed")
            .unwrap_or(0);
        assert_eq!(n, 0);
        let audit = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
        assert!(audit.contains("\"outcome\":\"step-ended\""), "{audit}");
        assert_eq!(audit.lines().count(), 1, "{audit}");
        assert!(TcpStream::connect(("127.0.0.1", port)).await.is_ok());
    }
}
