//! SSH transport to cargo-live-agent.
//!
//! The host key is verified inside the handshake (`check_server_key`), before
//! the token is sent: against `remote.host_key` if pinned, otherwise against
//! cargo-live's own known_hosts (trust on first use).

use std::borrow::Cow;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client::{self, ChannelOpenHandle, Handle};
use russh::keys::{Algorithm, PublicKeyOrCertificate};
use russh::{Channel, ChannelMsg, ChannelOpenFailure, ChannelStream, Preferred};
use tokio::net::TcpStream;

use cargo_live_proto::{fingerprint, CHANNEL_NAME, USERNAME};

use crate::config::AgentUrl;
use crate::net::TunnelGate;
use crate::store::{HostKeyStatus, KnownHosts};
use crate::{error, Result};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Accept { learn: bool },
    Reject(String),
}

/// Decides whether to trust `fingerprint` for `host` (canonical `host:port`).
pub fn verify_host(
    pin: Option<&str>,
    known_hosts: &KnownHosts,
    host: &str,
    fingerprint: &str,
) -> Result<Verdict> {
    if let Some(pin) = pin {
        return Ok(if pin == fingerprint {
            Verdict::Accept { learn: false }
        } else {
            Verdict::Reject(format!(
                "host key mismatch for {host}: .cargo/live.toml pins remote.host_key = \
                 \"{pin}\" but the agent presented {fingerprint}. Refusing to send the token. \
                 Compare with `cargo-live-agent fingerprint` on the agent; if the key was \
                 intentionally replaced, update remote.host_key."
            ))
        });
    }
    Ok(match known_hosts.check(host, fingerprint)? {
        HostKeyStatus::Known => Verdict::Accept { learn: false },
        HostKeyStatus::Unknown => Verdict::Accept { learn: true },
        HostKeyStatus::Mismatch { expected } => Verdict::Reject(format!(
            "host key mismatch for {host}: expected {expected} (from {}) but the agent \
             presented {fingerprint}. Refusing to send the token; this may be an attack. \
             Compare with `cargo-live-agent fingerprint` on the agent; if the key was \
             intentionally replaced, remove the {host} line from that file or pin the new \
             key with remote.host_key in .cargo/live.toml.",
            known_hosts.path.display()
        )),
    })
}

pub struct Verifier {
    /// Decides on the agent's tunnel channels; `None` refuses them all.
    tunnel: Option<Arc<TunnelGate>>,
    pin: Option<String>,
    known_hosts: KnownHosts,
    host: String,
    /// The fingerprint and verdict, for error reporting after the handshake.
    result: Arc<Mutex<Option<(String, Verdict)>>>,
}

impl client::Handler for Verifier {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = key else {
            *self.result.lock().unwrap() = Some((
                String::new(),
                Verdict::Reject(
                    "the agent presented a host certificate; expected a plain key".into(),
                ),
            ));
            return Ok(false);
        };
        let Ok(blob) = key.to_bytes() else {
            return Ok(false);
        };
        let fp = fingerprint(&blob);
        let verdict = verify_host(self.pin.as_deref(), &self.known_hosts, &self.host, &fp)
            .unwrap_or_else(|e| Verdict::Reject(e.to_string()));
        let accept = matches!(verdict, Verdict::Accept { .. });
        *self.result.lock().unwrap() = Some((fp, verdict));
        Ok(accept)
    }

    /// The build proxy's `client` tunnels; checked against `[tunnel]`.
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<client::Msg>,
        connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        crate::net::handle_channel(
            self.tunnel.as_ref(),
            channel,
            connected_address,
            connected_port,
            reply,
        )
        .await;
        Ok(())
    }

    // Every other channel the agent might open is refused (russh's
    // defaults accept them).
    async fn server_channel_open_forwarded_streamlocal(
        &mut self,
        _channel: Channel<client::Msg>,
        _socket_path: &str,
        reply: ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        refuse(reply, "forwarded-streamlocal").await;
        Ok(())
    }

    async fn server_channel_open_agent_forward(
        &mut self,
        _channel: Channel<client::Msg>,
        reply: ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        refuse(reply, "agent forwarding").await;
        Ok(())
    }

    async fn server_channel_open_session(
        &mut self,
        _channel: Channel<client::Msg>,
        reply: ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        refuse(reply, "session").await;
        Ok(())
    }

    async fn server_channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<client::Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        refuse(reply, "direct-tcpip").await;
        Ok(())
    }

    async fn server_channel_open_direct_streamlocal(
        &mut self,
        _channel: Channel<client::Msg>,
        _socket_path: &str,
        reply: ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        refuse(reply, "direct-streamlocal").await;
        Ok(())
    }

    async fn server_channel_open_x11(
        &mut self,
        _channel: Channel<client::Msg>,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        refuse(reply, "x11").await;
        Ok(())
    }
}

async fn refuse(reply: ChannelOpenHandle, kind: &str) {
    eprintln!("cargo-live: refused a {kind} channel opened by the agent");
    reply
        .reject(ChannelOpenFailure::AdministrativelyProhibited)
        .await;
}

pub struct Connection {
    pub handle: Handle<Verifier>,
    pub stream: ChannelStream<client::Msg>,
}

fn client_config() -> client::Config {
    client::Config {
        // The agent only has an Ed25519 key; accept nothing else.
        preferred: Preferred {
            key: Cow::Owned(vec![Algorithm::Ed25519]),
            ..Preferred::default()
        },
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(15)),
        keepalive_max: 4,
        nodelay: true,
        ..Default::default()
    }
}

/// Connects, verifies the host key, authenticates with `token` and opens the
/// `cargo-live` channel. `tunnel` decides on the agent's tunnel channels.
pub async fn connect(
    url: &AgentUrl,
    pin: Option<&str>,
    token: &str,
    tunnel: Option<Arc<TunnelGate>>,
) -> Result<Connection> {
    let host = url.to_string();
    let known_hosts = KnownHosts::default_location()?;
    let known_hosts_path = known_hosts.path.clone();
    let addrs: Vec<_> = tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio::net::lookup_host((url.host.as_str(), url.port)),
    )
    .await
    .map_err(|_| error(format!("timed out resolving {}", url.host)))?
    .map_err(|e| error(format!("cannot resolve {}: {e}", url.host)))?
    .collect();
    let mut last_error = None;
    let mut socket = None;
    for addr in addrs {
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => {
                socket = Some(s);
                break;
            }
            Ok(Err(e)) => last_error = Some(e.to_string()),
            Err(_) => last_error = Some("connection timed out".into()),
        }
    }
    let socket = socket.ok_or_else(|| {
        error(format!(
            "cannot connect to cargo-live-agent at {host}: {}",
            last_error.unwrap_or_else(|| "no addresses".into())
        ))
    })?;
    let _ = socket.set_nodelay(true);

    let result = Arc::new(Mutex::new(None));
    let verifier = Verifier {
        tunnel,
        pin: pin.map(str::to_owned),
        known_hosts,
        host: host.clone(),
        result: result.clone(),
    };
    let handshake = tokio::time::timeout(
        CONNECT_TIMEOUT,
        client::connect_stream(Arc::new(client_config()), socket, verifier),
    )
    .await;
    let verdict = result.lock().unwrap().take();
    let (mut handle, fp, learn) = match (handshake, verdict) {
        (_, Some((_, Verdict::Reject(message)))) => return Err(error(message).into()),
        (Ok(Ok(handle)), Some((fp, Verdict::Accept { learn }))) => (handle, fp, learn),
        (Ok(Ok(_)), None) => return Err(error("the agent's host key was not verified").into()),
        (Ok(Err(e)), _) => {
            return Err(error(format!("SSH handshake with {host} failed: {e}")).into())
        }
        (Err(_), _) => return Err(error(format!("SSH handshake with {host} timed out")).into()),
    };

    let auth = tokio::time::timeout(
        // Allows for the agent's per-IP backoff (up to 60s).
        Duration::from_secs(90),
        handle.authenticate_password(USERNAME, token),
    )
    .await
    .map_err(|_| error("authentication timed out"))??;
    if !auth.success() {
        return Err(error(format!(
            "the agent at {host} rejected the token; run `cargo live login {host}` \
             with a valid token (or check CARGO_LIVE_TOKEN)"
        ))
        .into());
    }
    if learn {
        KnownHosts {
            path: known_hosts_path.clone(),
        }
        .learn(&host, &fp)?;
        eprintln!(
            "cargo-live: trusting new host key {fp} for {host} (saved to {})",
            known_hosts_path.display()
        );
    }

    let mut channel = handle.channel_open_session().await?;
    channel.exec(true, CHANNEL_NAME).await?;
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => break,
            Some(ChannelMsg::Failure) | None => {
                return Err(error("the agent refused the cargo-live channel").into())
            }
            Some(_) => {}
        }
    }
    Ok(Connection {
        handle,
        stream: channel.into_stream(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const B: &str = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    #[test]
    fn pinned_key_must_match_exactly() {
        let dir = tempfile::tempdir().unwrap();
        let kh = KnownHosts {
            path: dir.path().join("known_hosts"),
        };
        assert_eq!(
            verify_host(Some(A), &kh, "h:1", A).unwrap(),
            Verdict::Accept { learn: false }
        );
        let Verdict::Reject(msg) = verify_host(Some(A), &kh, "h:1", B).unwrap() else {
            panic!("accepted a mismatching pin");
        };
        assert!(msg.contains(A) && msg.contains(B), "{msg}");
        // A pin overrides known_hosts entirely.
        kh.learn("h:1", B).unwrap();
        assert!(matches!(
            verify_host(Some(A), &kh, "h:1", B).unwrap(),
            Verdict::Reject(_)
        ));
    }

    #[test]
    fn trust_on_first_use_then_detect_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let kh = KnownHosts {
            path: dir.path().join("known_hosts"),
        };
        assert_eq!(
            verify_host(None, &kh, "h:1", A).unwrap(),
            Verdict::Accept { learn: true }
        );
        kh.learn("h:1", A).unwrap();
        assert_eq!(
            verify_host(None, &kh, "h:1", A).unwrap(),
            Verdict::Accept { learn: false }
        );
        let Verdict::Reject(msg) = verify_host(None, &kh, "h:1", B).unwrap() else {
            panic!("accepted a changed key");
        };
        assert!(msg.contains(A) && msg.contains(B), "{msg}");
        assert!(msg.contains("known_hosts"), "{msg}");
    }
}
