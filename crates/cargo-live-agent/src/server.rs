//! The SSH server: authentication and channel policy.
//!
//! Policy:
//! - only the `password` method is offered; the user must be
//!   [`USERNAME`] and the password a valid API token;
//! - rejections take at least one second (russh's `auth_rejection_time`),
//!   plus a per-IP exponential backoff after repeated failures;
//! - an authenticated connection may open exactly one `session` channel,
//!   which accepts only an exec or subsystem request named [`CHANNEL_NAME`];
//!   pty, shell, env, x11, agent forwarding, signals, TCP/IP and streamlocal
//!   forwarding and every other channel type are refused;
//! - the agent itself opens `forwarded-tcpip` channels towards the client
//!   for the build proxy's `client` tunnels (see `net`); the client accepts
//!   them only during a build and only for destinations in its `[tunnel]`;
//! - unauthenticated connections are closed after [`AUTH_DEADLINE`];
//! - at most `max_connections` connections (authenticated or not) are open
//!   at once; further connections are closed right after `accept`.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use russh::keys::PrivateKey;
use russh::server::{self, Auth, ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet, Pty, Sig};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use cargo_live_proto::{CHANNEL_NAME, USERNAME};

use crate::settings::Settings;
use crate::tokens::TokenFile;
use crate::{log, Result};

const AUTH_DEADLINE: Duration = Duration::from_secs(30);
const BACKOFF_FREE_FAILURES: u32 = 3;
const BACKOFF_MAX: Duration = Duration::from_secs(60);
const BACKOFF_RESET: Duration = Duration::from_secs(15 * 60);

/// State shared by all connections.
pub struct Shared {
    pub settings: Settings,
    pub agent_exe: std::path::PathBuf,
    pub builds: Semaphore,
    connections: Arc<Semaphore>,
    failures: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl Shared {
    pub fn new(settings: Settings, agent_exe: std::path::PathBuf) -> Self {
        Self {
            builds: Semaphore::new(settings.max_concurrent_builds),
            connections: Arc::new(Semaphore::new(settings.max_connections)),
            settings,
            agent_exe,
            failures: Mutex::new(HashMap::new()),
        }
    }

    fn backoff(&self, ip: Option<IpAddr>) -> Duration {
        let Some(ip) = ip else {
            return Duration::ZERO;
        };
        let failures = self.failures.lock().unwrap();
        match failures.get(&ip) {
            Some((count, last)) if last.elapsed() < BACKOFF_RESET => backoff_for(*count),
            _ => Duration::ZERO,
        }
    }

    fn record(&self, ip: Option<IpAddr>, success: bool) {
        let Some(ip) = ip else { return };
        let mut failures = self.failures.lock().unwrap();
        if success {
            failures.remove(&ip);
            return;
        }
        if failures.len() > 10_000 {
            failures.retain(|_, (_, last)| last.elapsed() < BACKOFF_RESET);
        }
        let entry = failures.entry(ip).or_insert((0, Instant::now()));
        if entry.1.elapsed() >= BACKOFF_RESET {
            entry.0 = 0;
        }
        entry.0 = entry.0.saturating_add(1);
        entry.1 = Instant::now();
    }
}

/// Extra delay before evaluating an attempt after `failures` failures.
pub fn backoff_for(failures: u32) -> Duration {
    if failures <= BACKOFF_FREE_FAILURES {
        return Duration::ZERO;
    }
    let exp = (failures - BACKOFF_FREE_FAILURES - 1).min(6);
    Duration::from_secs(1 << exp).min(BACKOFF_MAX)
}

pub fn ssh_config(key: PrivateKey) -> server::Config {
    let mut methods = MethodSet::empty();
    methods.push(MethodKind::Password);
    server::Config {
        methods,
        auth_rejection_time: Duration::from_secs(1),
        auth_rejection_time_initial: Some(Duration::from_secs(1)),
        keys: vec![key],
        max_auth_attempts: 3,
        inactivity_timeout: Some(Duration::from_secs(3600)),
        keepalive_interval: Some(Duration::from_secs(15)),
        keepalive_max: 4,
        nodelay: true,
        ..Default::default()
    }
}

pub async fn serve(
    shared: Arc<Shared>,
    config: server::Config,
    listener: TcpListener,
) -> Result<()> {
    let config = Arc::new(config);
    loop {
        let (socket, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                log!("accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(slot) = shared.connections.clone().try_acquire_owned() else {
            log!(
                "{peer}: connection refused: {} connections already open",
                shared.settings.max_connections
            );
            drop(socket);
            continue;
        };
        let _ = socket.set_nodelay(true);
        let authenticated = Arc::new(AtomicBool::new(false));
        let handler = Connection {
            shared: shared.clone(),
            peer,
            authenticated: authenticated.clone(),
            token_name: None,
            channel: None,
            started: false,
        };
        let config = config.clone();
        tokio::spawn(async move {
            let session = match server::run_stream(config, socket, handler).await {
                Ok(session) => session,
                Err(e) => {
                    log!("{peer}: handshake failed: {e}");
                    return;
                }
            };
            let handle = session.handle();
            let watchdog = tokio::spawn(async move {
                tokio::time::sleep(AUTH_DEADLINE).await;
                if !authenticated.load(Ordering::SeqCst) {
                    let _ = handle
                        .disconnect(
                            russh::Disconnect::ByApplication,
                            "authentication timeout".into(),
                            String::new(),
                        )
                        .await;
                }
            });
            if let Err(e) = session.await {
                log!("{peer}: connection error: {e}");
            }
            watchdog.abort();
            drop(slot);
        });
    }
}

struct Connection {
    shared: Arc<Shared>,
    peer: SocketAddr,
    authenticated: Arc<AtomicBool>,
    token_name: Option<String>,
    channel: Option<Channel<Msg>>,
    started: bool,
}

impl Connection {
    fn refuse(
        &mut self,
        channel: ChannelId,
        what: &str,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        log!("{}: refused {what} request", self.peer);
        session.channel_failure(channel)?;
        session.close(channel)?;
        Ok(())
    }
}

impl server::Handler for Connection {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(password_only())
    }

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        _offer: server::PublicKeyOffer<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(password_only())
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _key: server::VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(password_only())
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        _user: &str,
        _submethods: &str,
        _response: Option<server::Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        Ok(password_only())
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        let ip = Some(self.peer.ip());
        let delay = self.shared.backoff(ip);
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        let name = if user == USERNAME {
            match TokenFile::load(&self.shared.settings.paths.tokens_file) {
                Ok(tokens) => tokens.verify(password).map(str::to_owned),
                Err(e) => {
                    log!("cannot load tokens: {e}");
                    None
                }
            }
        } else {
            None
        };
        self.shared.record(ip, name.is_some());
        match name {
            Some(name) => {
                log!("{}: authenticated as token {name:?}", self.peer);
                self.token_name = Some(name);
                self.authenticated.store(true, Ordering::SeqCst);
                Ok(Auth::Accept)
            }
            None => {
                log!("{}: authentication failed (user {user:?})", self.peer);
                Ok(password_only())
            }
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.token_name.is_none() || self.channel.is_some() || self.started {
            log!("{}: refused additional session channel", self.peer);
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }
        self.channel = Some(channel);
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if data == CHANNEL_NAME.as_bytes() {
            self.start(channel, session)
        } else {
            self.refuse(channel, "exec", session)
        }
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name == CHANNEL_NAME {
            self.start(channel, session)
        } else {
            self.refuse(channel, "subsystem", session)
        }
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.refuse(channel, "shell", session)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.refuse(channel, "pty", session)
    }

    async fn x11_request(
        &mut self,
        channel: ChannelId,
        _single_connection: bool,
        _x11_auth_protocol: &str,
        _x11_auth_cookie: &str,
        _x11_screen_number: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.refuse(channel, "x11", session)
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        _variable_name: &str,
        _variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.refuse(channel, "env", session)
    }

    async fn agent_request(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        log!("{}: refused agent forwarding", self.peer);
        Ok(false)
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        _signal: Sig,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.refuse(channel, "signal", session)
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.refuse(channel, "window-change", session)
    }

    async fn tcpip_forward(
        &mut self,
        _address: &str,
        _port: &mut u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        log!("{}: refused tcpip-forward", self.peer);
        Ok(false)
    }

    async fn streamlocal_forward(
        &mut self,
        _socket_path: &str,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        log!("{}: refused streamlocal-forward", self.peer);
        Ok(false)
    }
}

impl Connection {
    fn start(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), russh::Error> {
        let matches = self.channel.as_ref().is_some_and(|c| c.id() == channel);
        let (true, false, Some(token)) = (matches, self.started, self.token_name.clone()) else {
            return self.refuse(channel, "duplicate exec", session);
        };
        let ch = self.channel.take().expect("checked above");
        self.started = true;
        session.channel_success(channel)?;
        let shared = self.shared.clone();
        let peer = self.peer;
        // The handle opens `forwarded-tcpip` channels to the client for
        // the build proxy's tunnels.
        let handle = session.handle();
        tokio::spawn(crate::session::run(
            shared,
            token,
            peer,
            ch.into_stream(),
            handle,
        ));
        Ok(())
    }
}

fn password_only() -> Auth {
    let mut methods = MethodSet::empty();
    methods.push(MethodKind::Password);
    Auth::Reject {
        proceed_with_methods: Some(methods),
        partial_success: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_is_capped() {
        assert_eq!(backoff_for(0), Duration::ZERO);
        assert_eq!(backoff_for(3), Duration::ZERO);
        assert_eq!(backoff_for(4), Duration::from_secs(1));
        assert_eq!(backoff_for(5), Duration::from_secs(2));
        assert_eq!(backoff_for(100), Duration::from_secs(60));
    }
}
