//! SSH policy of the real agent binary, exercised with a russh client.

use std::fs;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use russh::client::{self, Handle};
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, Pty};

struct Agent {
    child: Child,
    data: tempfile::TempDir,
    addr: String,
    token: String,
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_agent() -> Agent {
    start_agent_with(&[])
}

fn start_agent_with(extra: &[&str]) -> Agent {
    let exe = env!("CARGO_BIN_EXE_cargo-live-agent");
    let data = tempfile::tempdir().unwrap();
    let out = Command::new(exe)
        .args(["token", "create", "--name", "policy", "--data-dir"])
        .arg(data.path())
        .output()
        .unwrap();
    assert!(out.status.success());
    let token = String::from_utf8(out.stdout).unwrap().trim().to_owned();
    let log = data.path().join("agent.log");
    let child = Command::new(exe)
        .args(["serve", "--listen", "127.0.0.1:0", "--data-dir"])
        .arg(data.path())
        .args(extra)
        .stderr(fs::File::create(&log).unwrap())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let addr = loop {
        let text = fs::read_to_string(&log).unwrap_or_default();
        if let Some(addr) = text
            .lines()
            .find_map(|l| l.split(" listening on ").nth(1))
            .and_then(|r| r.split_whitespace().next())
        {
            break addr.to_owned();
        }
        assert!(Instant::now() < deadline, "agent did not start: {text}");
        std::thread::sleep(Duration::from_millis(50));
    };
    Agent {
        child,
        data,
        addr,
        token,
    }
}

struct AcceptAll;

impl client::Handler for AcceptAll {
    type Error = russh::Error;
    async fn check_server_key(&mut self, _: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

async fn connect(agent: &Agent) -> Handle<AcceptAll> {
    let config = Arc::new(client::Config::default());
    client::connect(config, agent.addr.as_str(), AcceptAll)
        .await
        .unwrap()
}

async fn authed(agent: &Agent) -> Handle<AcceptAll> {
    let mut handle = connect(agent).await;
    let auth = handle
        .authenticate_password("cargo-live", &agent.token)
        .await
        .unwrap();
    assert!(auth.success());
    handle
}

/// Waits for the reply to a channel request.
async fn reply(channel: &mut russh::Channel<client::Msg>) -> Option<bool> {
    loop {
        match tokio::time::timeout(Duration::from_secs(10), channel.wait())
            .await
            .expect("no reply")
        {
            Some(ChannelMsg::Success) => return Some(true),
            Some(ChannelMsg::Failure) => return Some(false),
            None => return None,
            Some(_) => {}
        }
    }
}

#[tokio::test]
async fn rejects_other_auth_methods_and_bad_credentials() {
    let agent = start_agent();
    let mut handle = connect(&agent).await;
    assert!(!handle
        .authenticate_none("cargo-live")
        .await
        .unwrap()
        .success());
    let key = PrivateKey::from(russh::keys::ssh_key::private::Ed25519Keypair::from_seed(
        &[7; 32],
    ));
    let key = PrivateKeyWithHashAlg::new(Arc::new(key), None);
    assert!(!handle
        .authenticate_publickey("cargo-live", key)
        .await
        .unwrap()
        .success());

    let mut handle = connect(&agent).await;
    assert!(!handle
        .authenticate_password("root", &agent.token)
        .await
        .unwrap()
        .success());
    let started = Instant::now();
    assert!(!handle
        .authenticate_password("cargo-live", "clt_wrong")
        .await
        .unwrap()
        .success());
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "failed auth must be delayed"
    );
}

#[tokio::test]
async fn refuses_everything_but_the_cargo_live_channel() {
    let agent = start_agent();

    let handle = authed(&agent).await;
    let mut channel = handle.channel_open_session().await.unwrap();
    channel
        .request_pty(true, "xterm", 80, 24, 0, 0, &[(Pty::ECHO, 1)])
        .await
        .unwrap();
    assert_ne!(reply(&mut channel).await, Some(true), "pty accepted");

    let handle = authed(&agent).await;
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.request_shell(true).await.unwrap();
    assert_ne!(reply(&mut channel).await, Some(true), "shell accepted");

    let handle = authed(&agent).await;
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.set_env(true, "LD_PRELOAD", "/x.so").await.unwrap();
    assert_ne!(reply(&mut channel).await, Some(true), "env accepted");

    let handle = authed(&agent).await;
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.exec(true, "id").await.unwrap();
    assert_ne!(reply(&mut channel).await, Some(true), "exec id accepted");

    let handle = authed(&agent).await;
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.request_subsystem(true, "sftp").await.unwrap();
    assert_ne!(reply(&mut channel).await, Some(true), "sftp accepted");

    let handle = authed(&agent).await;
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.agent_forward(true).await.unwrap();
    assert_ne!(
        reply(&mut channel).await,
        Some(true),
        "agent forwarding accepted"
    );

    let handle = authed(&agent).await;
    assert!(handle
        .channel_open_direct_tcpip("127.0.0.1", 22, "127.0.0.1", 1234)
        .await
        .is_err());
    assert!(handle.tcpip_forward("127.0.0.1", 0).await.is_err());

    // The real channel works once per connection.
    let handle = authed(&agent).await;
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.exec(true, "cargo-live").await.unwrap();
    assert_eq!(reply(&mut channel).await, Some(true));
    assert!(handle.channel_open_session().await.is_err());
}

#[tokio::test]
async fn unauthenticated_clients_cannot_open_channels() {
    let agent = start_agent();
    let handle = connect(&agent).await;
    assert!(handle.channel_open_session().await.is_err());
}

/// Reads the server's SSH identification line, or `None` on EOF.
fn banner(stream: &mut std::net::TcpStream) -> Option<String> {
    use std::io::Read;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut buf = [0u8; 64];
    match stream.read(&mut buf) {
        Ok(0) | Err(_) => None,
        Ok(n) => Some(String::from_utf8_lossy(&buf[..n]).into_owned()),
    }
}

#[test]
fn connections_beyond_the_cap_are_closed_immediately() {
    use std::net::TcpStream;
    let agent = start_agent_with(&["--max-connections", "1"]);
    // An unauthenticated connection holds the only slot.
    let mut first = TcpStream::connect(&agent.addr).unwrap();
    assert!(banner(&mut first).unwrap().starts_with("SSH-2.0-"));

    let mut second = TcpStream::connect(&agent.addr).unwrap();
    let started = Instant::now();
    assert_eq!(banner(&mut second), None, "second connection was served");
    assert!(started.elapsed() < Duration::from_secs(5));
    let log = fs::read_to_string(agent.data.path().join("agent.log")).unwrap();
    assert!(
        log.contains("connection refused: 1 connections already open"),
        "{log}"
    );

    // Closing the first connection frees the slot.
    drop(first);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut next = TcpStream::connect(&agent.addr).unwrap();
        if banner(&mut next).is_some() {
            break;
        }
        assert!(Instant::now() < deadline, "slot was not released");
        std::thread::sleep(Duration::from_millis(100));
    }
}
