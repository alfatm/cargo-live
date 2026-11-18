//! The per-job credential broker.
//!
//! For each build step that may receive credentials the agent creates a
//! Unix socket `<ws>/tmp/cred-<id>.sock` (mode 0600) and a random nonce,
//! and passes both to Cargo as `CARGO_LIVE_BROKER` and
//! `CARGO_LIVE_BROKER_NONCE`. The helper modes of the agent binary (git
//! credential helper, Cargo credential provider, Docker credential helper)
//! connect, send `{"nonce", "scope"}` as one JSON line and get
//! `{"Ok": credential}` or `{"Err": message}` back. The socket and the
//! per-step directory are removed when the step ends.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};
use zeroize::Zeroizing;

use cargo_live_proto::cred::{Credential, Phase, Scope};

use super::resolve::{CredSession, ToClient};
use crate::{log, Result};

pub const BROKER_ENV: &str = "CARGO_LIVE_BROKER";
pub const NONCE_ENV: &str = "CARGO_LIVE_BROKER_NONCE";
/// argv[0] that makes the agent binary a Docker credential helper.
pub const DOCKER_HELPER_NAME: &str = "docker-credential-cargo-live";
const MAX_REQUEST: u64 = 64 * 1024;
/// Generic answer to helpers; details go to the logs and the client.
pub const GENERIC_ERROR: &str = "no credential available (see the cargo-live output)";

#[derive(Serialize, Deserialize)]
pub struct BrokerRequest {
    pub nonce: String,
    pub scope: Scope,
}

#[derive(Serialize, Deserialize)]
pub enum BrokerReply {
    Ok(Credential),
    Err(String),
}

pub struct Broker {
    socket: PathBuf,
    dir: PathBuf,
    nonce: Zeroizing<String>,
    task: JoinHandle<()>,
}

fn random_hex(bytes: usize) -> Result<String> {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).map_err(|e| format!("OS random number generator failed: {e}"))?;
    Ok(cargo_live_proto::hex(&buf))
}

/// Unix socket paths are limited to ~108 bytes; longer ones are reached
/// through `/proc/self/fd/<dirfd>/<name>`. The returned file must stay open
/// while the returned path is used.
pub fn short_socket_path(path: &Path) -> std::io::Result<(PathBuf, Option<fs::File>)> {
    if path.as_os_str().len() < 100 || !cfg!(target_os = "linux") {
        return Ok((path.to_owned(), None));
    }
    let parent = path.parent().unwrap_or(Path::new("."));
    let name = path.file_name().unwrap_or_default();
    let dir = fs::File::open(parent)?;
    use std::os::fd::AsRawFd;
    let short = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd())).join(name);
    Ok((short, Some(dir)))
}

impl Broker {
    /// Starts a broker for one build step.
    pub fn start(
        tmp: &Path,
        phase: Phase,
        session: Arc<CredSession>,
        client: mpsc::Sender<ToClient>,
        agent_exe: &Path,
    ) -> Result<Self> {
        let id = random_hex(8)?;
        let socket = tmp.join(format!("cred-{id}.sock"));
        let dir = tmp.join(format!("cred-{id}"));
        fs::create_dir(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        // Docker: DOCKER_CONFIG with credsStore, and the helper on PATH.
        fs::create_dir(dir.join("docker"))?;
        fs::write(
            dir.join("docker/config.json"),
            "{\"credsStore\":\"cargo-live\"}\n",
        )?;
        fs::create_dir(dir.join("bin"))?;
        symlink(agent_exe, dir.join("bin").join(DOCKER_HELPER_NAME))?;

        let (bind_path, _dirfd) = short_socket_path(&socket)?;
        let listener = UnixListener::bind(&bind_path)
            .map_err(|e| format!("cannot create credential socket: {e}"))?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        let mut nonce_bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut nonce_bytes[..])
            .map_err(|e| format!("OS random number generator failed: {e}"))?;
        let nonce = Zeroizing::new(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&nonce_bytes[..]),
        );
        let task = tokio::spawn(accept_loop(listener, nonce.clone(), phase, session, client));
        Ok(Self {
            socket,
            dir,
            nonce,
            task,
        })
    }

    /// Adds the broker environment to `cmd` and returns the Cargo
    /// `--config` arguments that register the credential provider.
    pub fn configure(
        &self,
        cmd: &mut Command,
        agent_exe: &Path,
        git_hosts: &[String],
    ) -> Result<Vec<String>> {
        let exe = agent_exe
            .to_str()
            .ok_or("agent executable path is not UTF-8")?;
        cmd.env(BROKER_ENV, &self.socket)
            .env(NONCE_ENV, self.nonce.as_str())
            .env("CARGO_NET_GIT_FETCH_WITH_CLI", "true")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("DOCKER_CONFIG", self.dir.join("docker"));
        let path = std::env::var_os("PATH").unwrap_or_default();
        let mut paths = vec![self.dir.join("bin")];
        paths.extend(std::env::split_paths(&path));
        cmd.env("PATH", std::env::join_paths(paths)?);
        for (k, v) in git_config_env(exe, git_hosts, std::env::var("GIT_CONFIG_COUNT").ok()) {
            cmd.env(k, v);
        }
        let quote = |s: &str| toml::Value::String(s.to_owned()).to_string();
        Ok(vec![
            "--config".into(),
            format!(
                "credential-alias.cargo-live=[{}, {}, {}]",
                quote(exe),
                quote("__cred"),
                quote("cargo")
            ),
            "--config".into(),
            "registry.global-credential-providers=[\"cargo-live\"]".into(),
        ])
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        // Aborting the accept loop drops its JoinSet, which aborts every
        // connection still being served.
        self.task.abort();
        let _ = fs::remove_file(&self.socket);
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Single-quotes `s` for the shell git runs `!` helpers with.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// `GIT_CONFIG_*` entries: clear inherited credential helpers, use the
/// agent as the only helper, match credentials per repository path, and
/// rewrite SSH URLs of `hosts` to HTTPS. Existing entries (`count`) are
/// kept; ours are appended after them.
pub fn git_config_env(exe: &str, hosts: &[String], count: Option<String>) -> Vec<(String, String)> {
    let mut entries = vec![
        ("credential.helper".to_owned(), String::new()),
        (
            "credential.helper".to_owned(),
            format!("!{} __cred git", shell_quote(exe)),
        ),
        ("credential.useHttpPath".to_owned(), "true".to_owned()),
    ];
    for host in hosts {
        let key = format!("url.https://{host}/.insteadOf");
        entries.push((key.clone(), format!("git@{host}:")));
        entries.push((key, format!("ssh://git@{host}/")));
    }
    let base: usize = count.and_then(|c| c.trim().parse().ok()).unwrap_or(0);
    let mut env = Vec::new();
    for (i, (k, v)) in entries.iter().enumerate() {
        env.push((format!("GIT_CONFIG_KEY_{}", base + i), k.clone()));
        env.push((format!("GIT_CONFIG_VALUE_{}", base + i), v.clone()));
    }
    env.push((
        "GIT_CONFIG_COUNT".into(),
        (base + entries.len()).to_string(),
    ));
    env
}

async fn accept_loop(
    listener: UnixListener,
    nonce: Zeroizing<String>,
    phase: Phase,
    session: Arc<CredSession>,
    client: mpsc::Sender<ToClient>,
) {
    let nonce = Arc::new(nonce);
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    connections.spawn(serve(
                        stream,
                        nonce.clone(),
                        phase,
                        session.clone(),
                        client.clone(),
                    ));
                }
                Err(e) => {
                    log!("credential socket: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

async fn serve(
    stream: UnixStream,
    nonce: Arc<Zeroizing<String>>,
    phase: Phase,
    session: Arc<CredSession>,
    client: mpsc::Sender<ToClient>,
) {
    let (rd, mut wr) = stream.into_split();
    let mut line = Zeroizing::new(String::new());
    let mut reader = tokio::io::BufReader::new(rd.take(MAX_REQUEST));
    let read = tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line)).await;
    if !matches!(read, Ok(Ok(n)) if n > 0) {
        return;
    }
    let reply = match serde_json::from_str::<BrokerRequest>(&line) {
        Ok(req) if bool::from(req.nonce.as_bytes().ct_eq(nonce.as_bytes())) => {
            match session.resolve(&req.scope, phase, &client).await {
                Some(credential) => BrokerReply::Ok(credential),
                None => BrokerReply::Err(GENERIC_ERROR.into()),
            }
        }
        Ok(_) => {
            log!("credential socket: request with a wrong nonce refused");
            BrokerReply::Err("invalid broker nonce".into())
        }
        Err(_) => BrokerReply::Err("malformed broker request".into()),
    };
    let Ok(out) = serde_json::to_string(&reply) else {
        return;
    };
    let mut out = Zeroizing::new(out);
    out.push('\n');
    let _ = wr.write_all(out.as_bytes()).await;
    let _ = wr.shutdown().await;
}

/// Client side, used by the helper modes: asks the broker named in the
/// environment for a credential.
pub fn request(scope: &Scope) -> std::result::Result<Credential, String> {
    let socket = std::env::var_os(BROKER_ENV).ok_or(
        "no credential broker is available to this process (CARGO_LIVE_BROKER is not set)",
    )?;
    let nonce =
        Zeroizing::new(std::env::var(NONCE_ENV).map_err(|_| "CARGO_LIVE_BROKER_NONCE is not set")?);
    request_at(Path::new(&socket), &nonce, scope)
}

pub fn request_at(
    socket: &Path,
    nonce: &str,
    scope: &Scope,
) -> std::result::Result<Credential, String> {
    let (path, _dirfd) =
        short_socket_path(socket).map_err(|e| format!("credential broker: {e}"))?;
    let mut stream = std::os::unix::net::UnixStream::connect(&path)
        .map_err(|e| format!("cannot connect to the credential broker: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(300)))
        .map_err(|e| e.to_string())?;
    let request = BrokerRequest {
        nonce: nonce.to_owned(),
        scope: scope.clone(),
    };
    let mut line = Zeroizing::new(serde_json::to_string(&request).map_err(|e| e.to_string())?);
    line.push('\n');
    stream
        .write_all(line.as_bytes())
        .map_err(|e| format!("credential broker: {e}"))?;
    let mut answer = Zeroizing::new(String::new());
    BufReader::new(stream)
        .read_line(&mut answer)
        .map_err(|e| format!("credential broker: {e}"))?;
    match serde_json::from_str::<BrokerReply>(&answer) {
        Ok(BrokerReply::Ok(c)) => Ok(c),
        Ok(BrokerReply::Err(e)) => Err(e),
        Err(_) => Err("credential broker closed the connection".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cred::config::{AgentCreds, Provider, ProviderKind, SecretRef};
    use cargo_live_proto::cred::{CredMatch, Kind};

    #[tokio::test(flavor = "multi_thread")]
    async fn broker_serves_with_nonce_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        // A long directory name exercises the /proc/self/fd path.
        let tmp = dir.path().join("x".repeat(90));
        fs::create_dir(&tmp).unwrap();
        fs::write(dir.path().join("secret"), "s3cr3t\n").unwrap();
        let creds = AgentCreds {
            providers: vec![Provider {
                name: "f".into(),
                matcher: CredMatch {
                    kind: Kind::Docker,
                    host: Some("ghcr.io".into()),
                    path: None,
                    registry: None,
                    index: None,
                },
                allow_tokens: vec!["*".into()],
                phases: None,
                kind: ProviderKind::File {
                    path: SecretRef::File(dir.path().join("secret")),
                    username: Some("bot".into()),
                },
            }],
            ..Default::default()
        };
        let session = Arc::new(CredSession::new(
            "t".into(),
            Arc::new(creds),
            dir.path().join("audit.log"),
        ));
        let (tx, mut rx) = mpsc::channel(8);
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        let broker =
            Broker::start(&tmp, Phase::Fetch, session, tx, Path::new("/bin/true")).unwrap();
        let socket = broker.socket.clone();
        let mode = fs::metadata(&socket).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(socket.as_os_str().len() > 108);
        let nonce = broker.nonce.to_string();
        let s = socket.clone();
        let (good, bad, missing) = tokio::task::spawn_blocking(move || {
            (
                request_at(&s, &nonce, &Scope::docker("ghcr.io")),
                request_at(&s, "wrong", &Scope::docker("ghcr.io")),
                request_at(&s, &nonce, &Scope::docker("quay.io")),
            )
        })
        .await
        .unwrap();
        let good = good.unwrap();
        assert_eq!(
            (good.secret.expose(), good.username.as_deref()),
            ("s3cr3t", Some("bot"))
        );
        assert_eq!(bad.unwrap_err(), "invalid broker nonce");
        assert_eq!(missing.unwrap_err(), GENERIC_ERROR);
        let link = broker.dir.join("bin").join(DOCKER_HELPER_NAME);
        assert_eq!(fs::read_link(&link).unwrap(), Path::new("/bin/true"));
        let bdir = broker.dir.clone();
        drop(broker);
        assert!(!socket.exists() && !bdir.exists());
    }

    #[test]
    fn git_config_appends_after_existing_entries() {
        let env = git_config_env(
            "/opt/my agent/cargo-live-agent",
            &["github.com".into(), "gitlab.acme.dev".into()],
            Some("2".into()),
        );
        let get = |k: &str| {
            env.iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(get("GIT_CONFIG_KEY_2"), Some("credential.helper"));
        assert_eq!(get("GIT_CONFIG_VALUE_2"), Some(""));
        assert_eq!(
            get("GIT_CONFIG_VALUE_3"),
            Some("!'/opt/my agent/cargo-live-agent' __cred git")
        );
        assert_eq!(get("GIT_CONFIG_KEY_4"), Some("credential.useHttpPath"));
        assert_eq!(
            get("GIT_CONFIG_KEY_5"),
            Some("url.https://github.com/.insteadOf")
        );
        assert_eq!(get("GIT_CONFIG_VALUE_5"), Some("git@github.com:"));
        assert_eq!(get("GIT_CONFIG_VALUE_6"), Some("ssh://git@github.com/"));
        assert_eq!(
            get("GIT_CONFIG_VALUE_8"),
            Some("ssh://git@gitlab.acme.dev/")
        );
        assert_eq!(get("GIT_CONFIG_COUNT"), Some("9"));
        assert!(get("GIT_CONFIG_KEY_0").is_none());
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
    }
}
