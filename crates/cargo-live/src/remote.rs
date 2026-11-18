//! The client side of the cargo-live protocol.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use russh::client;
use russh::{ChannelStream, Disconnect};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::mpsc;

use cargo_live_proto::cred::{Credential, CredentialPolicy, ExplainStep, Scope};
use cargo_live_proto::net::{Destination, NetworkPolicy};
use cargo_live_proto::{
    parse_version, write_frame, AgentMsg, BuildRequest, ClientMsg, Entry, FrameReader, SyncStats,
    WaitReason, Welcome, CHUNK_SIZE, PROTOCOL_VERSION,
};

use crate::config::AgentUrl;
use crate::creds::resolve::ClientResolver;
use crate::net::TunnelGate;
use crate::output::{handle_line, Emit};
use crate::ssh::{self, Verifier};
use crate::store::CachedBinary;
use crate::{error, Result};

pub struct Remote {
    handle: client::Handle<Verifier>,
    tunnel: Option<Arc<TunnelGate>>,
    rd: FrameReader<ReadHalf<ChannelStream<client::Msg>>>,
    wr: WriteHalf<ChannelStream<client::Msg>>,
}

pub struct BuildResult {
    pub code: i32,
    pub run_target: Option<(String, Vec<(String, String)>)>,
}

impl Remote {
    /// Connects, authenticates and exchanges Hello/Welcome.
    pub async fn connect(
        url: &AgentUrl,
        pin: Option<&str>,
        token: &str,
        tunnel: Option<Arc<TunnelGate>>,
    ) -> Result<(Self, Welcome)> {
        let conn = ssh::connect(url, pin, token, tunnel.clone()).await?;
        let (rd, wr) = tokio::io::split(conn.stream);
        let mut remote = Self {
            handle: conn.handle,
            tunnel,
            rd: FrameReader::new(rd),
            wr,
        };
        remote
            .send(&ClientMsg::Hello {
                protocol_version: PROTOCOL_VERSION,
                client_version: env!("CARGO_PKG_VERSION").into(),
            })
            .await?;
        let welcome = match remote.recv().await? {
            AgentMsg::Welcome(welcome) => welcome,
            other => return Err(unexpected(&other)),
        };
        if welcome.protocol_version != PROTOCOL_VERSION {
            return Err(error(format!(
                "protocol version mismatch: cargo-live {} speaks protocol {PROTOCOL_VERSION}, \
                 cargo-live-agent {} speaks {}; install matching versions",
                env!("CARGO_PKG_VERSION"),
                welcome.agent_version,
                welcome.protocol_version
            ))
            .into());
        }
        Ok((remote, welcome))
    }

    pub async fn close(mut self) {
        let _ = self.wr.shutdown().await;
        drop((self.rd, self.wr));
        let _ = self
            .handle
            .disconnect(Disconnect::ByApplication, "", "en")
            .await;
    }

    async fn send(&mut self, msg: &ClientMsg) -> Result<()> {
        write_frame(&mut self.wr, msg)
            .await
            .map_err(|e| error(format!("lost connection to the agent: {e}")).into())
    }

    async fn recv(&mut self) -> Result<AgentMsg> {
        received(self.rd.next().await)
    }

    /// Sends the credential policy (rules, `[forward]`, registries).
    pub async fn send_credential_policy(&mut self, policy: CredentialPolicy) -> Result<()> {
        self.send(&ClientMsg::CredentialPolicy(policy)).await
    }

    /// Sends the network policy (`[tunnel]`, `[[network]]`).
    pub async fn send_network_policy(&mut self, network: NetworkPolicy) -> Result<()> {
        self.send(&ClientMsg::NetworkPolicy(network)).await
    }

    /// Dry run of the agent's network decision for `destination`.
    pub async fn net_explain(&mut self, destination: Destination) -> Result<Vec<ExplainStep>> {
        self.send(&ClientMsg::NetExplain { destination }).await?;
        match self.recv().await? {
            AgentMsg::ExplainResult { steps } => Ok(steps),
            other => Err(unexpected(&other)),
        }
    }

    /// Dry run of the agent's credential resolution for `scope`.
    pub async fn explain(&mut self, scope: Scope) -> Result<Vec<ExplainStep>> {
        self.send(&ClientMsg::Explain { scope }).await?;
        match self.recv().await? {
            AgentMsg::ExplainResult { steps } => Ok(steps),
            other => Err(unexpected(&other)),
        }
    }

    /// Locks the remote workspace. Returns the logical and physical remote
    /// source directories.
    pub async fn open(&mut self, workspace_id: &str) -> Result<(String, String)> {
        self.send(&ClientMsg::Open {
            workspace_id: workspace_id.into(),
        })
        .await?;
        loop {
            match self.recv().await? {
                AgentMsg::Waiting {
                    reason: WaitReason::WorkspaceLock,
                } => eprintln!("cargo-live: waiting for remote workspace lock"),
                AgentMsg::Opened {
                    source_dir,
                    source_dir_physical,
                } => return Ok((source_dir, source_dir_physical)),
                other => return Err(unexpected(&other)),
            }
        }
    }

    pub async fn sync(&mut self, entries: Vec<(Entry, PathBuf)>) -> Result<SyncStats> {
        let mut local: HashMap<String, PathBuf> = HashMap::with_capacity(entries.len());
        let mut manifest = Vec::with_capacity(entries.len());
        for (entry, path) in entries {
            local.insert(entry.path.clone(), path);
            manifest.push(entry);
        }
        self.send(&ClientMsg::Manifest { entries: manifest })
            .await?;
        let paths = match self.recv().await? {
            AgentMsg::Need { paths } => paths,
            other => return Err(unexpected(&other)),
        };
        let mut buf = vec![0u8; CHUNK_SIZE];
        for rel in paths {
            let path = local
                .get(&rel)
                .ok_or_else(|| error(format!("the agent asked for an unknown file {rel:?}")))?;
            let ok = match tokio::fs::File::open(path).await {
                Ok(mut file) => loop {
                    match file.read(&mut buf).await {
                        Ok(0) => break true,
                        Ok(n) => self.send(&ClientMsg::FileChunk(buf[..n].to_vec())).await?,
                        Err(e) => {
                            eprintln!("cargo-live: warning: cannot read {}: {e}", path.display());
                            break false;
                        }
                    }
                },
                Err(e) => {
                    eprintln!("cargo-live: warning: cannot read {}: {e}", path.display());
                    false
                }
            };
            self.send(&ClientMsg::FileEnd { ok }).await?;
        }
        match self.recv().await? {
            AgentMsg::Synced(stats) => Ok(stats),
            other => Err(unexpected(&other)),
        }
    }

    /// Runs Cargo remotely, forwarding its output.
    /// Credential requests from the agent are resolved in the background
    /// (one at a time) while output keeps streaming.
    pub async fn build(
        &mut self,
        request: BuildRequest,
        remotes: &[&str],
        local: &Path,
        resolver: Arc<ClientResolver>,
    ) -> Result<BuildResult> {
        let json_output = request.json_output;
        // The agent may open tunnel channels only while the build runs.
        let _tunnels = self.tunnel.clone().map(TunnelsOpen::new);
        self.send(&ClientMsg::Build(request)).await?;
        let (answers_tx, mut answers) = mpsc::channel::<(u64, Result<Credential, String>)>(8);
        let one_at_a_time = Arc::new(std::sync::Mutex::new(()));
        let code = loop {
            let msg = tokio::select! {
                frame = self.rd.next::<AgentMsg>() => received(frame)?,
                Some((id, result)) = answers.recv() => {
                    self.send(&ClientMsg::CredentialResponse { id, result }).await?;
                    continue;
                }
            };
            match msg {
                AgentMsg::CredentialRequest {
                    id,
                    scope,
                    phase: _,
                } => {
                    let (resolver, tx, lock) =
                        (resolver.clone(), answers_tx.clone(), one_at_a_time.clone());
                    tokio::task::spawn_blocking(move || {
                        let _guard = lock.lock();
                        let result = resolver.resolve(&scope);
                        let _ = tx.blocking_send((id, result));
                    });
                }
                AgentMsg::CredentialEvent(event) => {
                    eprintln!("{}", crate::creds::event_line(&event));
                }
                AgentMsg::NetEvent(event) => {
                    eprintln!("{}", crate::net::event_line(&event));
                }
                AgentMsg::Stdout(line) => match handle_line(&line, json_output, remotes, local) {
                    Emit::Stdout(text) => {
                        let mut out = std::io::stdout().lock();
                        writeln!(out, "{text}")?;
                        out.flush()?;
                    }
                    Emit::Stderr(text) => eprint!("{text}"),
                    Emit::Nothing => {}
                },
                AgentMsg::Stderr(bytes) => {
                    let mut err = std::io::stderr().lock();
                    err.write_all(&bytes)?;
                    err.flush()?;
                }
                AgentMsg::Waiting {
                    reason: WaitReason::BuildSlot,
                } => eprintln!("cargo-live: waiting for a free build slot on the agent"),
                AgentMsg::Exit { code } => break code,
                other => return Err(unexpected(&other)),
            }
        };
        if code != 0 || json_output {
            return Ok(BuildResult {
                code,
                run_target: None,
            });
        }
        match self.recv().await? {
            AgentMsg::RunTarget { executable, env } => Ok(BuildResult {
                code,
                run_target: Some((executable, env)),
            }),
            other => Err(unexpected(&other)),
        }
    }

    /// Downloads `executable` into `cached` unless the cached copy matches.
    pub async fn fetch(&mut self, executable: &str, cached: &CachedBinary) -> Result<()> {
        let known = cached.hash();
        self.send(&ClientMsg::Fetch {
            executable: executable.into(),
            known_blake3: known.clone(),
        })
        .await?;
        let (hash, size) = match self.recv().await? {
            AgentMsg::BinaryInfo { blake3, size, .. } => (blake3, size),
            other => return Err(unexpected(&other)),
        };
        if known.as_deref() == Some(hash.as_str()) {
            eprintln!("cargo-live: executable unchanged");
            return Ok(());
        }
        eprintln!("cargo-live: downloading executable ({})", human_bytes(size));
        if let Some(parent) = cached.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = cached
            .path
            .with_extension(format!("partial{}", std::process::id()));
        let result = self.download(&tmp, &hash, size).await;
        match result {
            Ok(()) => cached.install(&tmp, &hash),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                Err(e)
            }
        }
    }

    async fn download(&mut self, tmp: &Path, hash: &str, size: u64) -> Result<()> {
        let mut file = tokio::fs::File::create(tmp).await?;
        let mut hasher = blake3::Hasher::new();
        let mut received = 0u64;
        loop {
            match self.recv().await? {
                AgentMsg::BinaryChunk(data) => {
                    received += data.len() as u64;
                    if received > size {
                        return Err(error("the agent sent more data than announced").into());
                    }
                    hasher.update(&data);
                    file.write_all(&data).await?;
                }
                AgentMsg::BinaryEnd => break,
                other => return Err(unexpected(&other)),
            }
        }
        file.flush().await?;
        file.sync_all().await?;
        if received != size || hasher.finalize().to_hex().as_str() != hash {
            return Err(error("the downloaded executable failed verification").into());
        }
        Ok(())
    }
}

/// Allows tunnel channels until dropped.
struct TunnelsOpen(Arc<TunnelGate>);

impl TunnelsOpen {
    fn new(gate: Arc<TunnelGate>) -> Self {
        gate.activate();
        Self(gate)
    }
}

impl Drop for TunnelsOpen {
    fn drop(&mut self) {
        self.0.deactivate();
    }
}

fn received(
    frame: std::result::Result<Option<AgentMsg>, cargo_live_proto::FrameError>,
) -> Result<AgentMsg> {
    match frame {
        Ok(Some(AgentMsg::Error { message })) => {
            Err(error(format!("remote error: {message}")).into())
        }
        Ok(Some(msg)) => Ok(msg),
        Ok(None) => Err(error("the agent closed the connection unexpectedly").into()),
        Err(e) => Err(error(format!("lost connection to the agent: {e}")).into()),
    }
}

fn unexpected(msg: &AgentMsg) -> Box<dyn std::error::Error + Send + Sync> {
    let name = match msg {
        AgentMsg::Welcome(_) => "Welcome",
        AgentMsg::Error { .. } => "Error",
        AgentMsg::Waiting { .. } => "Waiting",
        AgentMsg::Opened { .. } => "Opened",
        AgentMsg::Need { .. } => "Need",
        AgentMsg::Synced(_) => "Synced",
        AgentMsg::Stdout(_) => "Stdout",
        AgentMsg::Stderr(_) => "Stderr",
        AgentMsg::Exit { .. } => "Exit",
        AgentMsg::RunTarget { .. } => "RunTarget",
        AgentMsg::BinaryInfo { .. } => "BinaryInfo",
        AgentMsg::BinaryChunk(_) => "BinaryChunk",
        AgentMsg::BinaryEnd => "BinaryEnd",
        AgentMsg::CredentialRequest { .. } => "CredentialRequest",
        AgentMsg::CredentialEvent(_) => "CredentialEvent",
        AgentMsg::ExplainResult { .. } => "ExplainResult",
        AgentMsg::NetEvent(_) => "NetEvent",
    };
    error(format!("protocol error: unexpected {name} from the agent")).into()
}

pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Whether a binary built by the agent can run here. `Err` describes why
/// not; `Ok(Some)` is a warning.
pub fn compat_check(
    welcome: &Welcome,
    local_triple: &str,
    local_glibc: Option<&str>,
) -> std::result::Result<Option<String>, String> {
    if welcome.host_triple != local_triple {
        return Err(format!(
            "the agent builds for {} but this machine is {local_triple}; \
             the binary would not run locally",
            welcome.host_triple
        ));
    }
    if !local_triple.contains("-gnu") {
        return Ok(None);
    }
    match (welcome.glibc_version.as_deref(), local_glibc) {
        (Some(remote), Some(local)) => match (parse_version(remote), parse_version(local)) {
            (Some(r), Some(l)) if r > l => Err(format!(
                "the agent links against glibc {remote} but this machine has glibc {local}; \
                 the binary would likely fail to start locally (use an agent image with an \
                 older or equal glibc)"
            )),
            (Some(_), Some(_)) => Ok(None),
            _ => Ok(Some(format!(
                "cannot compare glibc versions {remote:?} and {local:?}"
            ))),
        },
        _ => Ok(Some(
            "cannot determine the glibc version of the agent or this machine".into(),
        )),
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub fn local_glibc() -> Option<String> {
    // SAFETY: gnu_get_libc_version returns a pointer to a static string.
    let version = unsafe { std::ffi::CStr::from_ptr(libc::gnu_get_libc_version()) };
    version.to_str().ok().map(str::to_owned)
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
pub fn local_glibc() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn welcome(triple: &str, glibc: Option<&str>) -> Welcome {
        Welcome {
            protocol_version: PROTOCOL_VERSION,
            agent_version: "0".into(),
            rustc_vv: String::new(),
            host_triple: triple.into(),
            glibc_version: glibc.map(str::to_owned),
        }
    }

    #[test]
    fn compatibility_rules() {
        let gnu = "x86_64-unknown-linux-gnu";
        assert_eq!(
            compat_check(&welcome(gnu, Some("2.31")), gnu, Some("2.39")),
            Ok(None)
        );
        assert_eq!(
            compat_check(&welcome(gnu, Some("2.39")), gnu, Some("2.39")),
            Ok(None)
        );
        assert!(compat_check(&welcome(gnu, Some("2.40")), gnu, Some("2.39")).is_err());
        assert!(compat_check(&welcome("aarch64-unknown-linux-gnu", None), gnu, None).is_err());
        assert!(matches!(
            compat_check(&welcome(gnu, None), gnu, Some("2.39")),
            Ok(Some(_))
        ));
        let musl = "x86_64-unknown-linux-musl";
        assert_eq!(compat_check(&welcome(musl, None), musl, None), Ok(None));
    }

    #[test]
    fn formats_sizes() {
        assert_eq!(human_bytes(10), "10 B");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(3 << 20), "3.0 MiB");
    }
}
