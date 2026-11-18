//! One `cargo-live` channel: handshake, workspace lock, sync, build, fetch.

use std::fs::{self, File};
use std::net::SocketAddr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use russh::server::Msg;
use russh::ChannelStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use cargo_live_proto::cred::CredentialPolicy;
use cargo_live_proto::{
    is_token_name, is_workspace_id, write_frame, AgentMsg, ClientMsg, FrameReader, SyncStats,
    WaitReason, Welcome, CHUNK_SIZE, PROTOCOL_VERSION,
};

use crate::cred::CredSession;
use crate::mirror;
use crate::server::Shared;
use crate::{job, log, Result};

pub struct Workspace {
    pub source: PathBuf,
    pub target: PathBuf,
    pub tmp: PathBuf,
    pub index: PathBuf,
    pub runner_out: PathBuf,
    pub source_physical: PathBuf,
    /// Holds the exclusive workspace lock until the session ends.
    _lock: File,
}

pub struct Context {
    pub shared: Arc<Shared>,
    pub token: String,
    pub peer: SocketAddr,
    pub workspace: Option<Workspace>,
    pub run_target: Option<String>,
    pub creds: Arc<CredSession>,
}

pub async fn run(shared: Arc<Shared>, token: String, peer: SocketAddr, stream: ChannelStream<Msg>) {
    let (rd, mut wr) = tokio::io::split(stream);
    let mut rd = FrameReader::new(rd);
    let creds = Arc::new(CredSession::new(
        token.clone(),
        shared.settings.creds.clone(),
        shared.settings.paths.data_dir.join("audit.log"),
    ));
    let mut ctx = Context {
        shared,
        token,
        peer,
        workspace: None,
        run_target: None,
        creds,
    };
    if let Err(e) = ctx.serve(&mut rd, &mut wr).await {
        log!("{peer} [{}]: {e}", ctx.token);
        let message = e.to_string();
        let _ = write_frame(&mut wr, &AgentMsg::Error { message }).await;
    }
    let _ = wr.shutdown().await;
    // Dropping the stream closes the channel; dropping the context releases
    // the workspace lock.
    drop(ctx);
    log!("{peer}: session ended");
}

impl Context {
    async fn serve<R, W>(&mut self, rd: &mut FrameReader<R>, wr: &mut W) -> Result<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        match rd.next().await? {
            Some(ClientMsg::Hello {
                protocol_version,
                client_version,
            }) => {
                if protocol_version != PROTOCOL_VERSION {
                    return Err(format!(
                        "protocol version mismatch: client cargo-live {client_version} speaks \
                         protocol {protocol_version}, agent {} speaks {PROTOCOL_VERSION}; \
                         install matching versions of cargo-live and cargo-live-agent",
                        env!("CARGO_PKG_VERSION")
                    )
                    .into());
                }
                log!(
                    "{} [{}]: client cargo-live {client_version}",
                    self.peer,
                    self.token
                );
            }
            Some(_) => return Err("expected Hello".into()),
            None => return Ok(()),
        }
        let welcome = welcome(&self.shared.settings.cargo).await;
        write_frame(wr, &AgentMsg::Welcome(welcome)).await?;

        loop {
            let Some(msg) = rd.next::<ClientMsg>().await? else {
                return Ok(());
            };
            match msg {
                ClientMsg::Open { workspace_id } => {
                    if self.workspace.is_some() {
                        return Err("workspace already open".into());
                    }
                    let ws = self.open(&workspace_id, rd, wr).await?;
                    self.creds.set_workspace(&workspace_id);
                    write_frame(
                        wr,
                        &AgentMsg::Opened {
                            source_dir: path_string(&ws.source)?,
                            source_dir_physical: path_string(&ws.source_physical)?,
                        },
                    )
                    .await?;
                    self.workspace = Some(ws);
                }
                ClientMsg::Manifest { entries } => {
                    let stats = self.sync(entries, rd, wr).await?;
                    write_frame(wr, &AgentMsg::Synced(stats)).await?;
                }
                ClientMsg::Build(request) => {
                    let ws = self.workspace.as_ref().ok_or("no workspace open")?;
                    log!(
                        "{} [{}]: cargo {:?} {:?} in {:?}",
                        self.peer,
                        self.token,
                        request.command,
                        request.args,
                        request.relative_cwd
                    );
                    let outcome =
                        job::build(&self.shared, ws, &request, &self.creds, rd, wr).await?;
                    log!(
                        "{} [{}]: cargo exited with {}",
                        self.peer,
                        self.token,
                        outcome.code
                    );
                    write_frame(wr, &AgentMsg::Exit { code: outcome.code }).await?;
                    self.run_target = None;
                    if let Some((executable, env)) = outcome.run_target {
                        self.run_target = Some(executable.clone());
                        write_frame(wr, &AgentMsg::RunTarget { executable, env }).await?;
                    }
                }
                ClientMsg::Fetch {
                    executable,
                    known_blake3,
                } => {
                    if self.run_target.as_deref() != Some(executable.as_str()) {
                        return Err("can only fetch the executable of the last run".into());
                    }
                    self.fetch(&executable, known_blake3, wr).await?;
                }
                ClientMsg::CredentialPolicy(policy) => {
                    validate_policy(&policy)?;
                    log!(
                        "{} [{}]: credential policy: {} rules, {} registry config entries",
                        self.peer,
                        self.token,
                        policy.rules.len(),
                        policy.registries_config.len()
                    );
                    self.creds.set_policy(policy);
                }
                ClientMsg::Explain { scope } => {
                    let steps = self.creds.explain(&scope);
                    write_frame(wr, &AgentMsg::ExplainResult { steps }).await?;
                }
                other => return Err(format!("unexpected message {}", msg_name(&other)).into()),
            }
        }
    }

    async fn open<R, W>(&self, id: &str, rd: &mut FrameReader<R>, wr: &mut W) -> Result<Workspace>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        if !is_workspace_id(id) {
            return Err("invalid workspace id".into());
        }
        if !is_token_name(&self.token) {
            return Err("invalid token name".into());
        }
        let workspaces = self.shared.settings.paths.data_dir.join("workspaces");
        let token_dir = workspaces.join(&self.token);
        let dir = token_dir.join(id);
        fs::create_dir_all(&workspaces)?;
        for d in [&workspaces, &token_dir, &dir] {
            real_dir(d)?;
        }
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(dir.join("lock"))
            .map_err(|e| format!("cannot open workspace lock: {e}"))?;
        let started = Instant::now();
        let mut announced = false;
        // The client sends nothing until `Opened`: any message, EOF or error
        // while waiting means it gave up (or the connection dropped).
        loop {
            match lock.try_lock() {
                Ok(()) => break,
                Err(fs::TryLockError::WouldBlock) => {
                    if !announced {
                        announced = true;
                        write_frame(
                            wr,
                            &AgentMsg::Waiting {
                                reason: WaitReason::WorkspaceLock,
                            },
                        )
                        .await?;
                    }
                    if started.elapsed() >= self.shared.settings.lock_timeout {
                        return Err(format!(
                            "timed out after {}s waiting for the workspace lock",
                            self.shared.settings.lock_timeout.as_secs()
                        )
                        .into());
                    }
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_millis(200)) => {}
                        _ = rd.next::<ClientMsg>() => {
                            return Err(
                                "client disconnected while waiting for the workspace lock".into()
                            )
                        }
                    }
                }
                Err(fs::TryLockError::Error(e)) => {
                    return Err(format!("cannot lock workspace: {e}").into())
                }
            }
        }
        let source = dir.join("source");
        let target = dir.join("target");
        let tmp = dir.join("tmp");
        for d in [&source, &target, &tmp] {
            real_dir(d)?;
        }
        // Leftovers of an interrupted sync.
        for entry in fs::read_dir(&tmp)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                fs::remove_dir_all(entry.path())?;
            } else {
                fs::remove_file(entry.path())?;
            }
        }
        log!(
            "{} [{}]: opened workspace {}",
            self.peer,
            self.token,
            &id[..12]
        );
        Ok(Workspace {
            source_physical: source.canonicalize()?,
            source,
            target,
            tmp,
            index: dir.join("index"),
            runner_out: dir.join("runner.json"),
            _lock: lock,
        })
    }

    async fn sync<R, W>(
        &self,
        entries: Vec<cargo_live_proto::Entry>,
        rd: &mut FrameReader<R>,
        wr: &mut W,
    ) -> Result<SyncStats>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let ws = self.workspace.as_ref().ok_or("no workspace open")?;
        let source = ws.source.clone();
        let index_path = ws.index.clone();
        let (plan, mut index) = tokio::task::spawn_blocking(move || -> Result<_> {
            let mut index = mirror::load_index(&index_path);
            let plan = mirror::prepare(&source, &mut index, entries)?;
            Ok((plan, index))
        })
        .await??;
        let mut stats = SyncStats {
            deleted: plan.deleted,
            ..Default::default()
        };
        write_frame(
            wr,
            &AgentMsg::Need {
                paths: plan.need.iter().map(|(p, _)| p.clone()).collect(),
            },
        )
        .await?;
        for (i, (rel, kind)) in plan.need.into_iter().enumerate() {
            let tmp = ws.tmp.join(format!("upload-{i}"));
            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)
                .await?;
            let mut size = 0u64;
            let ok = loop {
                match rd.next().await? {
                    Some(ClientMsg::FileChunk(data)) => {
                        size += data.len() as u64;
                        file.write_all(&data).await?;
                    }
                    Some(ClientMsg::FileEnd { ok }) => break ok,
                    Some(other) => {
                        return Err(format!("unexpected {} during upload", msg_name(&other)).into())
                    }
                    None => return Err("client disconnected during upload".into()),
                }
            };
            file.flush().await?;
            drop(file);
            if !ok {
                fs::remove_file(&tmp)?;
                continue;
            }
            let source = ws.source.clone();
            let installed = tokio::task::spawn_blocking(move || {
                mirror::install(&source, &tmp, &rel, &kind).map(|k| (rel, k))
            })
            .await??;
            index.insert(installed.0, installed.1);
            stats.files_written += 1;
            stats.bytes_written += size;
        }
        mirror::save_index(&ws.index, &index)?;
        log!(
            "{} [{}]: synced: {} written ({} bytes), {} deleted",
            self.peer,
            self.token,
            stats.files_written,
            stats.bytes_written,
            stats.deleted
        );
        Ok(stats)
    }

    async fn fetch<W: AsyncWrite + Unpin>(
        &self,
        executable: &str,
        known: Option<String>,
        wr: &mut W,
    ) -> Result<()> {
        let ws = self.workspace.as_ref().ok_or("no workspace open")?;
        let path = checked_executable(&ws.target, Path::new(executable))?;
        let hash_path = path.clone();
        let (hash, size, mode) = tokio::task::spawn_blocking(move || -> Result<_> {
            let mut hasher = blake3::Hasher::new();
            let mut file = File::open(&hash_path)?;
            let size = std::io::copy(&mut file, &mut hasher)?;
            let mode = file.metadata()?.permissions().mode() & 0o777;
            Ok((hasher.finalize().to_hex().to_string(), size, mode))
        })
        .await??;
        write_frame(
            wr,
            &AgentMsg::BinaryInfo {
                blake3: hash.clone(),
                size,
                mode,
            },
        )
        .await?;
        if known.as_deref() == Some(hash.as_str()) {
            return Ok(());
        }
        let mut file = tokio::fs::File::open(&path).await?;
        let mut buf = vec![0u8; CHUNK_SIZE];
        loop {
            let n = file.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            write_frame(wr, &AgentMsg::BinaryChunk(buf[..n].to_vec())).await?;
        }
        write_frame(wr, &AgentMsg::BinaryEnd).await?;
        Ok(())
    }
}

/// Resolves `executable` and checks that it is a regular file inside
/// `target` after resolving symlinks.
pub fn checked_executable(target: &Path, executable: &Path) -> Result<PathBuf> {
    if !executable.is_absolute() {
        return Err("executable path is not absolute".into());
    }
    let target = target.canonicalize()?;
    let path = executable
        .canonicalize()
        .map_err(|e| format!("executable not found: {e}"))?;
    if !path.starts_with(&target) || path == target {
        return Err("executable is outside the workspace target directory".into());
    }
    if !fs::metadata(&path)?.is_file() {
        return Err("executable is not a regular file".into());
    }
    Ok(path)
}

/// Creates `dir` if needed and checks that it is a real directory.
fn real_dir(dir: &Path) -> Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(md) if md.file_type().is_dir() => Ok(()),
        Ok(_) => Err(format!("{} is not a real directory (symlink?)", dir.display()).into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(dir)?;
            real_dir(dir)
        }
        Err(e) => Err(e.into()),
    }
}

fn path_string(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| "agent paths must be UTF-8".into())
}

fn msg_name(msg: &ClientMsg) -> &'static str {
    match msg {
        ClientMsg::Hello { .. } => "Hello",
        ClientMsg::Open { .. } => "Open",
        ClientMsg::Manifest { .. } => "Manifest",
        ClientMsg::FileChunk(_) => "FileChunk",
        ClientMsg::FileEnd { .. } => "FileEnd",
        ClientMsg::Build(_) => "Build",
        ClientMsg::Fetch { .. } => "Fetch",
        ClientMsg::CredentialPolicy(_) => "CredentialPolicy",
        ClientMsg::CredentialResponse { .. } => "CredentialResponse",
        ClientMsg::Explain { .. } => "Explain",
    }
}

/// Checks a client's credential policy. Registry entries become `--config`
/// arguments of remote Cargo, so only registry definitions are accepted.
pub fn validate_policy(policy: &CredentialPolicy) -> Result<()> {
    policy
        .validate()
        .map_err(|e| format!("invalid credential policy: {e}"))?;
    for entry in &policy.registries_config {
        let table: toml::Table = toml::from_str(entry)
            .map_err(|_| format!("invalid registry config entry {entry:?}"))?;
        let ok = table.iter().all(|(key, value)| match key.as_str() {
            "registries" | "source" => true,
            "registry" => value
                .as_table()
                .is_some_and(|t| t.keys().all(|k| k == "default")),
            _ => false,
        });
        if !ok || table.is_empty() {
            return Err(format!(
                "registry config entry {entry:?} may only set registries.*, source.* or \
                 registry.default"
            )
            .into());
        }
        if entry.contains("credential-provider") || entry.contains("token") {
            return Err(format!("registry config entry {entry:?} must not set credentials").into());
        }
    }
    Ok(())
}

async fn welcome(cargo: &Path) -> Welcome {
    let rustc_vv = job::rustc_vv(cargo)
        .await
        .unwrap_or_else(|e| format!("error: {e}"));
    let host_triple =
        job::host_of(&rustc_vv).unwrap_or_else(|| cargo_live_proto::BUILD_TARGET.to_owned());
    Welcome {
        protocol_version: PROTOCOL_VERSION,
        agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        rustc_vv,
        host_triple,
        glibc_version: glibc_version(),
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub fn glibc_version() -> Option<String> {
    // SAFETY: gnu_get_libc_version returns a pointer to a static string.
    let version = unsafe { std::ffi::CStr::from_ptr(libc::gnu_get_libc_version()) };
    version.to_str().ok().map(str::to_owned)
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
pub fn glibc_version() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn executable_must_stay_inside_target() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        fs::create_dir_all(target.join("debug")).unwrap();
        fs::write(target.join("debug/app"), "bin").unwrap();
        fs::write(temp.path().join("secret"), "x").unwrap();
        symlink(temp.path().join("secret"), target.join("debug/escape")).unwrap();
        assert!(checked_executable(&target, &target.join("debug/app")).is_ok());
        assert!(checked_executable(&target, &target.join("debug/escape")).is_err());
        assert!(checked_executable(&target, &target.join("debug/../../secret")).is_err());
        assert!(checked_executable(&target, &target.join("debug")).is_err());
        assert!(checked_executable(&target, Path::new("debug/app")).is_err());
    }

    #[test]
    fn policy_registry_entries_are_restricted() {
        let mut policy = CredentialPolicy::default();
        for good in [
            "registries.\"acme\".index = \"sparse+https://r/\"",
            "source.\"crates-io\".replace-with = \"mirror\"",
            "registry.default = \"acme\"",
        ] {
            policy.registries_config = vec![good.into()];
            assert!(validate_policy(&policy).is_ok(), "{good}");
        }
        for bad in [
            "build.rustflags = [\"-C\", \"x\"]",
            "registry.token = \"x\"",
            "registries.acme.token = \"x\"",
            "registries.acme.credential-provider = \"/bin/evil\"",
            "not toml",
        ] {
            policy.registries_config = vec![bad.into()];
            assert!(validate_policy(&policy).is_err(), "{bad}");
        }
    }

    #[test]
    fn real_dir_refuses_symlinks() {
        let temp = tempfile::tempdir().unwrap();
        let elsewhere = temp.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        symlink(&elsewhere, temp.path().join("link")).unwrap();
        assert!(real_dir(&temp.path().join("link")).is_err());
        assert!(real_dir(&temp.path().join("new")).is_ok());
        assert!(temp.path().join("new").is_dir());
    }
}
