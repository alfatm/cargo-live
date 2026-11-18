//! Running Cargo for a client.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot};

use cargo_live_proto::cred::{Credential, Phase};
use cargo_live_proto::{
    validate_relative_path, write_frame, AgentMsg, BuildCommand, BuildRequest, ClientMsg,
    FrameReader, WaitReason,
};

use crate::cred::broker::{BROKER_ENV, NONCE_ENV};
use crate::cred::{Broker, CredSession, ToClient};
use crate::runner::{RunnerOutput, OUT_ENV};
use crate::server::Shared;
use crate::session::Workspace;
use crate::{mirror, Result};

pub struct Outcome {
    pub code: i32,
    pub run_target: Option<(String, Vec<(String, String)>)>,
}

/// Arguments that would break the agent's assumptions.
pub fn check_args(request: &BuildRequest) -> Result<()> {
    if let Some(toolchain) = &request.toolchain {
        if toolchain.is_empty()
            || !toolchain
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        {
            return Err("invalid toolchain name".into());
        }
    }
    for arg in &request.args {
        let forbidden = ["--target-dir", "--manifest-path"]
            .iter()
            .any(|opt| arg == opt || arg.starts_with(&format!("{opt}=")));
        let message_format = arg == "--message-format" || arg.starts_with("--message-format=");
        if arg == "--" || forbidden || (request.command == BuildCommand::Run && message_format) {
            return Err(format!("unsupported Cargo argument {arg:?}").into());
        }
    }
    Ok(())
}

/// TOML for `--config`: makes the agent Cargo's runner for the host target.
pub fn runner_config(host_triple: &str, agent_exe: &Path) -> Result<String> {
    let exe = agent_exe
        .to_str()
        .ok_or("agent executable path is not UTF-8")?;
    let quote = |s: &str| toml::Value::String(s.to_owned()).to_string();
    Ok(format!(
        "target.{}.runner=[{}, {}]",
        quote(host_triple),
        quote(exe),
        quote("__runner")
    ))
}

/// Cargo's working directory in the mirror.
fn working_dir(ws: &Workspace, request: &BuildRequest) -> Result<PathBuf> {
    if request.relative_cwd.is_empty() {
        return Ok(ws.source.clone());
    }
    validate_relative_path(&request.relative_cwd)
        .map_err(|e| format!("invalid working directory: {e}"))?;
    let path = mirror::resolve(&ws.source, &request.relative_cwd)?;
    match fs::symlink_metadata(&path) {
        Ok(md) if md.file_type().is_dir() => Ok(path),
        _ => Err("working directory is not a directory in the mirror".into()),
    }
}

/// A Cargo command with the settings shared by both steps.
fn base_command(shared: &Shared, ws: &Workspace, request: &BuildRequest, cwd: &Path) -> Command {
    let mut cmd = Command::new(&shared.settings.cargo);
    if let Some(toolchain) = &request.toolchain {
        cmd.arg(format!("+{toolchain}"));
    }
    cmd.current_dir(cwd)
        .env("CARGO_TARGET_DIR", &ws.target)
        // Only a broker for this step may set these.
        .env_remove(BROKER_ENV)
        .env_remove(NONCE_ENV)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true);
    // Root secrets of `env` providers must not reach build scripts.
    for var in shared.settings.creds.secret_env_vars() {
        cmd.env_remove(var);
    }
    #[cfg(target_os = "linux")]
    // SAFETY: prctl is async-signal-safe.
    unsafe {
        cmd.pre_exec(|| {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd
}

/// The user's options that also apply to `cargo fetch`.
pub fn fetch_args(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--locked" | "--frozen" | "--offline" => out.push(arg.clone()),
            "--config" | "-Z" => {
                out.push(arg.clone());
                if let Some(value) = iter.next() {
                    out.push(value.clone());
                }
            }
            a if a.starts_with("--config=") || (a.starts_with("-Z") && a.len() > 2) => {
                out.push(arg.clone())
            }
            _ => {}
        }
    }
    out
}

fn config_args(entries: &[String]) -> Vec<String> {
    entries
        .iter()
        .flat_map(|e| ["--config".to_owned(), e.clone()])
        .collect()
}

/// Step 1: `cargo fetch` with the forwarded options.
pub fn fetch_command(
    shared: &Shared,
    ws: &Workspace,
    request: &BuildRequest,
    cwd: &Path,
    registries: &[String],
) -> Command {
    let mut cmd = base_command(shared, ws, request, cwd);
    cmd.arg("fetch")
        .args(config_args(registries))
        .args(fetch_args(&request.args));
    cmd
}

/// Step 2: `cargo run` / `cargo check`.
pub fn cargo_command(
    shared: &Shared,
    ws: &Workspace,
    request: &BuildRequest,
    host_triple: &str,
    cwd: &Path,
    registries: &[String],
) -> Result<Command> {
    let mut cmd = base_command(shared, ws, request, cwd);
    match request.command {
        BuildCommand::Run => {
            cmd.arg("run")
                .args(config_args(registries))
                .args(&request.args);
            cmd.arg("--message-format=json");
            cmd.arg("--config")
                .arg(runner_config(host_triple, &shared.agent_exe)?);
            cmd.env(OUT_ENV, &ws.runner_out);
        }
        BuildCommand::Check => {
            cmd.arg("check")
                .args(config_args(registries))
                .args(&request.args);
            if !request
                .args
                .iter()
                .any(|a| a.starts_with("--message-format"))
            {
                cmd.arg("--message-format=json");
            }
        }
    }
    Ok(cmd)
}

pub async fn build<R, W>(
    shared: &Shared,
    ws: &Workspace,
    request: &BuildRequest,
    creds: &Arc<CredSession>,
    rd: &mut FrameReader<R>,
    wr: &mut W,
) -> Result<Outcome>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    check_args(request)?;
    let host_triple = host_triple(&shared.settings.cargo).await;
    let cwd = working_dir(ws, request)?;
    let registries = creds.registries_config();
    let _ = fs::remove_file(&ws.runner_out);

    let _permit = match shared.builds.try_acquire() {
        Ok(permit) => permit,
        Err(_) => {
            write_frame(
                wr,
                &AgentMsg::Waiting {
                    reason: WaitReason::BuildSlot,
                },
            )
            .await?;
            // Any message or EOF from the client while waiting means it
            // gave up.
            tokio::select! {
                permit = shared.builds.acquire() => permit?,
                _ = rd.next::<ClientMsg>() => return Err("client disconnected".into()),
            }
        }
    };

    // Step 1: `cargo fetch` with the broker open. No third-party code runs
    // in this step.
    let mut fetch = fetch_command(shared, ws, request, &cwd, &registries);
    let (client_tx, client_rx) = mpsc::channel(16);
    let broker = Broker::start(
        &ws.tmp,
        Phase::Fetch,
        creds.clone(),
        client_tx,
        &shared.agent_exe,
    )?;
    let extra = broker.configure(&mut fetch, &shared.agent_exe, &creds.git_hosts())?;
    fetch.args(extra);
    let code = run_step(shared, fetch, client_rx, rd, wr).await;
    drop(broker);
    let code = code?;
    if code != 0 {
        let message = format!(
            "cargo-live-agent: `cargo fetch` failed (exit code {code}); the build was not started\n"
        );
        write_frame(wr, &AgentMsg::Stderr(message.into_bytes())).await?;
        return Ok(Outcome {
            code,
            run_target: None,
        });
    }

    // Step 2: the build, which runs build scripts and proc macros. The
    // broker is only open if some scope opted into the build phase; each
    // request is still checked against that scope's phases.
    let mut cmd = cargo_command(shared, ws, request, &host_triple, &cwd, &registries)?;
    let (client_tx, client_rx) = mpsc::channel(16);
    let broker = if creds.build_phase_enabled() {
        let broker = Broker::start(
            &ws.tmp,
            Phase::Build,
            creds.clone(),
            client_tx,
            &shared.agent_exe,
        )?;
        let extra = broker.configure(&mut cmd, &shared.agent_exe, &creds.git_hosts())?;
        cmd.args(extra);
        Some(broker)
    } else {
        drop(client_tx);
        None
    };
    let code = run_step(shared, cmd, client_rx, rd, wr).await;
    drop(broker);
    let code = code?;
    let run_target = if request.command == BuildCommand::Run && code == 0 {
        Some(read_runner_output(&ws.runner_out)?)
    } else {
        None
    };
    Ok(Outcome { code, run_target })
}

/// Runs one Cargo step, streaming its output and relaying credential
/// requests to the client. Returns Cargo's exit code.
async fn run_step<R, W>(
    shared: &Shared,
    mut cmd: Command,
    mut client_rx: mpsc::Receiver<ToClient>,
    rd: &mut FrameReader<R>,
    wr: &mut W,
) -> Result<i32>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("cannot start {}: {e}", shared.settings.cargo.display()))?;
    let pgid = child.id().map(|id| id as i32);
    let (tx, mut rx) = mpsc::channel::<AgentMsg>(64);
    let stdout = child.stdout.take().expect("piped");
    let stderr = child.stderr.take().expect("piped");
    let out_tx = tx.clone();
    tokio::spawn(async move {
        let mut lines = BufReader::new(stdout).split(b'\n');
        while let Ok(Some(line)) = lines.next_segment().await {
            let line = String::from_utf8_lossy(&line)
                .trim_end_matches('\r')
                .to_owned();
            if out_tx.send(AgentMsg::Stdout(line)).await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        // Line-based so that Cargo's "Running `<agent> __runner ...`" status
        // line, an implementation detail, can be dropped.
        let mut lines = BufReader::new(stderr).split(b'\n');
        while let Ok(Some(mut line)) = lines.next_segment().await {
            if is_runner_status(&line) {
                continue;
            }
            line.push(b'\n');
            if tx.send(AgentMsg::Stderr(line)).await.is_err() {
                break;
            }
        }
    });

    let mut pending: HashMap<u64, oneshot::Sender<std::result::Result<Credential, String>>> =
        HashMap::new();
    let mut next_id = 0u64;
    let result: Result<ExitStatus> = async {
        let mut output_open = true;
        let mut status = None;
        loop {
            if let (false, Some(status)) = (output_open, status) {
                return Ok(status);
            }
            tokio::select! {
                msg = rx.recv(), if output_open => match msg {
                    Some(msg) => write_frame(wr, &msg).await?,
                    None => output_open = false,
                },
                exited = child.wait(), if status.is_none() => status = Some(exited?),
                Some(call) = client_rx.recv() => match call {
                    ToClient::Request { scope, phase, reply } => {
                        next_id += 1;
                        pending.insert(next_id, reply);
                        write_frame(wr, &AgentMsg::CredentialRequest { id: next_id, scope, phase })
                            .await?;
                    }
                    ToClient::Event(event) => {
                        write_frame(wr, &AgentMsg::CredentialEvent(event)).await?
                    }
                },
                frame = rd.next::<ClientMsg>() => match frame {
                    Ok(Some(ClientMsg::CredentialResponse { id, result })) => {
                        if let Some(reply) = pending.remove(&id) {
                            let _ = reply.send(result);
                        }
                    }
                    Ok(Some(_)) => return Err("unexpected message from the client during the build".into()),
                    Ok(None) | Err(_) => return Err("client disconnected during the build".into()),
                },
            }
        }
    }
    .await;
    match result {
        Ok(status) => Ok(exit_code(status)),
        Err(e) => {
            terminate(&mut child, pgid).await;
            Err(e)
        }
    }
}

fn is_runner_status(line: &[u8]) -> bool {
    let line = String::from_utf8_lossy(line);
    let line = line.trim_start();
    line.starts_with("Running `") && line.contains(" __runner ")
}

/// SIGTERM to Cargo's process group, SIGKILL after five seconds.
async fn terminate(child: &mut Child, pgid: Option<i32>) {
    let Some(pgid) = pgid else {
        let _ = child.kill().await;
        return;
    };
    // SAFETY: plain kill(2) on our own child's process group, which cannot
    // be reused while the unreaped child exists.
    unsafe { libc::kill(-pgid, libc::SIGTERM) };
    if tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .is_err()
    {
        unsafe { libc::kill(-pgid, libc::SIGKILL) };
        let _ = child.wait().await;
    }
    // Stragglers such as rustc processes still in the group.
    unsafe { libc::kill(-pgid, libc::SIGKILL) };
}

fn exit_code(status: ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .or_else(|| status.signal().map(|s| 128 + s))
        .unwrap_or(1)
}

fn read_runner_output(path: &Path) -> Result<(String, Vec<(String, String)>)> {
    let data = fs::read(path).map_err(|_| {
        "cargo finished without starting the program; cargo-live needs a binary target \
         built for the agent's host (cross-compilation, build.target and custom runners \
         are not supported)"
    })?;
    let _ = fs::remove_file(path);
    let output: RunnerOutput = serde_json::from_slice(&data)?;
    let own: HashMap<String, String> = std::env::vars().collect();
    let env = output
        .env
        .into_iter()
        // Keep what Cargo set for the program, not the agent's own settings.
        .filter(|(k, v)| own.get(k) != Some(v))
        .filter(|(k, _)| k != OUT_ENV && k != "CARGO_TARGET_DIR" && !k.starts_with("CARGO_LIVE_"))
        .collect();
    Ok((output.executable, env))
}

/// Output of the agent toolchain's `rustc -vV`.
pub async fn rustc_vv(cargo: &Path) -> std::result::Result<String, String> {
    let rustc = cargo
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.join("rustc"))
        .filter(|p| p.is_file())
        .unwrap_or_else(|| "rustc".into());
    let output = tokio::time::timeout(
        Duration::from_secs(60),
        Command::new(&rustc)
            .arg("-vV")
            .stdin(Stdio::null())
            .output(),
    )
    .await;
    match output {
        Ok(Ok(out)) if out.status.success() => {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        }
        Ok(Ok(out)) => Err(format!(
            "{} -vV failed: {}",
            rustc.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        )),
        Ok(Err(e)) => Err(format!("cannot run {}: {e}", rustc.display())),
        Err(_) => Err(format!("{} -vV timed out", rustc.display())),
    }
}

pub fn host_of(rustc_vv: &str) -> Option<String> {
    rustc_vv
        .lines()
        .find_map(|l| l.strip_prefix("host: ").map(|h| h.trim().to_owned()))
}

/// The host triple of the agent's toolchain.
pub async fn host_triple(cargo: &Path) -> String {
    rustc_vv(cargo)
        .await
        .ok()
        .and_then(|vv| host_of(&vv))
        .unwrap_or_else(|| cargo_live_proto::BUILD_TARGET.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(command: BuildCommand, args: &[&str]) -> BuildRequest {
        BuildRequest {
            command,
            toolchain: None,
            args: args.iter().map(|s| s.to_string()).collect(),
            relative_cwd: String::new(),
            json_output: false,
        }
    }

    #[test]
    fn rejects_dangerous_arguments() {
        assert!(check_args(&request(BuildCommand::Run, &["--release", "-p", "x"])).is_ok());
        for args in [
            &["--"][..],
            &["--target-dir", "/tmp"],
            &["--manifest-path=/etc/Cargo.toml"],
            &["--message-format=short"],
        ] {
            assert!(
                check_args(&request(BuildCommand::Run, args)).is_err(),
                "{args:?}"
            );
        }
        assert!(check_args(&request(BuildCommand::Check, &["--message-format=json"])).is_ok());
        let mut r = request(BuildCommand::Run, &[]);
        r.toolchain = Some("nightly; rm -rf /".into());
        assert!(check_args(&r).is_err());
    }

    #[test]
    fn fetch_gets_only_the_relevant_options() {
        let args: Vec<String> = [
            "--release",
            "--locked",
            "--config",
            "a=1",
            "--config=b=2",
            "-Z",
            "x",
            "-Zy",
            "--bin",
            "app",
            "--offline",
            "--frozen",
            "-p",
            "z",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            fetch_args(&args),
            [
                "--locked",
                "--config",
                "a=1",
                "--config=b=2",
                "-Z",
                "x",
                "-Zy",
                "--offline",
                "--frozen"
            ]
        );
    }

    #[test]
    fn hides_runner_status_line() {
        assert!(is_runner_status(
            b"     Running `/usr/bin/cargo-live-agent __runner /t/app`"
        ));
        assert!(!is_runner_status(b"   Compiling app v0.1.0"));
    }

    #[test]
    fn runner_config_is_valid_toml() {
        let config = runner_config(
            "x86_64-unknown-linux-gnu",
            Path::new("/opt/a \"b\"/cargo-live-agent"),
        )
        .unwrap();
        let value: toml::Table = toml::from_str(&config).unwrap();
        let runner = &value["target"]["x86_64-unknown-linux-gnu"]["runner"];
        assert_eq!(
            runner.as_array().unwrap()[0].as_str().unwrap(),
            "/opt/a \"b\"/cargo-live-agent"
        );
        assert_eq!(runner.as_array().unwrap()[1].as_str().unwrap(), "__runner");
    }
}
