//! Running Cargo for a client.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;

use cargo_live_proto::{
    read_frame, validate_relative_path, write_frame, AgentMsg, BuildCommand, BuildRequest,
    ClientMsg, WaitReason,
};

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

pub fn cargo_command(
    shared: &Shared,
    ws: &Workspace,
    request: &BuildRequest,
    host_triple: &str,
) -> Result<Command> {
    check_args(request)?;
    let cwd = if request.relative_cwd.is_empty() {
        ws.source.clone()
    } else {
        validate_relative_path(&request.relative_cwd)
            .map_err(|e| format!("invalid working directory: {e}"))?;
        let path = mirror::resolve(&ws.source, &request.relative_cwd)?;
        match fs::symlink_metadata(&path) {
            Ok(md) if md.file_type().is_dir() => path,
            _ => return Err("working directory is not a directory in the mirror".into()),
        }
    };
    let mut cmd = Command::new(&shared.settings.cargo);
    if let Some(toolchain) = &request.toolchain {
        cmd.arg(format!("+{toolchain}"));
    }
    match request.command {
        BuildCommand::Run => {
            cmd.arg("run").args(&request.args);
            cmd.arg("--message-format=json");
            cmd.arg("--config")
                .arg(runner_config(host_triple, &shared.agent_exe)?);
            cmd.env(OUT_ENV, &ws.runner_out);
        }
        BuildCommand::Check => {
            cmd.arg("check").args(&request.args);
            if !request
                .args
                .iter()
                .any(|a| a.starts_with("--message-format"))
            {
                cmd.arg("--message-format=json");
            }
        }
    }
    cmd.current_dir(cwd)
        .env("CARGO_TARGET_DIR", &ws.target)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true);
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
    Ok(cmd)
}

pub async fn build<R, W>(
    shared: &Shared,
    ws: &Workspace,
    request: &BuildRequest,
    rd: &mut R,
    wr: &mut W,
) -> Result<Outcome>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let host_triple = host_triple(&shared.settings.cargo).await;
    let mut cmd = cargo_command(shared, ws, request, &host_triple)?;
    let _ = fs::remove_file(&ws.runner_out);

    // Any message or EOF from the client during the build means it gave up.
    let mut incoming = Box::pin(read_frame::<_, ClientMsg>(rd));

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
            tokio::select! {
                permit = shared.builds.acquire() => permit?,
                _ = &mut incoming => return Err("client disconnected".into()),
            }
        }
    };

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

    let result: Result<ExitStatus> = async {
        loop {
            tokio::select! {
                msg = rx.recv() => match msg {
                    Some(msg) => write_frame(wr, &msg).await?,
                    None => break,
                },
                _ = &mut incoming => return Err("client disconnected during the build".into()),
            }
        }
        tokio::select! {
            status = child.wait() => Ok(status?),
            _ = &mut incoming => Err("client disconnected during the build".into()),
        }
    }
    .await;
    let status = match result {
        Ok(status) => status,
        Err(e) => {
            terminate(&mut child, pgid).await;
            return Err(e);
        }
    };
    let code = exit_code(status);
    let run_target = if request.command == BuildCommand::Run && code == 0 {
        Some(read_runner_output(&ws.runner_out)?)
    } else {
        None
    };
    Ok(Outcome { code, run_target })
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
