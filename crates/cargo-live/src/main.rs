mod config;
mod creds;
mod net;
mod output;
mod remote;
mod ssh;
mod store;
mod walk;

use std::env;
use std::ffi::{OsStr, OsString};
use std::io::{self, BufRead, IsTerminal};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::Arc;

use serde::Deserialize;

use cargo_live_proto::{sha256_hex, BuildCommand, BuildRequest, BUILD_TARGET, TOKEN_PREFIX};

use cargo_live_proto::cred::{parse_git_target, CredentialPolicy, Scope};
use cargo_live_proto::net::{Destination, NetworkPolicy, DEFAULT_TUNNEL_PORT};
use config::{AgentUrl, Config};
use creds::registries::LocalCargoConfig;
use creds::resolve::ClientResolver;
use creds::UserConfig;
use remote::Remote;
use store::{CachedBinary, Credentials};

pub type Result<T, E = Box<dyn std::error::Error + Send + Sync>> = std::result::Result<T, E>;

pub fn error(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

const SKIP_COMPAT_ENV: &str = "CARGO_LIVE_SKIP_COMPAT_CHECK";

fn main() -> ExitCode {
    match main_impl() {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(err) => {
            eprintln!("cargo-live: {err}");
            ExitCode::FAILURE
        }
    }
}

fn main_impl() -> Result<i32> {
    let mut args = env::args_os();
    let invoked_as = args.next().unwrap_or_default();
    let shim = Path::new(&invoked_as).file_name() == Some(OsStr::new("cargo"));
    let mut args: Vec<OsString> = args.collect();
    let mut cwd = env::current_dir()?.canonicalize()?;
    let cargo = real_cargo()?;
    let mut found_config = None;
    let mut toolchain = None;

    if shim {
        let Some(invocation) = parse_shim_args(&args).filter(|i| i.args[0] == "run") else {
            return passthrough(&cargo, &args);
        };
        if let Some(dir) = &invocation.directory {
            match cwd.join(dir).canonicalize() {
                Ok(dir) => cwd = dir,
                Err(_) => return passthrough(&cargo, &args),
            }
        }
        let Some(found) = Config::find(&cwd)? else {
            return passthrough(&cargo, &args);
        };
        found_config = Some(found);
        toolchain = invocation
            .toolchain
            .map(|t| {
                t.into_string()
                    .map_err(|_| error("the +toolchain argument must be UTF-8"))
            })
            .transpose()?
            .map(|t| t.trim_start_matches('+').to_owned());
        args = invocation.args;
    } else {
        // Cargo invokes external subcommands as `cargo-live live ...`.
        if args.first().is_some_and(|arg| arg == "live") {
            args.remove(0);
        }
        if args.is_empty() || args[0] == "--help" || args[0] == "help" || args[0] == "-h" {
            print_help();
            return Ok(0);
        }
        if args[0] == "--version" || args[0] == "-V" {
            println!("cargo-live {}", env!("CARGO_PKG_VERSION"));
            return Ok(0);
        }
    }

    let command = args.remove(0);
    match command.to_str() {
        Some("run" | "check") => {}
        Some("login") => return login(&cwd, &args),
        Some("logout") => return logout(&args),
        Some("creds") => return creds_command(&cwd, &args),
        Some("net") => return net_command(&cwd, &args),
        _ => {
            return Err(
                error("supported commands: run, check, login, logout, creds, net, help").into(),
            )
        }
    }
    let is_run = command == "run";
    let (config_root, config) = match found_config {
        Some(found) => found,
        None => Config::find(&cwd)?.ok_or_else(|| {
            error("no .cargo/live.toml found in the current directory or its parents")
        })?,
    };
    let metadata = Metadata::load(&cargo, &cwd)?;
    let workspace = metadata.workspace_root.canonicalize()?;
    if config_root.canonicalize()? != workspace {
        return Err(error(".cargo/live.toml must be at the Cargo workspace root").into());
    }
    let relative = cwd
        .strip_prefix(&workspace)
        .map_err(|_| error("working directory is outside the workspace"))?
        .to_str()
        .ok_or_else(|| error("working directory must be UTF-8"))?
        .to_owned();
    let (cargo_args, program_args) = split_args(args, is_run)?;

    let url = config.url()?;
    let token = lookup_token(&url)?;
    let user_config = UserConfig::load()?;
    let local_cargo = LocalCargoConfig::load(&workspace);
    let policy = creds::policy(
        &user_config,
        &config.credentials,
        local_cargo.registries_config(),
    );
    let network = net::policy(&user_config.tunnel, &user_config.network, &config.network);
    let tunnel = net::TunnelGate::new(user_config.tunnel.patterns().to_vec());
    let resolver = Arc::new(ClientResolver::new(user_config.forward, local_cargo));
    let job = Job {
        url,
        policy,
        network,
        tunnel,
        resolver,
        pin: config.remote.host_key.clone(),
        token,
        excludes: config.excludes()?,
        workspace: workspace.clone(),
        target_dir: metadata
            .target_directory
            .canonicalize()
            .unwrap_or(metadata.target_directory),
        request: BuildRequest {
            command: if is_run {
                BuildCommand::Run
            } else {
                BuildCommand::Check
            },
            toolchain,
            args: cargo_args,
            relative_cwd: relative,
            json_output: !is_run,
        },
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let outcome = runtime.block_on(job.run())?;
    drop(runtime);
    let (binary, remote_env, remotes) = match outcome {
        Outcome::Exit(code) => return Ok(code),
        Outcome::Run {
            binary,
            env,
            remotes,
        } => (binary, env, remotes),
    };

    let remotes: Vec<&str> = remotes.iter().map(String::as_str).collect();
    let env = local_env(remote_env, &remotes, &workspace, &cargo);
    eprintln!("cargo-live: running {}", binary.display());
    let status = Command::new(&binary)
        .args(program_args)
        .current_dir(&cwd)
        .envs(env)
        .status()
        .map_err(|e| error(format!("cannot run {}: {e}", binary.display())))?;
    use std::os::unix::process::ExitStatusExt;
    Ok(status
        .code()
        .or_else(|| status.signal().map(|s| 128 + s))
        .unwrap_or(1))
}

/// Cargo's run environment with remote source paths mapped to the local
/// workspace and `CARGO` pointing at the local Cargo.
fn local_env(
    remote_env: Vec<(String, String)>,
    remotes: &[&str],
    workspace: &Path,
    cargo: &Path,
) -> Vec<(String, String)> {
    remote_env
        .into_iter()
        .map(|(k, v)| {
            let v = if k == "CARGO" {
                cargo.to_string_lossy().into_owned()
            } else {
                output::remap_path(&v, remotes, workspace).unwrap_or(v)
            };
            (k, v)
        })
        .collect()
}

struct Job {
    url: AgentUrl,
    policy: CredentialPolicy,
    network: NetworkPolicy,
    tunnel: Arc<net::TunnelGate>,
    resolver: Arc<ClientResolver>,
    pin: Option<String>,
    token: String,
    excludes: cargo_live_proto::ExcludeSet,
    workspace: PathBuf,
    target_dir: PathBuf,
    request: BuildRequest,
}

enum Outcome {
    Exit(i32),
    Run {
        binary: PathBuf,
        env: Vec<(String, String)>,
        remotes: Vec<String>,
    },
}

impl Job {
    async fn run(self) -> Result<Outcome> {
        let is_run = self.request.command == BuildCommand::Run;
        let (mut remote, welcome) = Remote::connect(
            &self.url,
            self.pin.as_deref(),
            &self.token,
            Some(self.tunnel.clone()),
        )
        .await?;
        if is_run {
            match remote::compat_check(&welcome, BUILD_TARGET, remote::local_glibc().as_deref()) {
                Ok(None) => {}
                Ok(Some(warning)) => eprintln!("cargo-live: warning: {warning}"),
                Err(problem) if env::var_os(SKIP_COMPAT_ENV).is_some_and(|v| v == "1") => {
                    eprintln!("cargo-live: warning: {problem} ({SKIP_COMPAT_ENV}=1)")
                }
                Err(problem) => {
                    remote.close().await;
                    return Err(error(format!(
                        "{problem}. Set {SKIP_COMPAT_ENV}=1 to try anyway."
                    ))
                    .into());
                }
            }
        }
        let workspace_id = sha256_hex(self.workspace.as_os_str().as_encoded_bytes());
        let (source, physical) = remote.open(&workspace_id).await?;
        remote.send_credential_policy(self.policy.clone()).await?;
        remote.send_network_policy(self.network.clone()).await?;

        let (root, target, excludes) = (
            self.workspace.clone(),
            self.target_dir.clone(),
            self.excludes.clone(),
        );
        let entries =
            tokio::task::spawn_blocking(move || walk::manifest(&root, &target, &excludes))
                .await??;
        let stats = remote.sync(entries).await?;
        eprintln!(
            "cargo-live: synced to {}: {} files sent ({}), {} deleted",
            self.url,
            stats.files_written,
            remote::human_bytes(stats.bytes_written),
            stats.deleted
        );
        eprintln!(
            "cargo-live: running cargo {} remotely",
            if is_run { "run" } else { "check" }
        );
        let remotes = [source.as_str(), physical.as_str()];
        let result = remote
            .build(
                self.request.clone(),
                &remotes,
                &self.workspace,
                self.resolver.clone(),
            )
            .await?;
        if result.code != 0 || !is_run {
            remote.close().await;
            return Ok(Outcome::Exit(result.code));
        }
        let (executable, env) = result
            .run_target
            .ok_or_else(|| error("the agent did not report an executable"))?;
        // Keep remote target directories and binaries with the same name separate.
        let cached = CachedBinary {
            path: store::cache_dir()?
                .join(&workspace_id)
                .join(sha256_hex(executable.as_bytes())),
        };
        remote.fetch(&executable, &cached).await?;
        remote.close().await;
        Ok(Outcome::Run {
            binary: cached.path,
            env,
            remotes: vec![source, physical],
        })
    }
}

fn login(cwd: &Path, args: &[OsString]) -> Result<i32> {
    let [url] = args else {
        return Err(error("usage: cargo live login <host[:port]> (token on stdin)").into());
    };
    let url = AgentUrl::parse(url.to_str().ok_or_else(|| error("url must be UTF-8"))?)?;
    // Honour a pinned key from the current workspace for the same agent.
    let pin = Config::find(cwd)
        .ok()
        .flatten()
        .filter(|(_, c)| c.url().ok().as_ref() == Some(&url))
        .and_then(|(_, c)| c.remote.host_key);
    let token = read_token(&url)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let welcome = runtime.block_on(async {
        let (remote, welcome) = Remote::connect(&url, pin.as_deref(), &token, None).await?;
        remote.close().await;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(welcome)
    })?;
    let credentials = Credentials::default_location()?;
    credentials.store(&url.to_string(), &token)?;
    eprintln!(
        "cargo-live: logged in to {url} (cargo-live-agent {}, {}); token saved to {}",
        welcome.agent_version,
        welcome.host_triple,
        credentials.path.display()
    );
    Ok(0)
}

fn read_token(url: &AgentUrl) -> Result<String> {
    let token = if io::stdin().is_terminal() {
        rpassword::prompt_password(format!("cargo-live token for {url}: "))?
    } else {
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        line
    };
    let token = token.trim().to_owned();
    if !token.starts_with(TOKEN_PREFIX) || token.len() < 20 {
        return Err(error(format!(
            "expected a token starting with {TOKEN_PREFIX} (create one with \
             `cargo-live-agent token create --name NAME` on the agent)"
        ))
        .into());
    }
    Ok(token)
}

fn logout(args: &[OsString]) -> Result<i32> {
    let [url] = args else {
        return Err(error("usage: cargo live logout <host[:port]>").into());
    };
    let url = AgentUrl::parse(url.to_str().ok_or_else(|| error("url must be UTF-8"))?)?;
    if Credentials::default_location()?.remove(&url.to_string())? {
        eprintln!("cargo-live: removed the token for {url}");
    } else {
        eprintln!("cargo-live: no token stored for {url}");
    }
    Ok(0)
}

/// What the explain commands need: the workspace, its config, the agent
/// and its token, and the user config.
struct ExplainContext {
    workspace: PathBuf,
    config: Config,
    url: AgentUrl,
    token: String,
    user: UserConfig,
}

impl ExplainContext {
    fn load(cwd: &Path) -> Result<Self> {
        let (root, config) = Config::find(cwd)?.ok_or_else(|| {
            error("no .cargo/live.toml found in the current directory or its parents")
        })?;
        let url = config.url()?;
        Ok(Self {
            workspace: root.canonicalize()?,
            token: lookup_token(&url)?,
            url,
            config,
            user: UserConfig::load()?,
        })
    }

    /// Connects to the agent, runs `f` on the session (a dry run: no
    /// workspace is opened) and closes it.
    fn session<T>(&self, f: impl AsyncFnOnce(&mut Remote) -> Result<T>) -> Result<T> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let (mut remote, _) = Remote::connect(
                &self.url,
                self.config.remote.host_key.as_deref(),
                &self.token,
                None,
            )
            .await?;
            let result = f(&mut remote).await;
            remote.close().await;
            result
        })
    }
}

/// The token for `url` (stored by `cargo live login`, or `CARGO_LIVE_TOKEN`).
fn lookup_token(url: &AgentUrl) -> Result<String> {
    Credentials::default_location()?
        .lookup(&url.to_string())?
        .ok_or_else(|| {
            error(format!(
                "no token for {url}; run `cargo live login {url}` or set CARGO_LIVE_TOKEN"
            ))
            .into()
        })
}

/// `cargo live creds explain <git|cargo|docker> <target>`
fn creds_command(cwd: &Path, args: &[OsString]) -> Result<i32> {
    const USAGE: &str = "usage: cargo live creds explain git <url-or-host/path>\n       \
                         cargo live creds explain cargo <registry-name-or-index-url>\n       \
                         cargo live creds explain docker <host>";
    let args: Vec<&str> = args.iter().filter_map(|a| a.to_str()).collect();
    let ["explain", kind, target] = args[..] else {
        return Err(error(USAGE).into());
    };
    let ctx = ExplainContext::load(cwd)?;
    let local_cargo = LocalCargoConfig::load(&ctx.workspace);
    let scope = match kind {
        "git" => parse_git_target(target).map_err(error)?,
        "cargo" if target.contains("://") => Scope::cargo(None, Some(target)),
        "cargo" => Scope::cargo(Some(target), local_cargo.registry_index(target).as_deref()),
        "docker" => Scope::docker(target),
        _ => return Err(error(USAGE).into()),
    };
    scope.validate().map_err(error)?;
    let policy = creds::policy(
        &ctx.user,
        &ctx.config.credentials,
        local_cargo.registries_config(),
    );
    let steps = ctx.session(async |remote| {
        remote.send_credential_policy(policy).await?;
        remote.explain(scope.clone()).await
    })?;
    let resolver = ClientResolver::new(ctx.user.forward.clone(), local_cargo);
    print!(
        "{}",
        creds::explain_text(&scope, &ctx.url.to_string(), &steps, &resolver)
    );
    Ok(0)
}

/// `cargo live net explain <host[:port]>`
fn net_command(cwd: &Path, args: &[OsString]) -> Result<i32> {
    const USAGE: &str = "usage: cargo live net explain <host[:port]>   (port defaults to 443)";
    let args: Vec<&str> = args.iter().filter_map(|a| a.to_str()).collect();
    let ["explain", target] = args[..] else {
        return Err(error(USAGE).into());
    };
    let destination = Destination::parse(target, Some(DEFAULT_TUNNEL_PORT)).map_err(error)?;
    let ctx = ExplainContext::load(cwd)?;
    let network = net::policy(&ctx.user.tunnel, &ctx.user.network, &ctx.config.network);
    let steps = ctx.session(async |remote| {
        remote.send_network_policy(network).await?;
        remote.net_explain(destination.clone()).await
    })?;
    print!(
        "{}",
        net::explain_text(&destination, &ctx.url.to_string(), &steps, &ctx.user.tunnel)
    );
    Ok(0)
}

fn print_help() {
    println!(
        "cargo-live {}\n\n\
         Usage:\n  cargo live run [CARGO OPTIONS] [-- PROGRAM OPTIONS]\n  \
         cargo live check [CARGO OPTIONS]\n  \
         cargo live login <host[:port]>   (reads the token from stdin)\n  \
         cargo live logout <host[:port]>\n  \
         cargo live creds explain <git|cargo|docker> <target>\n  \
         cargo live net explain <host[:port]>\n\n\
         Configure .cargo/live.toml at the workspace root. See the README for\n\
         the agent setup, VS Code integration, and the optional cargo PATH shim.",
        env!("CARGO_PKG_VERSION")
    );
}

fn real_cargo() -> Result<PathBuf> {
    let this = env::current_exe()?.canonicalize()?;
    if let Some(path) = env::var_os("CARGO_LIVE_REAL_CARGO") {
        let path = PathBuf::from(path);
        if !path.is_absolute() || path.canonicalize()? == this {
            return Err(
                error("CARGO_LIVE_REAL_CARGO must be an absolute path to the real Cargo").into(),
            );
        }
        return Ok(path);
    }
    for dir in env::split_paths(&env::var_os("PATH").unwrap_or_default()) {
        let candidate = dir.join("cargo");
        if let Ok(resolved) = candidate.canonicalize() {
            if resolved != this && candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(error("could not find real cargo in PATH; set CARGO_LIVE_REAL_CARGO").into())
}

fn passthrough(cargo: &Path, args: &[OsString]) -> Result<i32> {
    let status = Command::new(cargo).args(args).status()?;
    Ok(status.code().unwrap_or(1))
}

/// A shim invocation with Cargo's global options moved behind the subcommand.
struct ShimInvocation {
    toolchain: Option<OsString>,
    directory: Option<OsString>,
    /// The subcommand (with the `r` alias expanded), the global options, and
    /// the remaining arguments.
    args: Vec<OsString>,
}

/// Finds the subcommand behind Cargo's global options, as in
/// `cargo +nightly --locked r`. Returns `None` if no subcommand runs or an
/// option is not understood; such invocations go to the real Cargo unchanged.
fn parse_shim_args(args: &[OsString]) -> Option<ShimInvocation> {
    let mut toolchain = None;
    let mut directory = None;
    let mut globals = Vec::new();
    let mut i = 0;
    if args
        .first()
        .is_some_and(|a| a.as_encoded_bytes().starts_with(b"+"))
    {
        toolchain = Some(args[0].clone());
        i = 1;
    }
    while i < args.len() {
        let arg = args[i].to_str()?;
        match arg {
            "--color" | "--config" | "-Z" => {
                globals.push(args[i].clone());
                globals.push(args.get(i + 1)?.clone());
                i += 1;
            }
            "-C" => {
                directory = Some(args.get(i + 1)?.clone());
                i += 1;
            }
            "--quiet" | "--verbose" | "--locked" | "--offline" | "--frozen" => {
                globals.push(args[i].clone());
            }
            _ if arg.starts_with("--color=") || arg.starts_with("--config=") => {
                globals.push(args[i].clone());
            }
            _ if arg.starts_with("-Z") => globals.push(args[i].clone()),
            _ if arg.starts_with("-C") => directory = Some(arg[2..].into()),
            // -q, -v, -vv, ...
            _ if arg.len() > 1
                && arg.starts_with('-')
                && arg[1..].bytes().all(|b| matches!(b, b'q' | b'v')) =>
            {
                globals.push(args[i].clone());
            }
            // --version, --list, --explain, --help, unknown options.
            _ if arg.starts_with('-') => return None,
            _ => {
                let command = if arg == "r" { "run" } else { arg };
                let mut rest = vec![OsString::from(command)];
                rest.extend(globals);
                rest.extend_from_slice(&args[i + 1..]);
                return Some(ShimInvocation {
                    toolchain,
                    directory,
                    args: rest,
                });
            }
        }
        i += 1;
    }
    None
}

/// Splits Cargo options from program arguments at the first `--`. Program
/// arguments are never sent to the agent.
fn split_args(args: Vec<OsString>, is_run: bool) -> Result<(Vec<String>, Vec<OsString>)> {
    let mut cargo = Vec::new();
    let mut program = Vec::new();
    let mut after_separator = false;
    for arg in args {
        if after_separator {
            program.push(arg);
        } else if arg == "--" {
            if !is_run {
                return Err(error("'--' is not supported for check").into());
            }
            after_separator = true;
        } else {
            let arg = arg
                .into_string()
                .map_err(|_| error("Cargo options must be UTF-8"))?;
            if ["--target-dir", "--manifest-path"]
                .iter()
                .any(|v| arg == *v || arg.starts_with(&format!("{v}=")))
            {
                return Err(error(format!(
                    "{arg} is not supported; run from the workspace instead"
                ))
                .into());
            }
            if (arg == "--message-format" || arg.starts_with("--message-format="))
                && (is_run || arg != "--message-format=json")
            {
                return Err(error("only --message-format=json is supported for check").into());
            }
            cargo.push(arg);
        }
    }
    Ok((cargo, program))
}

#[derive(Deserialize)]
struct Metadata {
    workspace_root: PathBuf,
    target_directory: PathBuf,
}

impl Metadata {
    fn load(cargo: &Path, cwd: &Path) -> Result<Self> {
        let output = Command::new(cargo)
            .args(["metadata", "--no-deps", "--format-version=1"])
            .current_dir(cwd)
            .stderr(Stdio::inherit())
            .output()?;
        if !output.status.success() {
            return Err(error(format!("cargo metadata failed: {}", output.status)).into());
        }
        Ok(serde_json::from_slice(&output.stdout)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separates_program_arguments() {
        let args = ["--release", "--", "--hello", "--"]
            .into_iter()
            .map(OsString::from)
            .collect();
        let (cargo, program) = split_args(args, true).unwrap();
        assert_eq!(cargo, ["--release"]);
        assert_eq!(program, [OsString::from("--hello"), OsString::from("--")]);
        assert!(split_args(vec!["--".into()], false).is_err());
    }

    #[test]
    fn prevents_unsupported_options() {
        for arg in [
            "--target-dir",
            "--target-dir=/elsewhere",
            "--manifest-path=x",
            "--message-format=json",
        ] {
            assert!(split_args(vec![arg.into()], true).is_err(), "{arg}");
        }
        assert!(split_args(vec!["--message-format=json".into()], false).is_ok());
        assert!(split_args(vec!["--message-format=short".into()], false).is_err());
    }

    #[test]
    fn maps_run_environment_to_local_paths() {
        let env = vec![
            ("CARGO_MANIFEST_DIR".into(), "/data/ws/source/app".into()),
            ("CARGO_PKG_NAME".into(), "app".into()),
            ("CARGO".into(), "/usr/local/cargo/bin/cargo".into()),
        ];
        let mapped = local_env(
            env,
            &["/data/ws/source"],
            Path::new("/home/me/app"),
            Path::new("/usr/bin/cargo"),
        );
        assert_eq!(
            mapped,
            [
                (
                    "CARGO_MANIFEST_DIR".to_owned(),
                    "/home/me/app/app".to_owned()
                ),
                ("CARGO_PKG_NAME".to_owned(), "app".to_owned()),
                ("CARGO".to_owned(), "/usr/bin/cargo".to_owned()),
            ]
        );
    }

    fn shim(args: &[&str]) -> Option<ShimInvocation> {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        parse_shim_args(&args)
    }

    #[test]
    fn shim_finds_run_behind_global_options() {
        let parsed = shim(&[
            "+nightly",
            "-q",
            "--locked",
            "--config",
            "a=1",
            "-Zfoo",
            "--color=never",
            "r",
            "--release",
            "--",
            "x",
        ])
        .unwrap();
        assert_eq!(parsed.toolchain, Some("+nightly".into()));
        assert_eq!(parsed.directory, None);
        assert_eq!(
            parsed.args,
            [
                "run",
                "-q",
                "--locked",
                "--config",
                "a=1",
                "-Zfoo",
                "--color=never",
                "--release",
                "--",
                "x"
            ]
        );
        let parsed = shim(&["-vv", "-C", "sub", "-Z", "unstable-options", "run"]).unwrap();
        assert_eq!(parsed.directory, Some("sub".into()));
        assert_eq!(parsed.args, ["run", "-vv", "-Z", "unstable-options"]);
    }

    #[test]
    fn shim_leaves_other_invocations_alone() {
        assert_eq!(shim(&["build", "run"]).unwrap().args, ["build", "run"]);
        for args in [
            &[][..],
            &["--version"],
            &["-V", "run"],
            &["--list"],
            &["--color"],
            &["--unknown", "run"],
        ] {
            assert!(shim(args).is_none(), "{args:?}");
        }
        // +toolchain is only recognized first; elsewhere it is not `run`.
        assert_eq!(
            shim(&["-q", "+nightly", "run"]).unwrap().args[0],
            "+nightly"
        );
    }
}
