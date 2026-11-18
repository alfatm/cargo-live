//! Command line, environment and config file handling.
//!
//! Precedence for every option: flag > `CARGO_LIVE_AGENT_<NAME>` > config
//! file > default. clap handles flag and environment; the file and defaults
//! are folded in here.

use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use serde::Deserialize;

use crate::cred::config::{ProviderConfig, TokenPolicy};
use crate::cred::AgentCreds;
use crate::Result;
use cargo_live_proto::net::{parse_patterns, HostPattern};

#[derive(Debug, Parser)]
#[command(
    name = "cargo-live-agent",
    version,
    about = "Remote build agent for cargo-live"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the SSH build server.
    Serve(ServeArgs),
    /// Manage API tokens.
    #[command(subcommand)]
    Token(TokenCommand),
    /// Print the host key fingerprint (generating the key if needed).
    Fingerprint(CommonArgs),
}

#[derive(Debug, Subcommand)]
pub enum TokenCommand {
    /// Create a token and print it once.
    Create {
        #[arg(long)]
        name: String,
        #[command(flatten)]
        common: CommonArgs,
    },
    /// List token names and creation times.
    List(CommonArgs),
    /// Revoke a token.
    Revoke {
        #[arg(long)]
        name: String,
        #[command(flatten)]
        common: CommonArgs,
    },
}

#[derive(Debug, Clone, Default, Args)]
pub struct CommonArgs {
    /// Config file [default: <data-dir>/agent.toml if present]
    #[arg(long, env = "CARGO_LIVE_AGENT_CONFIG")]
    pub config: Option<PathBuf>,
    /// Data directory [default: /data]
    #[arg(long, env = "CARGO_LIVE_AGENT_DATA_DIR")]
    pub data_dir: Option<PathBuf>,
    /// Host key [default: <data-dir>/host_key]
    #[arg(long, env = "CARGO_LIVE_AGENT_HOST_KEY")]
    pub host_key: Option<PathBuf>,
    /// Tokens file [default: <data-dir>/tokens.toml]
    #[arg(long, env = "CARGO_LIVE_AGENT_TOKENS_FILE")]
    pub tokens_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Args)]
pub struct ServeArgs {
    #[command(flatten)]
    pub common: CommonArgs,
    /// Listen address [default: 0.0.0.0:2222]
    #[arg(long, env = "CARGO_LIVE_AGENT_LISTEN")]
    pub listen: Option<SocketAddr>,
    /// Maximum number of concurrent Cargo processes [default: 2]
    #[arg(long, env = "CARGO_LIVE_AGENT_MAX_CONCURRENT_BUILDS")]
    pub max_concurrent_builds: Option<usize>,
    /// Cargo executable [default: cargo from PATH]
    #[arg(long, env = "CARGO_LIVE_AGENT_CARGO")]
    pub cargo: Option<PathBuf>,
    /// Seconds to wait for a busy workspace [default: 600]
    #[arg(long, env = "CARGO_LIVE_AGENT_LOCK_TIMEOUT")]
    pub lock_timeout: Option<u64>,
    /// Maximum number of open connections, authenticated or not; further
    /// connections are closed immediately [default: 64]
    #[arg(long, env = "CARGO_LIVE_AGENT_MAX_CONNECTIONS")]
    pub max_connections: Option<usize>,
    /// Destinations (`host[:port]` globs, any port when omitted) the build
    /// proxy may connect to directly from the agent; repeat the flag or
    /// separate with commas, "" for none [default: *]
    #[arg(long, env = "CARGO_LIVE_AGENT_NETWORK_DIRECT", value_delimiter = ',')]
    pub network_direct: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    listen: Option<SocketAddr>,
    data_dir: Option<PathBuf>,
    host_key: Option<PathBuf>,
    tokens_file: Option<PathBuf>,
    max_concurrent_builds: Option<usize>,
    cargo: Option<PathBuf>,
    lock_timeout: Option<u64>,
    max_connections: Option<usize>,
    /// Credential providers (`[[credentials]]`).
    #[serde(default)]
    credentials: Vec<ProviderConfig>,
    /// Per-token credential policy (`[tokens.<name>]`).
    #[serde(default)]
    tokens: BTreeMap<String, TokenPolicy>,
    /// Build proxy policy (`[network]`).
    #[serde(default)]
    network: NetworkConfig,
    /// Directory of the config file, for relative paths.
    #[serde(skip)]
    base: PathBuf,
}

/// `[network]` in agent.toml.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkConfig {
    /// `host[:port]` globs the proxy may connect to directly.
    direct: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct Paths {
    pub data_dir: PathBuf,
    pub host_key: PathBuf,
    pub tokens_file: PathBuf,
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub paths: Paths,
    pub listen: SocketAddr,
    pub max_concurrent_builds: usize,
    pub cargo: PathBuf,
    pub lock_timeout: Duration,
    pub max_connections: usize,
    pub creds: Arc<AgentCreds>,
    /// `[network] direct`: destinations the build proxy may connect to
    /// from the agent itself (empty: none), parsed.
    pub network_direct: Arc<Vec<HostPattern>>,
}

const DEFAULT_DATA_DIR: &str = "/data";
const DEFAULT_MAX_CONNECTIONS: usize = 64;

fn load_file(common: &CommonArgs) -> Result<FileConfig> {
    let (path, explicit) = match &common.config {
        Some(path) => (path.clone(), true),
        None => (
            common
                .data_dir
                .clone()
                .unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR))
                .join("agent.toml"),
            false,
        ),
    };
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if !explicit && e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(FileConfig::default())
        }
        Err(e) => return Err(format!("cannot read {}: {e}", path.display()).into()),
    };
    let mut config: FileConfig =
        toml::from_str(&text).map_err(|e| format!("invalid {}: {e}", path.display()))?;
    // Relative paths in the file are relative to the file.
    let base = path.parent().unwrap_or(Path::new("."));
    config.base = base.to_owned();
    for p in [
        &mut config.data_dir,
        &mut config.host_key,
        &mut config.tokens_file,
    ]
    .into_iter()
    .flatten()
    {
        if p.is_relative() {
            *p = base.join(&*p);
        }
    }
    if let Some(cargo) = &mut config.cargo {
        // A bare name is looked up in PATH; a relative path is file-relative.
        if cargo.components().count() > 1 && cargo.is_relative() {
            *cargo = base.join(&*cargo);
        }
    }
    Ok(config)
}

fn resolve_paths(common: &CommonArgs, file: &FileConfig) -> Paths {
    let data_dir = common
        .data_dir
        .clone()
        .or_else(|| file.data_dir.clone())
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR));
    // Cargo runs in other directories, so CARGO_TARGET_DIR must be absolute.
    let data_dir = std::path::absolute(&data_dir).unwrap_or(data_dir);
    Paths {
        host_key: common
            .host_key
            .clone()
            .or_else(|| file.host_key.clone())
            .unwrap_or_else(|| data_dir.join("host_key")),
        tokens_file: common
            .tokens_file
            .clone()
            .or_else(|| file.tokens_file.clone())
            .unwrap_or_else(|| data_dir.join("tokens.toml")),
        data_dir,
    }
}

pub fn paths(common: &CommonArgs) -> Result<Paths> {
    let file = load_file(common)?;
    Ok(resolve_paths(common, &file))
}

pub fn settings(args: &ServeArgs) -> Result<Settings> {
    let mut file = load_file(&args.common)?;
    let paths = resolve_paths(&args.common, &file);
    let creds = AgentCreds::from_config(
        std::mem::take(&mut file.credentials),
        std::mem::take(&mut file.tokens),
        &file.base,
    )?;
    // An empty value (`--network-direct ""`) means no direct connections.
    let network_direct: Vec<String> = args
        .network_direct
        .clone()
        .or(file.network.direct.take())
        .unwrap_or_else(|| vec!["*".to_owned()])
        .into_iter()
        .map(|p| p.trim().to_owned())
        .filter(|p| !p.is_empty())
        .collect();
    let network_direct = parse_patterns(&network_direct, None, "network direct")?;
    let settings = Settings {
        network_direct: Arc::new(network_direct),
        creds: Arc::new(creds),
        paths,
        listen: args
            .listen
            .or(file.listen)
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], cargo_live_proto::DEFAULT_PORT))),
        max_concurrent_builds: args
            .max_concurrent_builds
            .or(file.max_concurrent_builds)
            .unwrap_or(2),
        cargo: args
            .cargo
            .clone()
            .or(file.cargo)
            .unwrap_or_else(|| PathBuf::from("cargo")),
        lock_timeout: Duration::from_secs(args.lock_timeout.or(file.lock_timeout).unwrap_or(600)),
        max_connections: args
            .max_connections
            .or(file.max_connections)
            .unwrap_or(DEFAULT_MAX_CONNECTIONS),
    };
    if settings.max_concurrent_builds == 0 {
        return Err("max_concurrent_builds must be at least 1".into());
    }
    if settings.max_connections == 0 {
        return Err("max_connections must be at least 1".into());
    }
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precedence_is_flag_then_file_then_default() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("agent.toml"),
            "listen = '127.0.0.1:1'\nmax_concurrent_builds = 5\ntokens_file = 'tok.toml'\n\
             max_connections = 7\n",
        )
        .unwrap();
        let mut args = ServeArgs {
            common: CommonArgs {
                data_dir: Some(dir.path().to_owned()),
                ..Default::default()
            },
            listen: Some("127.0.0.1:2".parse().unwrap()),
            ..Default::default()
        };
        let s = settings(&args).unwrap();
        assert_eq!(s.listen.port(), 2);
        assert_eq!(s.max_concurrent_builds, 5);
        assert_eq!(s.paths.tokens_file, dir.path().join("tok.toml"));
        assert_eq!(s.paths.host_key, dir.path().join("host_key"));
        assert_eq!(s.lock_timeout, Duration::from_secs(600));
        assert_eq!(s.max_connections, 7);
        args.max_connections = Some(3);
        assert_eq!(settings(&args).unwrap().max_connections, 3);
        args.max_connections = Some(0);
        assert!(settings(&args).is_err());
        args.max_connections = None;
        let direct = |s: &Settings| -> Vec<String> {
            s.network_direct.iter().map(|p| p.to_string()).collect()
        };
        assert_eq!(direct(&s), ["*"]);

        fs::write(
            dir.path().join("agent.toml"),
            "[network]\ndirect = ['*.internal', '10.0.0.1:443']\n",
        )
        .unwrap();
        assert_eq!(
            direct(&settings(&args).unwrap()),
            ["*.internal", "10.0.0.1:443"]
        );
        args.network_direct = Some(vec![String::new()]);
        assert!(settings(&args).unwrap().network_direct.is_empty());
        args.network_direct = Some(vec!["h:0".into()]);
        assert!(settings(&args).is_err());
        args.network_direct = None;

        args.common.config = Some(dir.path().join("missing.toml"));
        assert!(settings(&args).is_err());
        fs::write(dir.path().join("bad.toml"), "unknown = 1\n").unwrap();
        args.common.config = Some(dir.path().join("bad.toml"));
        assert!(settings(&args).is_err());
    }
}
