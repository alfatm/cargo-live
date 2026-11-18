//! Shared harness for the end-to-end tests.
#![allow(dead_code)]

pub mod httpd;

use std::env;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use tempfile::TempDir;

pub fn cargo() -> PathBuf {
    env::var_os("CARGO").expect("run under cargo").into()
}

/// The agent binary next to the client, built on demand so that
/// `cargo test -p cargo-live` works on its own.
pub fn agent_bin() -> &'static Path {
    static AGENT: OnceLock<PathBuf> = OnceLock::new();
    AGENT.get_or_init(|| {
        let client = Path::new(env!("CARGO_BIN_EXE_cargo-live"));
        let mut build = Command::new(cargo());
        build
            .args([
                "build",
                "-p",
                "cargo-live-agent",
                "--bin",
                "cargo-live-agent",
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"));
        if client.parent().is_some_and(|p| p.ends_with("release")) {
            build.arg("--release");
        }
        let status = build.status().expect("cargo build");
        assert!(status.success(), "building cargo-live-agent failed");
        let agent = client.with_file_name("cargo-live-agent");
        assert!(agent.exists(), "{} missing", agent.display());
        agent
    })
}

pub struct Agent {
    pub child: Child,
    pub data: TempDir,
    pub addr: String,
    pub token: String,
    pub log: PathBuf,
    /// Cargo home of the agent's builds, if isolated.
    pub cargo_home: Option<TempDir>,
}

/// Extra setup for [`Agent::start_with`].
#[derive(Default)]
pub struct AgentOptions {
    /// Contents of `<data_dir>/agent.toml`.
    pub config: Option<String>,
    pub env: Vec<(String, String)>,
    /// Use a fresh `CARGO_HOME` for builds (no cached git/registry data).
    pub isolated_cargo_home: bool,
}

impl Agent {
    pub fn start() -> Self {
        Self::start_with(AgentOptions::default())
    }

    pub fn start_with(options: AgentOptions) -> Self {
        let data = tempfile::tempdir().unwrap();
        if let Some(config) = &options.config {
            fs::write(data.path().join("agent.toml"), config).unwrap();
        }
        let output = Command::new(agent_bin())
            .args(["token", "create", "--name", "tester", "--data-dir"])
            .arg(data.path())
            .output()
            .unwrap();
        assert!(output.status.success());
        let token = String::from_utf8(output.stdout).unwrap().trim().to_owned();
        let log = data.path().join("agent.log");
        let mut command = Command::new(agent_bin());
        command
            .args(["serve", "--listen", "127.0.0.1:0", "--data-dir"])
            .arg(data.path())
            .arg("--cargo")
            .arg(cargo())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(fs::File::create(&log).unwrap());
        // Do not leak the test harness's Cargo variables into remote builds.
        for (key, _) in env::vars_os() {
            let key = key.to_string_lossy().into_owned();
            if (key.starts_with("CARGO_") && key != "CARGO_HOME") || key == "CARGO" {
                command.env_remove(key);
            }
        }
        let cargo_home = options
            .isolated_cargo_home
            .then(|| tempfile::tempdir().unwrap());
        if let Some(home) = &cargo_home {
            command.env("CARGO_HOME", home.path());
        }
        command.envs(options.env.iter().map(|(k, v)| (k, v)));
        let child = command.spawn().unwrap();
        let mut agent = Agent {
            child,
            data,
            addr: String::new(),
            token,
            log,
            cargo_home,
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let text = fs::read_to_string(&agent.log).unwrap_or_default();
            if let Some(addr) = text
                .lines()
                .find_map(|l| l.split(" listening on ").nth(1))
                .and_then(|rest| rest.split_whitespace().next())
            {
                agent.addr = addr.to_owned();
                break;
            }
            assert!(Instant::now() < deadline, "agent did not start:\n{text}");
            std::thread::sleep(Duration::from_millis(50));
        }
        agent
    }

    pub fn log(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }

    pub fn fingerprint(&self) -> String {
        let output = Command::new(agent_bin())
            .args(["fingerprint", "--data-dir"])
            .arg(self.data.path())
            .output()
            .unwrap();
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    pub fn workspace_dir(&self, project: &Project) -> PathBuf {
        let workspace = project.root.canonicalize().unwrap();
        let id = cargo_live_proto::sha256_hex(workspace.as_os_str().as_encoded_bytes());
        self.data.path().join("workspaces/tester").join(id)
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub struct Project {
    pub temp: TempDir,
    pub root: PathBuf,
    pub bin: PathBuf,
    pub token: String,
    /// Extra environment of client commands.
    pub env: Vec<(String, String)>,
}

pub const MAIN: &str = r#"fn main() {
    println!(
        "{}|{}|{}",
        std::env::current_dir().unwrap().display(),
        std::env::args().nth(1).unwrap_or_default(),
        std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default()
    );
}
"#;

impl Project {
    pub fn new(agent: &Agent) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("workspace");
        let bin = temp.path().join("bin");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join(".cargo")).unwrap();
        fs::create_dir_all(root.join("target")).unwrap();
        fs::create_dir_all(&bin).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = 'fixture-app'\nversion = '0.1.0'\nedition = '2021'\n",
        )
        .unwrap();
        fs::write(root.join("src/main.rs"), MAIN).unwrap();
        fs::write(root.join("target/local-sentinel"), "do not copy").unwrap();
        symlink(env!("CARGO_BIN_EXE_cargo-live"), bin.join("cargo")).unwrap();
        let project = Project {
            temp,
            root,
            bin,
            token: agent.token.clone(),
            env: Vec::new(),
        };
        project.write_config(&agent.addr, None);
        project
    }

    pub fn write_config(&self, addr: &str, host_key: Option<&str>) {
        let mut text = format!("[remote]\nurl = {addr:?}\n");
        if let Some(key) = host_key {
            text.push_str(&format!("host_key = {key:?}\n"));
        }
        fs::write(self.root.join(".cargo/live.toml"), text).unwrap();
    }

    pub fn command(&self, program: &Path, args: &[&str]) -> Command {
        let path = format!("{}:{}", self.bin.display(), env::var("PATH").unwrap());
        let mut command = Command::new(program);
        command
            .args(args)
            .current_dir(&self.root)
            .env("PATH", path)
            .env("CARGO_LIVE_REAL_CARGO", cargo())
            .env("CARGO_TARGET_DIR", self.root.join("target"))
            .env("CARGO_LIVE_TOKEN", &self.token)
            .env("XDG_CONFIG_HOME", self.temp.path().join("config"))
            .env("XDG_CACHE_HOME", self.temp.path().join("cache"))
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::null());
        command
    }

    pub fn live(&self, args: &[&str]) -> Output {
        let mut full = vec!["live"];
        full.extend_from_slice(args);
        self.command(Path::new(env!("CARGO_BIN_EXE_cargo-live")), &full)
            .output()
            .unwrap()
    }

    pub fn shim(&self, args: &[&str]) -> Output {
        self.command(&self.bin.join("cargo"), args)
            .output()
            .unwrap()
    }
}

pub fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

pub fn assert_success(output: &Output) -> String {
    assert!(output.status.success(), "{}", stderr(output));
    String::from_utf8(output.stdout.clone()).unwrap()
}
