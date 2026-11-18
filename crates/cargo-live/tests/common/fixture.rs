//! Fixtures shared by the credential and network end-to-end tests: a local
//! HTTP server with git repositories and a sparse registry behind
//! authentication, agents with isolated Cargo homes, and client projects.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

use super::httpd::{Auth, Server};
use super::{Agent, AgentOptions, Project};

pub const AGENT_SECRET: &str = "agent-file-secret-6f1c2d0e";
pub const CLIENT_SECRET: &str = "client-forwarded-secret-9a8b7c6d";
pub const REGISTRY_TOKEN: &str = "registry-exec-token-5e4d3c2b";
pub const GH_TOKEN: &str = "ghs_minted-installation-token-1b2a3c4d";
pub const DOCKER_SECRET: &str = "docker-registry-secret-0f9e8d7c";

/// Files served by the test server and secrets mounted into the agent.
pub struct Fixture {
    pub server: Server,
    pub root: TempDir,
    pub secrets: TempDir,
}

pub fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.com")
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?}");
}

impl Fixture {
    pub fn new() -> Self {
        let fixture = Fixture {
            server: Server::start(),
            root: tempfile::tempdir().unwrap(),
            secrets: tempfile::tempdir().unwrap(),
        };
        let root = fixture.root.path().to_owned();
        fixture.server.serve_dir(
            "/git/acme/",
            root.join("git/acme"),
            Auth::Basic("deploy-bot".into(), AGENT_SECRET.into()),
        );
        fixture.server.serve_dir(
            "/git/alfatm/",
            root.join("git/alfatm"),
            Auth::Basic("me".into(), CLIENT_SECRET.into()),
        );
        fixture.server.serve_dir(
            "/gh/",
            root.join("gh"),
            Auth::Basic("x-access-token".into(), GH_TOKEN.into()),
        );
        fixture.server.serve_dir(
            "/registry/",
            root.join("registry"),
            Auth::Token(REGISTRY_TOKEN.into()),
        );
        fs::write(
            fixture.secrets.path().join("deploy-token"),
            format!("{AGENT_SECRET}\n"),
        )
        .unwrap();
        fs::write(fixture.secrets.path().join("docker-token"), DOCKER_SECRET).unwrap();
        fixture
    }

    pub fn host(&self) -> String {
        self.server.host()
    }

    /// A bare repository at `<root>/<rel>.git` with a library crate whose
    /// `value()` returns `value`; served via git's dumb HTTP protocol.
    pub fn git_repo(&self, rel: &str, name: &str, value: &str) -> String {
        let work = tempfile::tempdir().unwrap();
        fs::create_dir_all(work.path().join("src")).unwrap();
        fs::write(
            work.path().join("Cargo.toml"),
            format!("[package]\nname = '{name}'\nversion = '0.1.0'\nedition = '2021'\n"),
        )
        .unwrap();
        fs::write(
            work.path().join("src/lib.rs"),
            format!("pub fn value() -> &'static str {{ \"{value}\" }}\n"),
        )
        .unwrap();
        git(work.path(), &["init", "-q", "-b", "main"]);
        git(work.path(), &["add", "."]);
        git(work.path(), &["commit", "-q", "-m", "init"]);
        let bare = self.root.path().join(format!("{rel}.git"));
        fs::create_dir_all(bare.parent().unwrap()).unwrap();
        git(
            self.root.path(),
            &[
                "clone",
                "-q",
                "--bare",
                work.path().to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
        );
        git(&bare, &["update-server-info"]);
        self.server.url(&format!("/{rel}.git"))
    }

    /// A sparse registry (`auth-required`) with `privlib 0.1.0`.
    pub fn registry(&self) -> String {
        let reg = self.root.path().join("registry");
        fs::create_dir_all(reg.join("pr/iv")).unwrap();
        fs::create_dir_all(reg.join("dl")).unwrap();
        fs::write(
            reg.join("config.json"),
            serde_json::json!({
                "dl": self.server.url("/registry/dl/{crate}-{version}.crate"),
                "auth-required": true,
            })
            .to_string(),
        )
        .unwrap();
        let src = tempfile::tempdir().unwrap();
        let pkg = src.path().join("privlib-0.1.0");
        fs::create_dir_all(pkg.join("src")).unwrap();
        fs::write(
            pkg.join("Cargo.toml"),
            "[package]\nname = 'privlib'\nversion = '0.1.0'\nedition = '2021'\n",
        )
        .unwrap();
        fs::write(
            pkg.join("src/lib.rs"),
            "pub fn value() -> &'static str { \"privlib\" }\n",
        )
        .unwrap();
        let crate_file = reg.join("dl/privlib-0.1.0.crate");
        let status = Command::new("tar")
            .arg("-czf")
            .arg(&crate_file)
            .arg("-C")
            .arg(src.path())
            .arg("privlib-0.1.0")
            .status()
            .unwrap();
        assert!(status.success());
        let cksum = cargo_live_proto::sha256_hex(&fs::read(&crate_file).unwrap());
        fs::write(
            reg.join("pr/iv/privlib"),
            format!(
                "{}\n",
                serde_json::json!({"name": "privlib", "vers": "0.1.0", "deps": [],
                                   "cksum": cksum, "features": {}, "yanked": false})
            ),
        )
        .unwrap();
        format!("sparse+{}", self.server.url("/registry/"))
    }

    pub fn secret(&self, name: &str) -> PathBuf {
        self.secrets.path().join(name)
    }

    /// An executable script in the secrets directory.
    pub fn script(&self, name: &str, body: &str) -> PathBuf {
        let path = self.secrets.path().join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// agent.toml snippet: the `file` provider for `git/acme/*`.
    pub fn file_provider(&self, allow: &str) -> String {
        format!(
            "[[credentials]]\nname = \"acme-file\"\n\
             match = {{ kind = \"git\", host = \"{}\", path = \"git/acme/*\" }}\n\
             provider = \"file\"\npath = {:?}\nusername = \"deploy-bot\"\nallow_tokens = [{allow}]\n",
            self.host(),
            self.secret("deploy-token")
        )
    }
}

/// An agent with an isolated Cargo home and a global git config whose
/// credential helper must be ignored.
pub fn agent(fixture: &Fixture, config: &str) -> Agent {
    let gitconfig = fixture.secrets.path().join("agent-gitconfig");
    fs::write(
        &gitconfig,
        "[credential]\n\thelper = \"!f() { echo username=x; echo password=inherited-wrong; }; f\"\n",
    )
    .unwrap();
    Agent::start_with(AgentOptions {
        config: Some(config.to_owned()),
        env: vec![
            ("GIT_CONFIG_GLOBAL".into(), gitconfig.display().to_string()),
            ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
        ],
        isolated_cargo_home: true,
        cargo: None,
    })
}

/// A project depending on `deps` (Cargo.toml dependency lines); `main`
/// prints the dependencies' `value()`s.
pub fn project(agent: &Agent, deps: &[(&str, String)]) -> Project {
    let mut project = Project::new(agent);
    let mut manifest =
        "[package]\nname = 'fixture-app'\nversion = '0.1.0'\nedition = '2021'\n\n[dependencies]\n"
            .to_owned();
    let mut main = String::from("fn main() {\n");
    for (name, spec) in deps {
        manifest.push_str(&format!("{name} = {spec}\n"));
        main.push_str(&format!(
            "    println!(\"{{}}\", {}::value());\n",
            name.replace('-', "_")
        ));
    }
    main.push_str("}\n");
    fs::write(project.root.join("Cargo.toml"), manifest).unwrap();
    fs::write(project.root.join("src/main.rs"), main).unwrap();
    // The client's own environment: Cargo home, git config.
    let home = project.temp.path().join("cargo-home");
    fs::create_dir_all(&home).unwrap();
    let gitconfig = project.temp.path().join("gitconfig");
    fs::write(&gitconfig, "").unwrap();
    project.env = vec![
        ("CARGO_HOME".into(), home.display().to_string()),
        ("GIT_CONFIG_GLOBAL".into(), gitconfig.display().to_string()),
        ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
    ];
    project
}

pub fn user_config(project: &Project, text: &str) {
    let dir = project.temp.path().join("config/cargo-live");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("config.toml"), text).unwrap();
}

/// A local git credential helper that hands out `CLIENT_SECRET` for
/// `git/alfatm/*` and records each request.
pub fn client_git_helper(fixture: &Fixture, project: &Project) -> PathBuf {
    let log = project.temp.path().join("helper.log");
    let helper = fixture.script(
        "client-helper.sh",
        &format!(
            "test \"$1\" = get || exit 0\n\
             while read line; do [ -z \"$line\" ] && break; case \"$line\" in path=*) p=\"${{line#path=}}\";; esac; done\n\
             echo \"$p\" >> {log:?}\n\
             case \"$p\" in git/alfatm/*) echo username=me; echo password={CLIENT_SECRET};; esac\n"
        ),
    );
    fs::write(
        project.temp.path().join("gitconfig"),
        format!(
            "[credential]\n\thelper = {}\n\tuseHttpPath = true\n",
            helper.display()
        ),
    )
    .unwrap();
    log
}

/// Asserts that `secret` appears in no file under the given directories.
pub fn assert_not_on_disk(dirs: &[&Path], secret: &str) {
    pub fn walk(dir: &Path, secret: &[u8], hits: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                walk(&path, secret, hits);
            } else if ft.is_file() {
                if let Ok(data) = fs::read(&path) {
                    if data.windows(secret.len()).any(|w| w == secret) {
                        hits.push(path);
                    }
                }
            }
        }
    }
    let mut hits = Vec::new();
    for dir in dirs {
        walk(dir, secret.as_bytes(), &mut hits);
    }
    assert!(hits.is_empty(), "secret found on disk in {hits:?}");
}

pub fn agent_dirs(agent: &Agent) -> Vec<&Path> {
    let mut dirs = vec![agent.data.path()];
    if let Some(home) = &agent.cargo_home {
        dirs.push(home.path());
    }
    dirs
}

pub fn audit(agent: &Agent) -> Vec<serde_json::Value> {
    let path = agent.data.path().join("audit.log");
    let mode = fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}
