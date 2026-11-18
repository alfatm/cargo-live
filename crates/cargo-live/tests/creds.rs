//! End-to-end tests of the credential broker: a real agent and client, real
//! Cargo and git, and a local HTTP server that serves git repositories
//! (dumb HTTP), a sparse registry with `auth-required`, and a mock GitHub
//! API, all behind authentication.
#![cfg(unix)]

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use base64::Engine;
use tempfile::TempDir;

use common::httpd::{Auth, Response, Server};
use common::*;

const AGENT_SECRET: &str = "agent-file-secret-6f1c2d0e";
const CLIENT_SECRET: &str = "client-forwarded-secret-9a8b7c6d";
const REGISTRY_TOKEN: &str = "registry-exec-token-5e4d3c2b";
const GH_TOKEN: &str = "ghs_minted-installation-token-1b2a3c4d";
const DOCKER_SECRET: &str = "docker-registry-secret-0f9e8d7c";

/// Files served by the test server and secrets mounted into the agent.
struct Fixture {
    server: Server,
    root: TempDir,
    secrets: TempDir,
}

fn git(dir: &Path, args: &[&str]) {
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
    fn new() -> Self {
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

    fn host(&self) -> String {
        self.server.host()
    }

    /// A bare repository at `<root>/<rel>.git` with a library crate whose
    /// `value()` returns `value`; served via git's dumb HTTP protocol.
    fn git_repo(&self, rel: &str, name: &str, value: &str) -> String {
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
    fn registry(&self) -> String {
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

    fn secret(&self, name: &str) -> PathBuf {
        self.secrets.path().join(name)
    }

    /// An executable script in the secrets directory.
    fn script(&self, name: &str, body: &str) -> PathBuf {
        let path = self.secrets.path().join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// agent.toml snippet: the `file` provider for `git/acme/*`.
    fn file_provider(&self, allow: &str) -> String {
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
fn agent(fixture: &Fixture, config: &str) -> Agent {
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
    })
}

/// A project depending on `deps` (Cargo.toml dependency lines); `main`
/// prints the dependencies' `value()`s.
fn project(agent: &Agent, deps: &[(&str, String)]) -> Project {
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

fn user_config(project: &Project, text: &str) {
    let dir = project.temp.path().join("config/cargo-live");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("config.toml"), text).unwrap();
}

/// A local git credential helper that hands out `CLIENT_SECRET` for
/// `git/alfatm/*` and records each request.
fn client_git_helper(fixture: &Fixture, project: &Project) -> PathBuf {
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
fn assert_not_on_disk(dirs: &[&Path], secret: &str) {
    fn walk(dir: &Path, secret: &[u8], hits: &mut Vec<PathBuf>) {
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

fn agent_dirs(agent: &Agent) -> Vec<&Path> {
    let mut dirs = vec![agent.data.path()];
    if let Some(home) = &agent.cargo_home {
        dirs.push(home.path());
    }
    dirs
}

fn audit(agent: &Agent) -> Vec<serde_json::Value> {
    let path = agent.data.path().join("audit.log");
    let mode = fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn git_dependency_from_agent_file_provider() {
    let fixture = Fixture::new();
    let url = fixture.git_repo("git/acme/dep-a", "dep-a", "from-acme");
    let agent = agent(&fixture, &fixture.file_provider("\"*\""));
    let project = project(&agent, &[("dep-a", format!("{{ git = {url:?} }}"))]);
    let output = project.live(&["run"]);
    let err = stderr(&output);
    assert_eq!(assert_success(&output).trim(), "from-acme", "{err}");
    let host = fixture.host();
    assert!(
        err.contains(&format!(
            "cargo-live: credential for git {host}/git/acme/dep-a from agent (acme-file) (fetch phase)"
        )),
        "{err}"
    );
    let entries = audit(&agent);
    let served = entries
        .iter()
        .find(|e| e["outcome"] == "served")
        .expect("served entry");
    assert_eq!(served["source"], "agent:acme-file");
    assert_eq!(served["kind"], "git");
    assert_eq!(served["scope"], format!("{host}/git/acme/dep-a"));
    assert_eq!(served["phase"], "fetch");
    assert_eq!(served["token"], "tester");
    let ws = agent.workspace_dir(&project);
    assert_eq!(
        served["workspace"],
        ws.file_name().unwrap().to_str().unwrap()
    );
    assert!(served["ts"].as_str().unwrap().ends_with('Z'));
    assert!(agent
        .log()
        .contains("source=agent:acme-file outcome=served"));
    assert_not_on_disk(&agent_dirs(&agent), AGENT_SECRET);
    assert!(!agent.log().contains(AGENT_SECRET));
    assert!(!err.contains(AGENT_SECRET));
    // The broker is gone after the build.
    let leftovers: Vec<_> = fs::read_dir(ws.join("tmp")).unwrap().flatten().collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[test]
fn git_dependency_forwarded_from_the_client() {
    let fixture = Fixture::new();
    let url = fixture.git_repo("git/alfatm/dep-b", "dep-b", "from-client");
    let agent = agent(&fixture, "");
    let project = project(&agent, &[("dep-b", format!("{{ git = {url:?} }}"))]);
    let helper_log = client_git_helper(&fixture, &project);
    let host = fixture.host();
    user_config(
        &project,
        &format!(
            "[forward]\ngit = [\"{host}/git/alfatm/*\"]\n\n\
             [[credentials]]\nmatch = {{ kind = \"git\", host = \"{host}\", path = \"git/alfatm/*\" }}\n\
             sources = [\"client\"]\n"
        ),
    );
    let output = project.live(&["run"]);
    let err = stderr(&output);
    assert_eq!(assert_success(&output).trim(), "from-client", "{err}");
    assert!(
        err.contains(&format!(
            "credential for git {host}/git/alfatm/dep-b from client"
        )),
        "{err}"
    );
    assert_eq!(
        fs::read_to_string(helper_log).unwrap().trim(),
        "git/alfatm/dep-b"
    );
    assert!(audit(&agent)
        .iter()
        .any(|e| e["source"] == "client" && e["outcome"] == "served"));
    assert_not_on_disk(&agent_dirs(&agent), CLIENT_SECRET);
}

#[test]
fn one_build_mixes_agent_client_and_exec_registry() {
    let fixture = Fixture::new();
    let acme = fixture.git_repo("git/acme/dep-a", "dep-a", "from-acme");
    let alfatm = fixture.git_repo("git/alfatm/dep-b", "dep-b", "from-client");
    let index = fixture.registry();
    let host = fixture.host();
    let request_log = fixture.secrets.path().join("exec-requests");
    let exec = fixture.script(
        "registry-token.sh",
        &format!(
            "cat >> {request_log:?}\necho >> {request_log:?}\n\
             echo '{{\"secret\": \"{REGISTRY_TOKEN}\", \"expires_at\": 4102444800}}'\n"
        ),
    );
    let config = format!(
        "{}\n[[credentials]]\nname = \"acme-registry\"\nmatch = {{ kind = \"cargo\", registry = \"acme\" }}\n\
         provider = \"exec\"\ncommand = [{:?}]\nallow_tokens = [\"*\"]\n",
        fixture.file_provider("\"*\""),
        exec.display().to_string()
    );
    let agent = agent(&fixture, &config);
    let project = project(
        &agent,
        &[
            ("dep-a", format!("{{ git = {acme:?} }}")),
            ("dep-b", format!("{{ git = {alfatm:?} }}")),
            ("privlib", "{ version = '0.1', registry = 'acme' }".into()),
        ],
    );
    client_git_helper(&fixture, &project);
    // The registry is defined in the client's Cargo home, which is not
    // synced: the client sends the definition.
    fs::write(
        project.temp.path().join("cargo-home/config.toml"),
        format!("[registries.acme]\nindex = {index:?}\n"),
    )
    .unwrap();
    user_config(
        &project,
        &format!(
            "[forward]\ngit = [\"{host}/git/alfatm/*\"]\n\n\
             [[credentials]]\nmatch = {{ kind = \"git\", host = \"{host}\", path = \"git/alfatm/*\" }}\n\
             sources = [\"client\"]\n\
             [[credentials]]\nmatch = {{ kind = \"git\", host = \"{host}\", path = \"git/acme/*\" }}\n\
             sources = [\"agent\"]\n"
        ),
    );
    let output = project.live(&["run"]);
    let err = stderr(&output);
    assert_eq!(
        assert_success(&output).trim(),
        "from-acme\nfrom-client\nprivlib",
        "{err}"
    );
    assert!(err.contains("from agent (acme-file)"), "{err}");
    assert!(err.contains("from client"), "{err}");
    assert!(
        err.contains("credential for cargo acme from agent (acme-registry)"),
        "{err}"
    );
    let requests = fs::read_to_string(request_log).unwrap();
    let first: serde_json::Value = serde_json::from_str(requests.lines().next().unwrap()).unwrap();
    assert_eq!(first["kind"], "cargo");
    assert_eq!(first["registry"], "acme");
    assert_eq!(first["token_name"], "tester");
    assert_eq!(first["phase"], "fetch");
    let entries = audit(&agent);
    let registry = entries
        .iter()
        .find(|e| e["source"] == "agent:acme-registry")
        .unwrap();
    assert_eq!(registry["expires_at"], "2100-01-01T00:00:00Z");
    for secret in [AGENT_SECRET, CLIENT_SECRET, REGISTRY_TOKEN] {
        assert_not_on_disk(&agent_dirs(&agent), secret);
        assert!(!err.contains(secret));
    }
    assert!(fixture
        .server
        .log()
        .iter()
        .any(|l| l.starts_with("GET /registry/dl/privlib-0.1.0.crate -> 200")));
}

#[test]
fn falls_back_to_the_client_when_the_agent_provider_is_not_allowed() {
    let fixture = Fixture::new();
    let url = fixture.git_repo("git/alfatm/dep-b", "dep-b", "from-client");
    let host = fixture.host();
    // A provider for the scope exists but is not allowed for this token.
    let config = format!(
        "[[credentials]]\nname = \"other-team\"\nmatch = {{ kind = \"git\", host = \"{host}\" }}\n\
         provider = \"file\"\npath = {:?}\nallow_tokens = [\"someone-else\"]\n",
        fixture.secret("deploy-token")
    );
    let agent = agent(&fixture, &config);
    let project = project(&agent, &[("dep-b", format!("{{ git = {url:?} }}"))]);
    client_git_helper(&fixture, &project);
    // No rule: default sources [agent, client].
    user_config(
        &project,
        &format!("[forward]\ngit = [\"{host}/git/alfatm/*\"]\n"),
    );
    let output = project.live(&["run"]);
    let err = stderr(&output);
    assert_eq!(assert_success(&output).trim(), "from-client", "{err}");
    assert!(err.contains("from client"), "{err}");
    let entries = audit(&agent);
    assert!(entries.iter().any(|e| e["source"] == "client"));
    assert!(!entries.iter().any(|e| e["source"] == "agent:other-team"));
}

#[test]
fn refuses_scopes_outside_forward_with_the_chain_tried() {
    let fixture = Fixture::new();
    let url = fixture.git_repo("git/alfatm/dep-b", "dep-b", "from-client");
    let host = fixture.host();
    let agent = agent(&fixture, "");
    let project = project(&agent, &[("dep-b", format!("{{ git = {url:?} }}"))]);
    let helper_log = client_git_helper(&fixture, &project);
    user_config(&project, "[forward]\ngit = [\"github.com/alfatm/*\"]\n");
    let output = project.live(&["run"]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let err = stderr(&output);
    assert!(
        err.contains(&format!(
            "cargo-live: no credential for git {host}/git/alfatm/dep-b: \
             agent → no agent provider matches; client → not in [forward]"
        )),
        "{err}"
    );
    assert!(err.contains("`cargo fetch` failed"), "{err}");
    assert!(!helper_log.exists(), "the client resolver must not run");
    assert!(audit(&agent).iter().any(|e| e["outcome"] == "denied"));
}

#[test]
fn allow_client_false_blocks_forwarding() {
    let fixture = Fixture::new();
    let url = fixture.git_repo("git/alfatm/dep-b", "dep-b", "from-client");
    let host = fixture.host();
    let agent = agent(&fixture, "[tokens.tester]\nallow_client = false\n");
    let project = project(&agent, &[("dep-b", format!("{{ git = {url:?} }}"))]);
    let helper_log = client_git_helper(&fixture, &project);
    user_config(
        &project,
        &format!("[forward]\ngit = [\"{host}/git/alfatm/*\"]\n"),
    );
    let output = project.live(&["run"]);
    assert!(!output.status.success());
    let err = stderr(&output);
    assert!(
        err.contains("client → disabled for token \"tester\" (allow_client = false)"),
        "{err}"
    );
    assert!(!helper_log.exists());
}

const GATED_BUILD_RS: &str = r#"use std::io::Write;
use std::process::{Command, Stdio};

fn helper(server: &str) -> &'static str {
    let Ok(mut child) = Command::new("docker-credential-cargo-live")
        .arg("get")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return "missing";
    };
    child.stdin.take().unwrap().write_all(server.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status.success() && text.contains("\"Username\":\"bot\"") {
        "ok"
    } else {
        "failed"
    }
}

fn main() {
    let broker = if std::env::var_os("CARGO_LIVE_BROKER").is_some() { "present" } else { "absent" };
    let result = format!(
        "broker={broker} registry.test={} other.test={}",
        helper("registry.test"),
        helper("https://other.test/v2/")
    );
    let out = std::env::var("OUT_DIR").unwrap();
    std::fs::write(format!("{out}/result.rs"), format!("const RESULT: &str = {result:?};")).unwrap();
}
"#;

fn gated_project(agent: &Agent) -> Project {
    let project = project(agent, &[]);
    fs::write(project.root.join("build.rs"), GATED_BUILD_RS).unwrap();
    fs::write(
        project.root.join("src/main.rs"),
        "include!(concat!(env!(\"OUT_DIR\"), \"/result.rs\"));\nfn main() { println!(\"{RESULT}\"); }\n",
    )
    .unwrap();
    project
}

#[test]
fn build_scripts_get_credentials_only_for_scopes_opted_into_build() {
    let fixture = Fixture::new();
    let mut config = String::new();
    for (name, host) in [
        ("registry-test", "registry.test"),
        ("other-test", "other.test"),
    ] {
        config.push_str(&format!(
            "[[credentials]]\nname = \"{name}\"\nmatch = {{ kind = \"docker\", host = \"{host}\" }}\n\
             provider = \"file\"\npath = {:?}\nusername = \"bot\"\nallow_tokens = [\"*\"]\n",
            fixture.secret("docker-token")
        ));
    }
    let agent = agent(&fixture, &config);

    // Default phases: the build step has no broker at all.
    let default = gated_project(&agent);
    let output = default.live(&["run"]);
    assert_eq!(
        assert_success(&output).trim(),
        "broker=absent registry.test=missing other.test=missing",
        "{}",
        stderr(&output)
    );

    // registry.test opted into the build phase: its build script gets the
    // credential through the Docker helper; other.test still does not.
    let opted = gated_project(&agent);
    user_config(
        &opted,
        "[[credentials]]\nmatch = { kind = \"docker\", host = \"registry.test\" }\n\
         sources = [\"agent\"]\nphases = [\"fetch\", \"build\"]\n",
    );
    let output = opted.live(&["run"]);
    let err = stderr(&output);
    assert_eq!(
        assert_success(&output).trim(),
        "broker=present registry.test=ok other.test=failed",
        "{err}"
    );
    assert!(
        err.contains(
            "credential for docker registry.test from agent (registry-test) (build phase)"
        ),
        "{err}"
    );
    assert!(
        err.contains("no credential for docker other.test: phase build not allowed"),
        "{err}"
    );
    assert_not_on_disk(&agent_dirs(&agent), DOCKER_SECRET);
}

#[test]
fn github_app_provider_mints_repository_scoped_tokens() {
    use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
    use aws_lc_rs::signature::{KeyPair as _, UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256};

    let fixture = Fixture::new();
    let url = fixture.git_repo("gh/dep-gh", "dep-gh", "from-github-app");
    let key = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
    let der = AsDer::<Pkcs8V1Der>::as_der(&key).unwrap();
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        base64::engine::general_purpose::STANDARD.encode(der.as_ref())
    );
    fs::write(fixture.secret("gh-app.pem"), pem).unwrap();
    let public = key.public_key().as_ref().to_vec();
    let expires = "2099-12-31T23:59:59Z";
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let record = seen.clone();
    fixture.server.handle(move |req| {
        if !req.path.starts_with("/api/") {
            return None;
        }
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let jwt = req
            .headers
            .get("authorization")?
            .strip_prefix("Bearer ")?
            .to_owned();
        let parts: Vec<&str> = jwt.split('.').collect();
        let header: serde_json::Value = serde_json::from_slice(&b64.decode(parts[0]).ok()?).ok()?;
        let claims: serde_json::Value = serde_json::from_slice(&b64.decode(parts[1]).ok()?).ok()?;
        let signed = format!("{}.{}", parts[0], parts[1]);
        let valid = header == serde_json::json!({"alg": "RS256", "typ": "JWT"})
            && claims["iss"] == 4242
            && UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &public)
                .verify(signed.as_bytes(), &b64.decode(parts[2]).ok()?)
                .is_ok();
        if !valid {
            return Some(Response::json(
                401,
                serde_json::json!({"message": "Bad credentials"}),
            ));
        }
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/api/repos/gh/dep-gh/installation") => {
                record.lock().unwrap().push("installation".into());
                Some(Response::json(200, serde_json::json!({"id": 77})))
            }
            ("POST", "/api/app/installations/77/access_tokens") => {
                let body: serde_json::Value = serde_json::from_slice(&req.body).ok()?;
                record.lock().unwrap().push(format!("token {body}"));
                Some(Response::json(
                    201,
                    serde_json::json!({"token": GH_TOKEN, "expires_at": expires}),
                ))
            }
            _ => Some(Response::json(
                404,
                serde_json::json!({"message": "Not Found"}),
            )),
        }
    });
    let config = format!(
        "[[credentials]]\nname = \"gh-app\"\nmatch = {{ kind = \"git\", host = \"{}\", path = \"gh/*\" }}\n\
         provider = \"github-app\"\napp_id = 4242\nprivate_key = {{ file = {:?} }}\n\
         api_url = {:?}\npermissions = {{ contents = \"read\" }}\nallow_tokens = [\"*\"]\n",
        fixture.host(),
        fixture.secret("gh-app.pem"),
        fixture.server.url("/api"),
    );
    let agent = agent(&fixture, &config);
    let project = project(&agent, &[("dep-gh", format!("{{ git = {url:?} }}"))]);
    let output = project.live(&["run"]);
    let err = stderr(&output);
    assert_eq!(assert_success(&output).trim(), "from-github-app", "{err}");
    assert!(err.contains("from agent (gh-app)"), "{err}");
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert_eq!(seen[0], "installation");
    let body: serde_json::Value =
        serde_json::from_str(seen[1].strip_prefix("token ").unwrap()).unwrap();
    assert_eq!(
        body,
        serde_json::json!({"repositories": ["dep-gh"], "permissions": {"contents": "read"}})
    );
    let entries = audit(&agent);
    let served = entries
        .iter()
        .find(|e| e["source"] == "agent:gh-app")
        .unwrap();
    assert_eq!(served["expires_at"], expires);
    assert_not_on_disk(&agent_dirs(&agent), GH_TOKEN);
}

#[test]
fn creds_explain_reports_rules_and_sources_without_fetching() {
    let fixture = Fixture::new();
    let request_log = fixture.secrets.path().join("exec-requests");
    let exec = fixture.script(
        "token.sh",
        &format!("touch {request_log:?}\necho '{{\"secret\":\"x\"}}'\n"),
    );
    let config = format!(
        "[[credentials]]\nname = \"acme-github\"\nmatch = {{ kind = \"git\", host = \"github.com\", path = \"acme/*\" }}\n\
         provider = \"exec\"\ncommand = [{:?}]\nallow_tokens = [\"*\"]\nphases = [\"fetch\"]\n\
         [[credentials]]\nname = \"ci-only\"\nmatch = {{ kind = \"cargo\", registry = \"acme\" }}\n\
         provider = \"exec\"\ncommand = [{:?}]\nallow_tokens = [\"ci\"]\n",
        exec.display().to_string(),
        exec.display().to_string()
    );
    let agent = agent(&fixture, &config);
    let project = project(&agent, &[]);
    user_config(
        &project,
        "[forward]\ngit = [\"github.com/alfatm/*\"]\ncargo = [\"acme\"]\n\n\
         [[credentials]]\nmatch = { kind = \"git\", host = \"github.com\", path = \"acme/*\" }\n\
         sources = [\"agent\"]\nphases = [\"fetch\", \"build\"]\n",
    );
    fs::write(
        project.root.join(".cargo/live.toml"),
        format!(
            "[remote]\nurl = {:?}\n\n[[credentials]]\nmatch = {{ kind = \"docker\", host = \"ghcr.io\" }}\nsources = [\"client\"]\n",
            agent.addr
        ),
    )
    .unwrap();

    let explain = |args: &[&str]| {
        let mut full = vec!["creds", "explain"];
        full.extend_from_slice(args);
        assert_success(&project.live(&full))
    };
    let git = explain(&["git", "https://github.com/acme/foo.git"]);
    assert!(
        git.contains("credentials for git github.com/acme/foo"),
        "{git}"
    );
    assert!(
        git.contains("user rule #1 (match kind=git host=github.com path=acme/*)"),
        "{git}"
    );
    assert!(
        git.contains("[allowed] would use provider \"acme-github\" (exec)"),
        "{git}"
    );
    assert!(git.contains("build phase: agent"), "{git}");
    assert!(
        git.contains("[not allowed] not enabled for phase build (acme-github)"),
        "{git}"
    );
    assert!(git.contains("this machine"), "{git}");
    assert!(git.contains("not in [forward]"), "{git}");

    let ssh = explain(&["git", "git@github.com:alfatm/tool.git"]);
    assert!(ssh.contains("default (no matching rule)"), "{ssh}");
    assert!(
        ssh.contains("[would try] would ask the client (in [forward])"),
        "{ssh}"
    );
    assert!(ssh.contains("resolver: git credential fill"), "{ssh}");

    let cargo = explain(&["cargo", "acme"]);
    assert!(
        cargo.contains("[not allowed] not allowed for token \"tester\" (ci-only)"),
        "{cargo}"
    );
    assert!(cargo.contains("in [forward] via \"acme\""), "{cargo}");

    let docker = explain(&["docker", "ghcr.io"]);
    assert!(
        docker.contains("project rule #1 (match kind=docker host=ghcr.io)"),
        "{docker}"
    );
    assert!(
        docker.contains("[not allowed] not in [forward]"),
        "{docker}"
    );

    assert!(!request_log.exists(), "explain must not run providers");
    assert!(!agent.data.path().join("audit.log").exists());
}
