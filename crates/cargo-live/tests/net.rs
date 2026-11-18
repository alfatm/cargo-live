//! End-to-end tests of build network access: the agent's per-job proxy,
//! client tunnels over the SSH connection, mixing rules and policies. The
//! test HTTP server listens on 127.0.0.1, which the agent may not reach
//! directly (`[network] direct = []`), while the client can.
#![cfg(unix)]

mod common;

use std::fs;
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::fixture::*;
use common::*;

/// The agent may connect directly to nothing.
const NO_DIRECT: &str = "[network]\ndirect = []\n";

struct Setup {
    fixture: Fixture,
    agent: Agent,
    project: Project,
    host: String,
}

/// A project with a git dependency (client-forwarded credentials) and a
/// crate from an auth-required registry (client-forwarded token), both on
/// the test server.
fn setup(agent_config: &str) -> Setup {
    let fixture = Fixture::new();
    let url = fixture.git_repo("git/alfatm/dep-b", "dep-b", "from-client");
    let index = fixture.registry();
    let agent = agent(&fixture, agent_config);
    let mut project = project(
        &agent,
        &[
            ("dep-b", format!("{{ git = {url:?} }}")),
            ("privlib", "{ version = '0.1', registry = 'acme' }".into()),
        ],
    );
    client_git_helper(&fixture, &project);
    fs::write(
        project.temp.path().join("cargo-home/config.toml"),
        format!("[registries.acme]\nindex = {index:?}\n"),
    )
    .unwrap();
    project
        .env
        .push(("CARGO_REGISTRIES_ACME_TOKEN".into(), REGISTRY_TOKEN.into()));
    let host = fixture.host();
    Setup {
        fixture,
        agent,
        project,
        host,
    }
}

impl Setup {
    /// User config: forward the credentials, plus `extra`.
    fn user_config(&self, extra: &str) {
        user_config(
            &self.project,
            &format!(
                "[forward]\ngit = [\"{}/git/alfatm/*\"]\ncargo = [\"acme\"]\n\n{extra}",
                self.host
            ),
        );
    }

    fn net_audit(&self) -> Vec<serde_json::Value> {
        audit(&self.agent)
            .into_iter()
            .filter(|e| e["kind"] == "network")
            .collect()
    }
}

fn assert_no_secrets(text: &str) {
    for secret in [CLIENT_SECRET, REGISTRY_TOKEN, "http://cargo-live:"] {
        assert!(!text.contains(secret), "secret {secret:?} leaked:\n{text}");
    }
}

#[test]
fn fetches_git_and_registry_through_the_client_tunnel() {
    let s = setup(NO_DIRECT);
    // In [tunnel] without a rule: the default route is the client.
    s.user_config(&format!("[tunnel]\nhosts = [\"{}\"]\n", s.host));
    let output = s.project.live(&["run"]);
    let err = stderr(&output);
    assert_eq!(
        assert_success(&output).trim(),
        "from-client\nprivlib",
        "{err}"
    );
    let line = format!(
        "cargo-live: tunneling {} through this machine (fetch phase)",
        s.host
    );
    assert_eq!(err.matches(&line).count(), 1, "{err}");
    assert!(
        err.contains(&format!(
            "credential for git {}/git/alfatm/dep-b from client",
            s.host
        )),
        "{err}"
    );
    assert!(
        err.contains("credential for cargo acme from client"),
        "{err}"
    );
    let entries = s.net_audit();
    assert!(!entries.is_empty());
    let port: u16 = s.host.rsplit(':').next().unwrap().parse().unwrap();
    for e in &entries {
        assert_eq!(e["host"], "127.0.0.1");
        assert_eq!(e["port"], port);
        assert_eq!(e["via"], "client");
        assert_eq!(e["phase"], "fetch");
        assert_eq!(e["outcome"], "closed", "{e}");
        assert_eq!(e["token"], "tester");
    }
    let down: u64 = entries
        .iter()
        .map(|e| e["bytes_down"].as_u64().unwrap())
        .sum();
    assert!(down > 1000, "{entries:?}");
    assert!(entries.iter().all(|e| e["bytes_up"].as_u64().unwrap() > 0));
    let audit_text = fs::read_to_string(s.agent.data.path().join("audit.log")).unwrap();
    assert_no_secrets(&audit_text);
    assert_no_secrets(&s.agent.log());
    assert!(s
        .fixture
        .server
        .log()
        .iter()
        .any(|l| l.starts_with("GET /registry/dl/privlib-0.1.0.crate -> 200")));
}

#[test]
fn project_hints_cannot_extend_tunnel_and_failures_show_the_chain() {
    let s = setup(NO_DIRECT);
    s.user_config("");
    // The project prefers the client, but this machine's [tunnel] is empty.
    fs::write(
        s.project.root.join(".cargo/live.toml"),
        format!(
            "[remote]\nurl = {:?}\n\n[[network]]\nmatch = {{ host = \"127.0.0.1\" }}\nvia = [\"agent\", \"client\"]\n",
            s.agent.addr
        ),
    )
    .unwrap();
    let output = s.project.live(&["run"]);
    assert!(!output.status.success());
    let err = stderr(&output);
    assert!(
        err.contains(&format!(
            "cargo-live: no route to {} (fetch phase): agent → denied by the agent's [network] \
             direct; client → not in [tunnel] on the client",
            s.host
        )),
        "{err}"
    );
    assert!(err.contains("`cargo fetch` failed"), "{err}");
    assert!(s
        .net_audit()
        .iter()
        .any(|e| e["outcome"] == "denied" && e["via"] == "none"));

    // Without any rule, the default route for a host outside [tunnel] is
    // the agent alone.
    fs::write(
        s.project.root.join(".cargo/live.toml"),
        format!("[remote]\nurl = {:?}\n", s.agent.addr),
    )
    .unwrap();
    let err = stderr(&s.project.live(&["run"]));
    assert!(
        err.contains(&format!(
            "no route to {} (fetch phase): agent → denied by the agent's [network] direct\n",
            s.host
        )),
        "{err}"
    );
}

#[test]
fn allow_tunnel_false_blocks_client_tunnels() {
    let s = setup(&format!(
        "[tokens.tester]\nallow_tunnel = false\n{NO_DIRECT}"
    ));
    s.user_config(&format!("[tunnel]\nhosts = [\"{}\"]\n", s.host));
    let output = s.project.live(&["run"]);
    assert!(!output.status.success());
    let err = stderr(&output);
    // The default for a [tunnel] host falls back to a direct connection,
    // which this agent denies too.
    assert!(
        err.contains(
            "client → disabled for token \"tester\" (allow_tunnel = false); \
             agent → denied by the agent's [network] direct"
        ),
        "{err}"
    );
    assert!(!err.contains("tunneling"), "{err}");
}

#[test]
fn agent_then_client_falls_back_when_direct_is_denied() {
    let s = setup(NO_DIRECT);
    s.user_config(&format!(
        "[tunnel]\nhosts = [\"{0}\"]\n\n[[network]]\nmatch = {{ host = \"127.0.0.1\" }}\nvia = [\"agent\", \"client\"]\n",
        s.host
    ));
    let output = s.project.live(&["run"]);
    let err = stderr(&output);
    assert_eq!(
        assert_success(&output).trim(),
        "from-client\nprivlib",
        "{err}"
    );
    assert!(err.contains("through this machine (fetch phase)"), "{err}");
    assert!(s.net_audit().iter().all(|e| e["via"] == "client"));

    // With direct connections allowed, the agent connects itself.
    let fixture = &s.fixture;
    let agent = agent(fixture, &format!("[network]\ndirect = [\"{}\"]\n", s.host));
    let mut project = Project::new(&agent);
    project.env = s.project.env.clone();
    fs::copy(
        s.project.root.join("Cargo.toml"),
        project.root.join("Cargo.toml"),
    )
    .unwrap();
    fs::copy(
        s.project.root.join("src/main.rs"),
        project.root.join("src/main.rs"),
    )
    .unwrap();
    fs::create_dir_all(project.temp.path().join("config")).unwrap();
    fs::create_dir_all(project.temp.path().join("config/cargo-live")).unwrap();
    fs::copy(
        s.project.temp.path().join("config/cargo-live/config.toml"),
        project.temp.path().join("config/cargo-live/config.toml"),
    )
    .unwrap();
    let output = project.live(&["run"]);
    let err = stderr(&output);
    assert_eq!(
        assert_success(&output).trim(),
        "from-client\nprivlib",
        "{err}"
    );
    assert!(!err.contains("tunneling"), "{err}");
    let entries: Vec<_> = audit(&agent)
        .into_iter()
        .filter(|e| e["kind"] == "network")
        .collect();
    assert!(!entries.is_empty());
    assert!(entries.iter().all(|e| e["via"] == "agent"), "{entries:?}");
}

#[test]
fn fetch_keeps_the_agents_proxy_settings_without_network_config() {
    let fixture = Fixture::new();
    // A Cargo wrapper that records the environment of `cargo fetch`.
    let dump = fixture.root.path().join("fetch-env");
    let wrapper = fixture.script(
        "cargo-wrapper",
        &format!(
            "for a in \"$@\"; do [ \"$a\" = fetch ] && env > {dump:?}; done\nexec {:?} \"$@\"\n",
            cargo()
        ),
    );
    // An agent behind a corporate egress proxy, allowing every direct
    // connection (the default).
    let agent = Agent::start_with(AgentOptions {
        env: vec![
            (
                "HTTPS_PROXY".into(),
                "http://corporate-proxy.invalid:3128".into(),
            ),
            ("NO_PROXY".into(), "internal.example".into()),
        ],
        isolated_cargo_home: true,
        cargo: Some(wrapper),
        ..Default::default()
    });
    let project = Project::new(&agent);
    let output = project.live(&["run"]);
    assert_success(&output);
    let env = fs::read_to_string(&dump).unwrap();
    assert!(
        env.contains("\nHTTPS_PROXY=http://corporate-proxy.invalid:3128\n"),
        "{env}"
    );
    assert!(env.contains("\nNO_PROXY=internal.example\n"), "{env}");
    assert!(!env.contains("cargo-live:"), "{env}");
    assert!(!env.contains("http.proxy"), "{env}");
    assert!(!agent.log().contains("build proxy for the fetch step"));

    // With a [tunnel] host the proxy runs and replaces them.
    user_config(&project, "[tunnel]\nhosts = [\"gitlab.example.com\"]\n");
    assert_success(&project.live(&["run"]));
    let env = fs::read_to_string(&dump).unwrap();
    assert!(
        env.contains("\nHTTPS_PROXY=http://cargo-live:"),
        "fetch env not proxied"
    );
    assert!(!env.contains("NO_PROXY="), "NO_PROXY not removed");
    assert!(agent.log().contains("build proxy for the fetch step"));
}

const PROXY_BUILD_RS: &str = r#"fn main() {
    let vars = ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "CARGO_HTTP_PROXY"];
    let set: Vec<&str> = vars.iter().copied().filter(|v| std::env::var_os(v).is_some()).collect();
    let git = (0..64).any(|i| std::env::var(format!("GIT_CONFIG_KEY_{i}")).as_deref() == Ok("http.proxy"));
    let result = format!("proxy={set:?} git={git}");
    let out = std::env::var("OUT_DIR").unwrap();
    std::fs::write(format!("{out}/result.rs"), format!("const RESULT: &str = {result:?};")).unwrap();
}
"#;

#[test]
fn build_scripts_get_no_proxy_unless_a_rule_opts_into_build() {
    let fixture = Fixture::new();
    let agent = agent(&fixture, NO_DIRECT);
    let make = || {
        let project = project(&agent, &[]);
        fs::write(project.root.join("build.rs"), PROXY_BUILD_RS).unwrap();
        fs::write(
            project.root.join("src/main.rs"),
            "include!(concat!(env!(\"OUT_DIR\"), \"/result.rs\"));\nfn main() { println!(\"{RESULT}\"); }\n",
        )
        .unwrap();
        project
    };
    let default = make();
    user_config(
        &default,
        &format!("[tunnel]\nhosts = [\"{}\"]\n", fixture.host()),
    );
    let output = default.live(&["run"]);
    assert_eq!(
        assert_success(&output).trim(),
        "proxy=[] git=false",
        "{}",
        stderr(&output)
    );

    let opted = make();
    user_config(
        &opted,
        &format!(
            "[tunnel]\nhosts = [\"{}\"]\n\n[[network]]\nmatch = {{ host = \"127.0.0.1\" }}\nvia = [\"client\"]\nphases = [\"fetch\", \"build\"]\n",
            fixture.host()
        ),
    );
    let output = opted.live(&["run"]);
    assert_eq!(
        assert_success(&output).trim(),
        "proxy=[\"HTTPS_PROXY\", \"HTTP_PROXY\", \"https_proxy\", \"http_proxy\", \"CARGO_HTTP_PROXY\"] git=true",
        "{}",
        stderr(&output)
    );
}

/// Starts `cargo live run` and waits until its stderr contains `marker`.
fn spawn_until(project: &Project, marker: &str) -> (Child, std::path::PathBuf) {
    let log = project.temp.path().join("client-stderr.log");
    let child = project
        .command(
            std::path::Path::new(env!("CARGO_BIN_EXE_cargo-live")),
            &["live", "run"],
        )
        .stdout(Stdio::null())
        .stderr(fs::File::create(&log).unwrap())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let text = fs::read_to_string(&log).unwrap_or_default();
        if text.contains(marker) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "marker {marker:?} not seen:\n{text}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    (child, log)
}

#[test]
fn killing_the_client_mid_fetch_closes_its_tunnels() {
    let s = setup(NO_DIRECT);
    s.user_config(&format!("[tunnel]\nhosts = [\"{}\"]\n", s.host));
    // The git server hangs, keeping the tunnel open.
    let hanging = Arc::new(AtomicBool::new(false));
    let flag = hanging.clone();
    s.fixture.server.handle(move |req| {
        if req.path.starts_with("/git/alfatm/") {
            flag.store(true, Ordering::SeqCst);
            std::thread::sleep(Duration::from_secs(60));
        }
        None
    });
    let (mut child, _log) = spawn_until(&s.project, "through this machine (fetch phase)");
    let deadline = Instant::now() + Duration::from_secs(60);
    while !hanging.load(Ordering::SeqCst) {
        assert!(Instant::now() < deadline, "git never reached the server");
        std::thread::sleep(Duration::from_millis(50));
    }
    child.kill().unwrap();
    child.wait().unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let log = s.agent.log();
        if log.contains("session ended") && log.contains("via=client outcome=") {
            break;
        }
        assert!(Instant::now() < deadline, "tunnel not closed:\n{log}");
        std::thread::sleep(Duration::from_millis(100));
    }
    // The hanging tunnel was torn down when the client went away (its
    // channel closed), long before the server would have answered.
    let entries = s.net_audit();
    assert!(
        entries.iter().any(|e| e["via"] == "client"
            && e["bytes_down"] == 0
            && e["outcome"] != "idle-timeout"),
        "{entries:?}"
    );
    // The agent still serves this client afterwards.
    let explain = assert_success(&s.project.live(&["net", "explain", &s.host]));
    assert!(explain.contains("[would try] would tunnel"), "{explain}");
}

#[test]
fn net_explain_reports_rules_and_sources_without_connecting() {
    let fixture = Fixture::new();
    let agent = agent(&fixture, "[network]\ndirect = [\"*.crates.io\"]\n");
    let project = project(&agent, &[]);
    user_config(
        &project,
        "[tunnel]\nhosts = [\"gitlab.example.com\", \"*.internal:8443\"]\n\n\
         [[network]]\nmatch = { host = \"gitlab.example.com\" }\nvia = [\"agent\", \"client\"]\n",
    );
    fs::write(
        project.root.join(".cargo/live.toml"),
        format!(
            "[remote]\nurl = {:?}\n\n[[network]]\nmatch = {{ host = \"*.example.com\" }}\nvia = [\"client\"]\n",
            agent.addr
        ),
    )
    .unwrap();
    let explain = |target: &str| assert_success(&project.live(&["net", "explain", target]));

    let gitlab = explain("gitlab.example.com");
    assert!(
        gitlab.contains("network access to gitlab.example.com:443 (agent "),
        "{gitlab}"
    );
    assert!(
        gitlab.contains("user rule #1 (match host=gitlab.example.com): via = [\"agent\", \"client\"], phases = [\"fetch\"]"),
        "{gitlab}"
    );
    assert!(
        gitlab.contains("[not allowed] denied by the agent's [network] direct"),
        "{gitlab}"
    );
    assert!(
        gitlab.contains("fetch phase: client  [would try] would tunnel through this machine ([tunnel] via \"gitlab.example.com\")"),
        "{gitlab}"
    );
    assert!(
        gitlab.contains("build phase: client  [not allowed] phase build not allowed"),
        "{gitlab}"
    );
    assert!(gitlab.contains("no proxy during the build"), "{gitlab}");
    assert!(
        gitlab.contains("this machine         in [tunnel] via \"gitlab.example.com\""),
        "{gitlab}"
    );

    // A project hint for a host outside [tunnel].
    let other = explain("docs.example.com");
    assert!(
        other.contains("project rule #1 (match host=*.example.com)"),
        "{other}"
    );
    assert!(
        other.contains("[not allowed] not in [tunnel] on the client"),
        "{other}"
    );
    assert!(
        other.contains("this machine refuses to tunnel it"),
        "{other}"
    );

    // Defaults.
    let crates = explain("index.crates.io");
    assert!(
        crates.contains("default (no matching rule; not in [tunnel])"),
        "{crates}"
    );
    assert!(
        crates.contains(
            "[would try] would connect directly from the agent ([network] direct \"*.crates.io\")"
        ),
        "{crates}"
    );
    let internal = explain("db.internal:8443");
    assert!(
        internal.contains("default (no matching rule; in [tunnel] via \"*.internal:8443\")"),
        "{internal}"
    );

    let bad = project.live(&["net", "explain", "bad host"]);
    assert!(!bad.status.success());
    assert!(!agent.data.path().join("audit.log").exists());
}
