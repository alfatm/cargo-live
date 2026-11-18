//! End-to-end tests: a real cargo-live-agent on 127.0.0.1, the real client,
//! and real Cargo builds of tiny projects.
#![cfg(unix)]

mod common;

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

use common::*;

#[test]
fn run_executes_locally_from_the_local_cwd() {
    let agent = Agent::start();
    let project = Project::new(&agent);
    let stdout = assert_success(&project.live(&["run", "--", "hello"]));
    let root = project.root.canonicalize().unwrap();
    assert_eq!(
        stdout.trim(),
        format!("{}|hello|{}", root.display(), root.display())
    );
    let ws = agent.workspace_dir(&project);
    assert!(ws.join("source/src/main.rs").exists());
    assert!(!ws.join("source/target").exists(), "local target synced");
    assert!(project.root.join("target/local-sentinel").exists());
    let err = stderr(&project.live(&["run"]));
    assert!(!err.contains("__runner"), "{err}");
}

#[test]
fn shim_intercepts_short_run_behind_global_options() {
    let agent = Agent::start();
    let project = Project::new(&agent);
    let output = project.shim(&["-q", "r", "--", "x"]);
    let stdout = assert_success(&output);
    assert!(
        stdout.ends_with("|x|") || stdout.contains("|x|"),
        "{stdout}"
    );
    assert!(stderr(&output).contains("running cargo run remotely"));

    // Other commands go to the real Cargo.
    let version = assert_success(&project.shim(&["--version"]));
    assert!(version.starts_with("cargo "));
}

#[test]
fn check_emits_json_with_local_paths() {
    let agent = Agent::start();
    let project = Project::new(&agent);
    fs::write(
        project.root.join("src/main.rs"),
        "fn main() { missing_function(); }\n",
    )
    .unwrap();
    let output = project.live(&["check", "--message-format=json"]);
    assert!(!output.status.success());
    let root = project.root.canonicalize().unwrap();
    let messages: Vec<serde_json::Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).expect("stdout must be pure JSON"))
        .collect();
    let message = messages
        .iter()
        .find(|m| m["reason"] == "compiler-message")
        .expect("a compiler message");
    assert_eq!(
        message["manifest_path"],
        root.join("Cargo.toml").display().to_string()
    );
    assert_eq!(
        message["target"]["src_path"],
        root.join("src/main.rs").display().to_string()
    );
    let remote = agent.workspace_dir(&project).display().to_string();
    let text = serde_json::to_string(&messages).unwrap();
    assert!(!text.contains(&remote), "remote path leaked: {text}");
}

#[test]
fn wrong_token_is_rejected() {
    let agent = Agent::start();
    let mut project = Project::new(&agent);
    project.token = "clt_this-is-not-a-valid-token-at-all-xxxxxxxx".into();
    let output = project.live(&["run"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("rejected the token"),
        "{}",
        stderr(&output)
    );
    assert!(output.stdout.is_empty());
    assert!(!agent.data.path().join("workspaces/tester").exists());
    assert!(agent.log().contains("authentication failed"));
}

#[test]
fn missing_token_points_at_login() {
    let agent = Agent::start();
    let mut project = Project::new(&agent);
    project.token = String::new();
    let output = project.live(&["run"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("cargo live login"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn login_saves_token_after_verification() {
    let agent = Agent::start();
    let project = Project::new(&agent);
    let mut login = project
        .command(
            Path::new(env!("CARGO_BIN_EXE_cargo-live")),
            &["live", "login", &agent.addr],
        )
        .env_remove("CARGO_LIVE_TOKEN")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    writeln!(login.stdin.take().unwrap(), "{}", agent.token).unwrap();
    let output = login.wait_with_output().unwrap();
    assert_success(&output);
    let credentials = project
        .temp
        .path()
        .join("config/cargo-live/credentials.toml");
    assert!(fs::read_to_string(&credentials)
        .unwrap()
        .contains(&agent.token));

    // Now works without CARGO_LIVE_TOKEN.
    let run = project
        .command(
            Path::new(env!("CARGO_BIN_EXE_cargo-live")),
            &["live", "run", "--", "y"],
        )
        .env_remove("CARGO_LIVE_TOKEN")
        .output()
        .unwrap();
    assert!(assert_success(&run).contains("|y|"));

    let logout = project
        .command(
            Path::new(env!("CARGO_BIN_EXE_cargo-live")),
            &["live", "logout", &agent.addr],
        )
        .output()
        .unwrap();
    assert_success(&logout);
    assert!(!fs::read_to_string(&credentials)
        .unwrap()
        .contains(&agent.token));
}

#[test]
fn host_key_pin_and_known_hosts_mismatch_are_rejected_before_auth() {
    let agent = Agent::start();
    let project = Project::new(&agent);
    let wrong = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    project.write_config(&agent.addr, Some(wrong));
    let output = project.live(&["run"]);
    assert!(!output.status.success());
    let err = stderr(&output);
    assert!(err.contains("host key mismatch"), "{err}");
    assert!(err.contains(&agent.fingerprint()), "{err}");
    let log = agent.log();
    assert!(!log.contains("authentication"), "token was sent: {log}");

    // The correct pin works.
    project.write_config(&agent.addr, Some(&agent.fingerprint()));
    assert_success(&project.live(&["run"]));

    // Trust on first use, then a changed key is refused.
    project.write_config(&agent.addr, None);
    let first = project.live(&["run"]);
    assert_success(&first);
    assert!(stderr(&first).contains("trusting new host key"));
    let known_hosts = project.temp.path().join("config/cargo-live/known_hosts");
    let text = fs::read_to_string(&known_hosts).unwrap();
    assert!(text.contains(&agent.fingerprint()));
    fs::write(&known_hosts, format!("{} {wrong}\n", agent.addr)).unwrap();
    let output = project.live(&["run"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("host key mismatch"));
    assert!(stderr(&output).contains("known_hosts"));
}

#[test]
fn build_failure_does_not_run_a_stale_binary() {
    let agent = Agent::start();
    let project = Project::new(&agent);
    assert_success(&project.live(&["run", "--", "first"]));
    fs::write(project.root.join("src/main.rs"), "fn main() { nope }\n").unwrap();
    let output = project.live(&["run", "--", "stale"]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stale binary ran");
    assert!(
        stderr(&output).contains("could not compile"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn incremental_sync_and_deletion() {
    let agent = Agent::start();
    let project = Project::new(&agent);
    fs::write(project.root.join("extra.txt"), "x").unwrap();
    assert_success(&project.live(&["run"]));
    let source = agent.workspace_dir(&project).join("source");
    assert!(source.join("extra.txt").exists());

    // The project has no local Cargo.lock: the one Cargo generated remotely
    // is kept rather than deleted and re-resolved on every sync.
    assert!(source.join("Cargo.lock").exists());
    let second = project.live(&["run"]);
    assert_success(&second);
    assert!(
        stderr(&second).contains(": 0 files sent (0 B), 0 deleted"),
        "{}",
        stderr(&second)
    );
    assert!(stderr(&second).contains("executable unchanged"));

    fs::remove_file(project.root.join("extra.txt")).unwrap();
    assert_success(&project.live(&["run"]));
    assert!(!source.join("extra.txt").exists());
}

#[test]
fn runner_selects_default_run_among_multiple_binaries() {
    let agent = Agent::start();
    let project = Project::new(&agent);
    fs::write(
        project.root.join("Cargo.toml"),
        "[package]\nname = 'multi'\nversion = '0.1.0'\nedition = '2021'\ndefault-run = 'second'\n\n\
         [[bin]]\nname = 'first'\npath = 'src/first.rs'\n\n[[bin]]\nname = 'second'\npath = 'src/second.rs'\n",
    )
    .unwrap();
    fs::remove_file(project.root.join("src/main.rs")).unwrap();
    fs::write(
        project.root.join("src/first.rs"),
        "fn main() { println!(\"first\"); }",
    )
    .unwrap();
    fs::write(
        project.root.join("src/second.rs"),
        "fn main() { println!(\"second {}\", std::env::args().nth(1).unwrap_or_default()); }",
    )
    .unwrap();
    assert_eq!(
        assert_success(&project.live(&["run", "--", "z"])).trim(),
        "second z"
    );
    assert_eq!(
        assert_success(&project.live(&["run", "--bin", "first"])).trim(),
        "first"
    );
}

/// Starts `cargo live run` and returns it once a stderr line contains
/// `marker`.
fn spawn_until(project: &Project, marker: &str) -> Child {
    let mut client = project
        .command(
            Path::new(env!("CARGO_BIN_EXE_cargo-live")),
            &["live", "run"],
        )
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut reader = BufReader::new(client.stderr.take().unwrap());
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut line = String::new();
    loop {
        line.clear();
        assert!(
            reader.read_line(&mut line).unwrap() > 0,
            "client exited before {marker:?}"
        );
        if line.contains(marker) {
            break;
        }
        assert!(Instant::now() < deadline, "no {marker:?}");
    }
    // Keep draining stderr so the client never blocks on a full pipe.
    std::thread::spawn(move || std::io::copy(&mut reader, &mut std::io::sink()));
    client
}

#[test]
fn client_leaving_the_lock_queue_is_noticed_promptly() {
    let agent = Agent::start();
    let project = Project::new(&agent);
    fs::write(
        project.root.join("build.rs"),
        "fn main() { std::thread::sleep(std::time::Duration::from_secs(120)); }\n",
    )
    .unwrap();
    let mut holder = spawn_until(&project, "Compiling fixture-app");
    let mut waiter = spawn_until(&project, "waiting for remote workspace lock");
    waiter.kill().unwrap();
    waiter.wait().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !agent
        .log()
        .contains("client disconnected while waiting for the workspace lock")
    {
        assert!(
            Instant::now() < deadline,
            "agent did not notice:\n{}",
            agent.log()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    holder.kill().unwrap();
    holder.wait().unwrap();
}

#[test]
fn killing_the_client_mid_build_releases_the_lock() {
    let agent = Agent::start();
    let project = Project::new(&agent);
    fs::write(
        project.root.join("build.rs"),
        "fn main() { std::thread::sleep(std::time::Duration::from_secs(120)); }\n",
    )
    .unwrap();
    // Wait until the remote build is running the slow build script.
    let mut client = spawn_until(&project, "Compiling fixture-app");
    std::thread::sleep(Duration::from_millis(500));
    client.kill().unwrap();
    client.wait().unwrap();

    fs::write(project.root.join("build.rs"), "fn main() {}\n").unwrap();
    let started = Instant::now();
    let output = project.live(&["run", "--", "after"]);
    assert!(assert_success(&output).contains("|after|"));
    assert!(
        started.elapsed() < Duration::from_secs(40),
        "second run took {:?}",
        started.elapsed()
    );
    assert!(
        agent.log().contains("client disconnected"),
        "{}",
        agent.log()
    );
}
