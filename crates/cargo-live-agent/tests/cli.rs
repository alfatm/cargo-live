use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output};

fn agent(args: &[&str], data: &std::path::Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cargo-live-agent"))
        .args(args)
        .arg("--data-dir")
        .arg(data)
        .env_remove("CARGO_LIVE_AGENT_CONFIG")
        .env_remove("CARGO_LIVE_AGENT_TOKENS_FILE")
        .env_remove("CARGO_LIVE_AGENT_HOST_KEY")
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone()).unwrap()
}

#[test]
fn token_lifecycle() {
    let data = tempfile::tempdir().unwrap();
    let token = stdout(&agent(&["token", "create", "--name", "alice"], data.path()));
    let token = token.trim();
    assert!(token.starts_with("clt_"), "{token}");

    let duplicate = agent(&["token", "create", "--name", "alice"], data.path());
    assert!(!duplicate.status.success());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("already exists"));

    let tokens_file = data.path().join("tokens.toml");
    let text = fs::read_to_string(&tokens_file).unwrap();
    assert!(!text.contains(token));
    let mode = fs::metadata(&tokens_file).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);

    let list = stdout(&agent(&["token", "list"], data.path()));
    assert!(list.starts_with("alice\t"), "{list}");
    let hash = text
        .lines()
        .find_map(|l| l.strip_prefix("sha256 = "))
        .unwrap()
        .trim_matches('"');
    assert!(!list.contains(hash), "list must not show hashes");

    stdout(&agent(&["token", "revoke", "--name", "alice"], data.path()));
    assert!(!agent(&["token", "revoke", "--name", "alice"], data.path())
        .status
        .success());
    assert_eq!(stdout(&agent(&["token", "list"], data.path())), "");
}

#[test]
fn fingerprint_is_stable() {
    let data = tempfile::tempdir().unwrap();
    let first = stdout(&agent(&["fingerprint"], data.path()));
    assert!(first.starts_with("SHA256:"), "{first}");
    assert_eq!(first, stdout(&agent(&["fingerprint"], data.path())));
    let mode = fs::metadata(data.path().join("host_key"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn config_file_and_env_precedence() {
    let data = tempfile::tempdir().unwrap();
    fs::write(
        data.path().join("agent.toml"),
        "tokens_file = 'from-file.toml'\n",
    )
    .unwrap();
    stdout(&agent(&["token", "create", "--name", "a"], data.path()));
    assert!(data.path().join("from-file.toml").exists());

    // Environment beats the file.
    let output = Command::new(env!("CARGO_BIN_EXE_cargo-live-agent"))
        .args(["token", "create", "--name", "b", "--data-dir"])
        .arg(data.path())
        .env(
            "CARGO_LIVE_AGENT_TOKENS_FILE",
            data.path().join("from-env.toml"),
        )
        .output()
        .unwrap();
    stdout(&output);
    assert!(data.path().join("from-env.toml").exists());

    // The flag beats the environment.
    let output = Command::new(env!("CARGO_BIN_EXE_cargo-live-agent"))
        .args(["token", "create", "--name", "c", "--data-dir"])
        .arg(data.path())
        .arg("--tokens-file")
        .arg(data.path().join("from-flag.toml"))
        .env(
            "CARGO_LIVE_AGENT_TOKENS_FILE",
            data.path().join("from-env.toml"),
        )
        .output()
        .unwrap();
    stdout(&output);
    assert!(data.path().join("from-flag.toml").exists());
    let env_file = fs::read_to_string(data.path().join("from-env.toml")).unwrap();
    assert!(!env_file.contains("name = \"c\""));
}
