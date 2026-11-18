//! Helper modes of the agent binary, run by tools that Cargo starts:
//!
//! - `cargo-live-agent __cred git get|store|erase`: git credential helper;
//! - `cargo-live-agent __cred cargo --cargo-plugin`: Cargo credential
//!   provider (credential provider protocol v1);
//! - argv[0] `docker-credential-cargo-live get|store|erase|list`: Docker
//!   credential helper.
//!
//! Each asks the job's broker (see [`super::broker`]) and prints the answer
//! in the tool's format. Failures print only a generic message; details are
//! in the agent log, the audit log and the client's output.

use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{self, BufRead, Read, Write};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use cargo_live_proto::cred::{Credential, Scope};

use super::broker;

type Resolver<'a> = &'a dyn Fn(&Scope) -> Result<Credential, String>;

/// `__cred <git|cargo> ...`
pub fn cred_main(args: &[OsString]) -> i32 {
    let args: Vec<String> = args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let resolver: Resolver<'_> = &broker::request;
    match args.first().map(String::as_str) {
        Some("git") => git_main(args.get(1).map(String::as_str), resolver),
        Some("cargo") => cargo_main(resolver),
        _ => {
            eprintln!("cargo-live-agent: __cred is used by cargo-live builds (git or cargo)");
            2
        }
    }
}

// ---------------------------------------------------------------- git

/// Parses git's `key=value` lines up to a blank line or EOF.
pub fn parse_git_input(input: &str) -> HashMap<String, String> {
    input
        .lines()
        .take_while(|l| !l.is_empty())
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

/// The scope for a git request, or `None` for non-HTTP protocols.
pub fn git_scope(input: &HashMap<String, String>) -> Option<Scope> {
    let protocol = input.get("protocol")?;
    if protocol != "https" && protocol != "http" {
        return None;
    }
    let host = input.get("host")?;
    Some(Scope::git(
        protocol,
        host,
        input.get("path").map(String::as_str).unwrap_or(""),
    ))
}

pub fn format_git_output(c: &Credential, requested_user: Option<&str>) -> Zeroizing<String> {
    let username = c.username.as_deref().or(requested_user).unwrap_or("git");
    let mut out = Zeroizing::new(format!(
        "username={username}\npassword={}\n",
        c.secret.expose()
    ));
    if let Some(expiry) = c.expires_at {
        out.push_str(&format!("password_expiry_utc={expiry}\n"));
    }
    out
}

fn git_main(op: Option<&str>, resolve: Resolver<'_>) -> i32 {
    let mut input = Zeroizing::new(String::new());
    let _ = io::stdin().read_to_string(&mut input);
    // store/erase: nothing is stored on the agent.
    if op != Some("get") {
        return 0;
    }
    let fields = parse_git_input(&input);
    let Some(scope) = git_scope(&fields) else {
        return 0;
    };
    match resolve(&scope) {
        Ok(c) => {
            let out = format_git_output(&c, fields.get("username").map(String::as_str));
            let mut stdout = io::stdout().lock();
            let _ = stdout.write_all(out.as_bytes());
            let _ = stdout.flush();
            0
        }
        Err(e) => {
            eprintln!("cargo-live: {scope}: {e}");
            // Exit 0 without output: git goes on and fails authentication.
            0
        }
    }
}

// -------------------------------------------------------------- cargo

pub const CARGO_HELLO: &str = r#"{"v":[1]}"#;

#[derive(Deserialize)]
struct CargoRequest {
    v: u32,
    kind: String,
    // `operation` (read, publish, yank, owners, ...) does not matter: the
    // same credential is answered for every `get`.
    registry: CargoRegistry,
}

#[derive(Deserialize)]
struct CargoRegistry {
    #[serde(rename = "index-url")]
    index_url: String,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Serialize)]
enum CargoResponse<'a> {
    Ok(GetOk<'a>),
    Err(CargoError),
}

#[derive(Serialize)]
struct GetOk<'a> {
    kind: &'static str,
    token: &'a str,
    cache: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    expiration: Option<i64>,
    operation_independent: bool,
}

#[derive(Serialize)]
struct CargoError {
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

fn cargo_error(kind: &'static str, message: Option<String>) -> Zeroizing<String> {
    Zeroizing::new(
        serde_json::to_string(&CargoResponse::Err(CargoError { kind, message }))
            .expect("serializable"),
    )
}

/// Answers one request line of the credential provider protocol.
pub fn cargo_response(line: &str, resolve: Resolver<'_>) -> Zeroizing<String> {
    let request: CargoRequest = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(_) => {
            return cargo_error(
                "other",
                Some("cargo-live: malformed credential request".into()),
            )
        }
    };
    if request.v != 1 {
        return cargo_error(
            "other",
            Some(format!(
                "cargo-live: unsupported protocol version {}",
                request.v
            )),
        );
    }
    if request.kind != "get" {
        // login/logout: nothing is stored on the agent.
        return cargo_error("operation-not-supported", None);
    }
    let scope = Scope::cargo(
        request.registry.name.as_deref(),
        Some(&request.registry.index_url),
    );
    match resolve(&scope) {
        Ok(c) => Zeroizing::new(
            serde_json::to_string(&CargoResponse::Ok(GetOk {
                kind: "get",
                token: c.secret.expose(),
                cache: if c.expires_at.is_some() {
                    "expires"
                } else {
                    "never"
                },
                expiration: c.expires_at,
                operation_independent: true,
            }))
            .expect("serializable"),
        ),
        Err(e) => cargo_error(
            "other",
            Some(format!("cargo-live: registry `{scope}`: {e}")),
        ),
    }
}

fn cargo_main(resolve: Resolver<'_>) -> i32 {
    let mut stdout = io::stdout().lock();
    if writeln!(stdout, "{CARGO_HELLO}")
        .and_then(|_| stdout.flush())
        .is_err()
    {
        return 1;
    }
    let stdin = io::stdin();
    let mut line = Zeroizing::new(String::new());
    loop {
        line.clear();
        match stdin.lock().read_line(&mut line) {
            Ok(0) | Err(_) => return 0,
            Ok(_) => {}
        }
        if line.trim().is_empty() {
            continue;
        }
        let mut out = cargo_response(line.trim(), resolve);
        out.push('\n');
        if stdout
            .write_all(out.as_bytes())
            .and_then(|_| stdout.flush())
            .is_err()
        {
            return 1;
        }
    }
}

// ------------------------------------------------------------- docker

const DOCKER_NOT_FOUND: &str = "credentials not found in native keychain";

#[derive(Serialize)]
struct DockerCredential<'a> {
    #[serde(rename = "ServerURL")]
    server_url: &'a str,
    #[serde(rename = "Username")]
    username: &'a str,
    #[serde(rename = "Secret")]
    secret: &'a str,
}

/// `get`: server URL on stdin, JSON credential on stdout.
pub fn docker_get(server: &str, resolve: Resolver<'_>) -> Result<Zeroizing<String>, String> {
    let server = server.trim();
    if server.is_empty() {
        return Err("no server URL".into());
    }
    let c = resolve(&Scope::docker(server))?;
    Ok(Zeroizing::new(
        serde_json::to_string(&DockerCredential {
            server_url: server,
            username: c.username.as_deref().unwrap_or("cargo-live"),
            secret: c.secret.expose(),
        })
        .expect("serializable"),
    ))
}

pub fn docker_main(args: &[OsString]) -> i32 {
    let op = args.first().map(|a| a.to_string_lossy().into_owned());
    let mut input = Zeroizing::new(String::new());
    match op.as_deref() {
        Some("get") => {
            let _ = io::stdin().read_to_string(&mut input);
            match docker_get(&input, &broker::request) {
                Ok(out) => {
                    println!("{}", out.as_str());
                    0
                }
                Err(e) => {
                    eprintln!("cargo-live: docker registry {}: {e}", input.trim());
                    // Docker recognizes this message as "not found".
                    println!("{DOCKER_NOT_FOUND}");
                    1
                }
            }
        }
        Some("store") | Some("erase") => {
            // Nothing is stored on the agent.
            let _ = io::stdin().read_to_string(&mut input);
            0
        }
        Some("list") => {
            println!("{{}}");
            0
        }
        Some("version") => {
            println!("cargo-live {}", env!("CARGO_PKG_VERSION"));
            0
        }
        _ => {
            eprintln!("usage: docker-credential-cargo-live <get|store|erase|list>");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cargo_live_proto::cred::Secret;

    fn cred(expires_at: Option<i64>) -> Credential {
        Credential {
            username: Some("x-access-token".into()),
            secret: Secret::new("ghs_abc"),
            expires_at,
        }
    }

    #[test]
    fn git_helper_protocol() {
        let input =
            "protocol=https\nhost=github.com\npath=acme/foo.git\nusername=me\n\nignored=1\n";
        let fields = parse_git_input(input);
        assert_eq!(fields.len(), 4);
        assert_eq!(
            git_scope(&fields).unwrap(),
            Scope::git("https", "github.com", "acme/foo")
        );
        let ssh = parse_git_input("protocol=ssh\nhost=github.com\n");
        assert!(git_scope(&ssh).is_none());
        assert_eq!(
            format_git_output(&cred(Some(1700000000)), Some("me")).as_str(),
            "username=x-access-token\npassword=ghs_abc\npassword_expiry_utc=1700000000\n"
        );
        let mut c = cred(None);
        c.username = None;
        assert_eq!(
            format_git_output(&c, Some("me")).as_str(),
            "username=me\npassword=ghs_abc\n"
        );
        assert_eq!(
            format_git_output(&c, None).as_str(),
            "username=git\npassword=ghs_abc\n"
        );
    }

    #[test]
    fn cargo_provider_messages() {
        use serde_json::{json, Value};
        let seen = std::cell::RefCell::new(None);
        let ok = |scope: &Scope| {
            *seen.borrow_mut() = Some(scope.clone());
            Ok(cred(Some(1693942857)))
        };
        assert_eq!(
            serde_json::from_str::<Value>(CARGO_HELLO).unwrap(),
            json!({"v": [1]})
        );
        // Read request, exactly as documented.
        let read = r#"{"v":1,"kind":"get","operation":"read","registry":{"index-url":"sparse+https://registry-url/index/","name":"my-registry","headers":["WWW-Authenticate: cargo"]},"args":[]}"#;
        let out: Value = serde_json::from_str(&cargo_response(read, &ok)).unwrap();
        assert_eq!(
            out,
            json!({"Ok": {"kind": "get", "token": "ghs_abc", "cache": "expires",
                          "expiration": 1693942857, "operation_independent": true}})
        );
        assert_eq!(
            seen.borrow().clone().unwrap(),
            Scope::cargo(
                Some("my-registry"),
                Some("sparse+https://registry-url/index/")
            )
        );
        // Without expiry: never cache.
        let never = |_: &Scope| Ok(cred(None));
        let publish = r#"{"v":1,"kind":"get","operation":"publish","name":"sample","vers":"0.1.0","cksum":"abc","registry":{"index-url":"sparse+https://registry-url/index/"},"args":[]}"#;
        let out: Value = serde_json::from_str(&cargo_response(publish, &never)).unwrap();
        assert_eq!(out["Ok"]["cache"], "never");
        assert!(out["Ok"].get("expiration").is_none());
        // login/logout are refused.
        let login = r#"{"v":1,"kind":"login","registry":{"index-url":"sparse+https://registry-url/index/","name":"my-registry"},"token":"x","args":[]}"#;
        let out: Value = serde_json::from_str(&cargo_response(login, &ok)).unwrap();
        assert_eq!(out, json!({"Err": {"kind": "operation-not-supported"}}));
        let logout = r#"{"v":1,"kind":"logout","registry":{"index-url":"x"}}"#;
        let out: Value = serde_json::from_str(&cargo_response(logout, &ok)).unwrap();
        assert_eq!(out["Err"]["kind"], "operation-not-supported");
        // Failures are "other" with a message and no details.
        let fail = |_: &Scope| Err(broker::GENERIC_ERROR.to_owned());
        let out: Value = serde_json::from_str(&cargo_response(read, &fail)).unwrap();
        assert_eq!(out["Err"]["kind"], "other");
        assert!(out["Err"]["message"]
            .as_str()
            .unwrap()
            .contains("my-registry"));
        let out: Value = serde_json::from_str(&cargo_response("{", &ok)).unwrap();
        assert_eq!(out["Err"]["kind"], "other");
    }

    #[test]
    fn docker_helper_io() {
        let seen = std::cell::RefCell::new(None);
        let ok = |scope: &Scope| {
            *seen.borrow_mut() = Some(scope.clone());
            Ok(cred(None))
        };
        let out = docker_get("https://ghcr.io\n", &ok).unwrap();
        let value: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            value,
            serde_json::json!({"ServerURL": "https://ghcr.io", "Username": "x-access-token", "Secret": "ghs_abc"})
        );
        assert_eq!(seen.borrow().clone().unwrap(), Scope::docker("ghcr.io"));
        assert!(docker_get("", &ok).is_err());
        assert!(docker_get("ghcr.io", &|_: &Scope| Err("x".into())).is_err());
    }
}
