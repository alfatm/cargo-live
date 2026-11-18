//! Agent providers: `exec`, `file`, `env` and `github-app`.

use cargo_live_proto::cred::{parse_command_output, run_command, Credential, Phase, Scope};
use zeroize::Zeroizing;

use super::config::{Provider, ProviderKind};
use super::github;

/// Fetches a credential from `provider`. Errors never contain secrets.
pub async fn fetch(
    provider: &Provider,
    scope: &Scope,
    token: &str,
    phase: Phase,
) -> Result<Credential, String> {
    match &provider.kind {
        ProviderKind::File { path, username }
        | ProviderKind::Env {
            var: path,
            username,
        } => {
            let secret = path.load()?;
            Ok(Credential {
                username: username.clone(),
                secret,
                expires_at: None,
            })
        }
        ProviderKind::Exec { command, timeout } => {
            let mut request = scope.to_json();
            request.insert("token_name".into(), token.into());
            request.insert("phase".into(), phase.to_string().into());
            let stdin = serde_json::Value::Object(request).to_string();
            let (command, timeout) = (command.clone(), *timeout);
            tokio::task::spawn_blocking(move || {
                let out: Zeroizing<Vec<u8>> =
                    run_command(&command, stdin.as_bytes(), timeout, &[])?;
                parse_command_output(&out, false)
            })
            .await
            .map_err(|_| "exec provider task failed".to_string())?
        }
        ProviderKind::GithubApp(app) => {
            let (app, scope) = (app.clone(), scope.clone());
            tokio::task::spawn_blocking(move || github::mint(&app, &scope))
                .await
                .map_err(|_| "github-app provider task failed".to_string())?
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cred::config::SecretRef;
    use cargo_live_proto::cred::{CredMatch, Kind};
    use std::time::Duration;

    fn exec(script: &str, timeout: Duration) -> Provider {
        Provider {
            name: "t".into(),
            matcher: CredMatch {
                kind: Kind::Cargo,
                host: None,
                path: None,
                registry: None,
                index: None,
            },
            allow_tokens: vec!["*".into()],
            phases: None,
            kind: ProviderKind::Exec {
                command: vec!["sh".into(), "-c".into(), script.into()],
                timeout,
            },
        }
    }

    fn scope() -> Scope {
        Scope::cargo(Some("acme"), Some("sparse+http://r/"))
    }

    #[tokio::test]
    async fn exec_provider_success_timeout_and_bad_output() {
        // The request JSON arrives on stdin.
        let p = exec(
            r#"read line; case "$line" in *'"registry":"acme"'*'"token_name":"tok"'*) echo '{"secret":"s3","username":"u","expires_at":42}';; *) exit 9;; esac"#,
            Duration::from_secs(10),
        );
        let c = fetch(&p, &scope(), "tok", Phase::Fetch).await.unwrap();
        assert_eq!(
            (c.secret.expose(), c.username.as_deref(), c.expires_at),
            ("s3", Some("u"), Some(42))
        );

        let p = exec("sleep 10", Duration::from_millis(200));
        let err = fetch(&p, &scope(), "tok", Phase::Fetch).await.unwrap_err();
        assert!(err.contains("timed out"), "{err}");

        let p = exec("echo plain-secret-value", Duration::from_secs(10));
        let err = fetch(&p, &scope(), "tok", Phase::Fetch).await.unwrap_err();
        assert!(!err.contains("plain-secret-value"), "{err}");

        let p = exec("echo '{\"secret\": 1}'", Duration::from_secs(10));
        assert!(fetch(&p, &scope(), "tok", Phase::Fetch).await.is_err());

        let p = exec("exit 3", Duration::from_secs(10));
        assert!(fetch(&p, &scope(), "tok", Phase::Fetch).await.is_err());
    }

    #[tokio::test]
    async fn file_provider_trims_and_rejects_empty() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("t"), "deploy-token\n").unwrap();
        std::fs::write(dir.path().join("empty"), "\n").unwrap();
        let mut p = exec("", Duration::from_secs(1));
        p.kind = ProviderKind::File {
            path: SecretRef::File(dir.path().join("t")),
            username: Some("bot".into()),
        };
        let c = fetch(&p, &scope(), "tok", Phase::Fetch).await.unwrap();
        assert_eq!(
            (c.secret.expose(), c.username.as_deref()),
            ("deploy-token", Some("bot"))
        );
        p.kind = ProviderKind::File {
            path: SecretRef::File(dir.path().join("empty")),
            username: None,
        };
        assert!(fetch(&p, &scope(), "tok", Phase::Fetch).await.is_err());
    }
}
