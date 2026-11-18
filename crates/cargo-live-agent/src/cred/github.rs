//! `github-app` provider: short-lived installation tokens for one repository.
//!
//! 1. An RS256 JWT signed with the App's private key (`iss` = App id,
//!    valid for 9 minutes, `iat` backdated by 60 s for clock skew).
//! 2. `GET /repos/{owner}/{repo}/installation` unless `installation_id` is
//!    configured.
//! 3. `POST /app/installations/{id}/access_tokens` with
//!    `repositories: [repo]` and the configured `permissions`.
//!
//! The token is used with the username `x-access-token`; its expiry comes
//! from the response.

use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::KeyPair;
use aws_lc_rs::signature::RSA_PKCS1_SHA256;
use base64::Engine;
use serde::Deserialize;
use zeroize::Zeroizing;

use cargo_live_proto::cred::{now_unix, parse_rfc3339, Credential, Scope, Secret};

use super::config::GithubApp;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;
const USER_AGENT: &str = concat!("cargo-live-agent/", env!("CARGO_PKG_VERSION"));

/// Parses a PEM private key: PKCS#1 (`RSA PRIVATE KEY`, what GitHub hands
/// out) or PKCS#8 (`PRIVATE KEY`).
pub fn load_key(pem: &str) -> Result<KeyPair, String> {
    let pem = pem.trim();
    let (label, body) = pem
        .strip_prefix("-----BEGIN ")
        .and_then(|rest| rest.split_once("-----"))
        .ok_or("private key is not PEM")?;
    let end = format!("-----END {label}-----");
    let body = body
        .trim()
        .strip_suffix(end.as_str())
        .ok_or("private key PEM has no matching END line")?;
    let b64: Zeroizing<String> =
        Zeroizing::new(body.chars().filter(|c| !c.is_whitespace()).collect());
    let der = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .map_err(|_| "private key PEM is not valid base64")?,
    );
    match label {
        "RSA PRIVATE KEY" => KeyPair::from_der(&der),
        "PRIVATE KEY" => KeyPair::from_pkcs8(&der),
        _ => return Err(format!("unsupported private key type {label:?}")),
    }
    .map_err(|e| format!("invalid RSA private key: {e}"))
}

/// The App JWT for `now`.
pub fn jwt(app_id: u64, now: i64, key: &KeyPair) -> Result<Secret, String> {
    let header = B64.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let claims = serde_json::json!({ "iat": now - 60, "exp": now + 540, "iss": app_id });
    let claims = B64.encode(claims.to_string());
    let signing_input = format!("{header}.{claims}");
    let mut signature = vec![0; key.public_modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        signing_input.as_bytes(),
        &mut signature,
    )
    .map_err(|_| "signing the GitHub App JWT failed")?;
    Ok(Secret::new(format!(
        "{signing_input}.{}",
        B64.encode(signature)
    )))
}

fn http() -> ureq::Agent {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let tls = ureq::tls::TlsConfig::builder()
        .provider(ureq::tls::TlsProvider::Rustls)
        .unversioned_rustls_crypto_provider(provider)
        .build();
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .http_status_as_error(false)
        .user_agent(USER_AGENT)
        .tls_config(tls)
        .build()
        .new_agent()
}

#[derive(Deserialize)]
struct Installation {
    id: u64,
}

#[derive(Deserialize)]
struct AccessToken {
    token: Secret,
    #[serde(default)]
    expires_at: Option<String>,
}

#[derive(Deserialize)]
struct ApiError {
    #[serde(default)]
    message: String,
}

fn api_error(what: &str, status: u16, body: &str) -> String {
    let message = serde_json::from_str::<ApiError>(body)
        .map(|e| e.message)
        .unwrap_or_default();
    let message: String = message.chars().take(200).collect();
    format!("GitHub API {what}: HTTP {status} {message}")
        .trim_end()
        .to_owned()
}

/// `owner/repo` from a git scope; other shapes are not GitHub repositories.
pub fn owner_repo(scope: &Scope) -> Result<(String, String), String> {
    let Scope::Git { path, .. } = scope else {
        return Err("github-app only serves git scopes".into());
    };
    let valid = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    };
    match path.split('/').collect::<Vec<_>>()[..] {
        [owner, repo] if valid(owner) && valid(repo) => Ok((owner.into(), repo.into())),
        _ => Err(format!("{path:?} is not an owner/repo path")),
    }
}

pub fn mint(app: &GithubApp, scope: &Scope) -> Result<Credential, String> {
    let (owner, repo) = owner_repo(scope)?;
    let pem = app.private_key.load()?;
    let key = load_key(pem.expose())?;
    let jwt = jwt(app.app_id, now_unix(), &key)?;
    let bearer = Zeroizing::new(format!("Bearer {}", jwt.expose()));
    let agent = http();
    let api = &app.api_url;
    let installation_id = match app.installation_id {
        Some(id) => id,
        None => {
            let mut resp = agent
                .get(&format!("{api}/repos/{owner}/{repo}/installation"))
                .header("Authorization", bearer.as_str())
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .call()
                .map_err(|e| format!("GitHub API request failed: {e}"))?;
            let status = resp.status().as_u16();
            let body = resp
                .body_mut()
                .read_to_string()
                .map_err(|e| format!("GitHub API response: {e}"))?;
            if status != 200 {
                return Err(api_error("installation lookup", status, &body));
            }
            serde_json::from_str::<Installation>(&body)
                .map_err(|_| "GitHub API returned an unexpected installation response")?
                .id
        }
    };
    let mut request = serde_json::json!({ "repositories": [repo] });
    if !app.permissions.is_empty() {
        request["permissions"] = serde_json::to_value(&app.permissions).expect("map");
    }
    let mut resp = agent
        .post(&format!(
            "{api}/app/installations/{installation_id}/access_tokens"
        ))
        .header("Authorization", bearer.as_str())
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("Content-Type", "application/json")
        .send(request.to_string().as_bytes())
        .map_err(|e| format!("GitHub API request failed: {e}"))?;
    let status = resp.status().as_u16();
    let body = Zeroizing::new(
        resp.body_mut()
            .read_to_string()
            .map_err(|e| format!("GitHub API response: {e}"))?,
    );
    if status != 201 && status != 200 {
        return Err(api_error("access token", status, &body));
    }
    let token: AccessToken = serde_json::from_str(&body)
        .map_err(|_| "GitHub API returned an unexpected access token response")?;
    Ok(Credential {
        username: Some("x-access-token".into()),
        expires_at: token.expires_at.as_deref().and_then(parse_rfc3339),
        secret: token.token,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::signature::{KeyPair as _, UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256};

    pub fn test_key_pem() -> (String, Vec<u8>) {
        let key = KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
        let der = AsDer::<aws_lc_rs::encoding::Pkcs8V1Der>::as_der(&key).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(der.as_ref());
        let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END PRIVATE KEY-----\n");
        (pem, key.public_key().as_ref().to_vec())
    }

    #[test]
    fn jwt_has_expected_header_claims_and_signature() {
        let (pem, public) = test_key_pem();
        let key = load_key(&pem).unwrap();
        let token = jwt(123456, 1_700_000_000, &key).unwrap();
        let parts: Vec<&str> = token.expose().split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: serde_json::Value =
            serde_json::from_slice(&B64.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header, serde_json::json!({"alg": "RS256", "typ": "JWT"}));
        let claims: serde_json::Value =
            serde_json::from_slice(&B64.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], 123456);
        assert_eq!(claims["iat"], 1_700_000_000 - 60);
        assert_eq!(claims["exp"], 1_700_000_000 + 540);
        let signed = format!("{}.{}", parts[0], parts[1]);
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &public)
            .verify(signed.as_bytes(), &B64.decode(parts[2]).unwrap())
            .unwrap();
    }

    #[test]
    fn rejects_bad_keys_and_paths() {
        assert!(load_key("not a key").is_err());
        assert!(
            load_key("-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----").is_err()
        );
        assert!(
            load_key("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----")
                .is_err()
        );
        assert_eq!(
            owner_repo(&Scope::git("https", "github.com", "acme/foo.git")).unwrap(),
            ("acme".into(), "foo".into())
        );
        assert!(owner_repo(&Scope::git("https", "github.com", "acme")).is_err());
        assert!(owner_repo(&Scope::git("https", "github.com", "a/b/c")).is_err());
        assert!(owner_repo(&Scope::git("https", "github.com", "a/b?x")).is_err());
    }
}
