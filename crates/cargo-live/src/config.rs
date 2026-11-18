use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use cargo_live_proto::{ExcludeSet, DEFAULT_PORT};

use crate::creds::ProjectRule;
use crate::net::ProjectNetRule;
use crate::{error, Result};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub remote: Remote,
    #[serde(default)]
    pub sync: Sync,
    /// Credential source hints (`[[credentials]]` with match + sources).
    #[serde(default)]
    pub credentials: Vec<ProjectRule>,
    /// Network route hints (`[[network]]` with match + via).
    #[serde(default)]
    pub network: Vec<ProjectNetRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Remote {
    /// `host[:port]` of a cargo-live-agent.
    pub url: String,
    /// Optional pinned host key fingerprint (`SHA256:...`).
    #[serde(default)]
    pub host_key: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sync {
    #[serde(default)]
    pub exclude: Vec<String>,
}

/// A parsed agent address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentUrl {
    pub host: String,
    pub port: u16,
}

impl fmt::Display for AgentUrl {
    /// The canonical `host:port` form, used as the key in known_hosts and
    /// credentials.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

impl AgentUrl {
    pub fn parse(url: &str) -> Result<Self> {
        let invalid = || {
            error(format!(
                "invalid agent url {url:?}; expected host or host:port"
            ))
        };
        let rest = url.strip_prefix("ssh://").unwrap_or(url);
        let (host, port) = if let Some(rest) = rest.strip_prefix('[') {
            let (host, after) = rest.split_once(']').ok_or_else(invalid)?;
            let port = match after {
                "" => None,
                p => Some(p.strip_prefix(':').ok_or_else(invalid)?),
            };
            (host, port)
        } else {
            match rest.rsplit_once(':') {
                Some((host, port)) if !host.contains(':') => (host, Some(port)),
                Some(_) => return Err(invalid().into()),
                None => (rest, None),
            }
        };
        let port = match port {
            Some(p) => p
                .parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(invalid)?,
            None => DEFAULT_PORT,
        };
        if host.is_empty()
            || host.starts_with('-')
            || !host
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_' | b':'))
        {
            return Err(invalid().into());
        }
        Ok(Self {
            host: host.to_ascii_lowercase(),
            port,
        })
    }
}

impl Config {
    pub fn find(cwd: &Path) -> Result<Option<(PathBuf, Self)>> {
        for dir in cwd.ancestors() {
            let path = dir.join(".cargo").join("live.toml");
            if path.is_file() {
                let text = fs::read_to_string(&path)?;
                let config = Self::parse(&text)
                    .map_err(|e| error(format!("invalid {}: {e}", path.display())))?;
                return Ok(Some((dir.to_path_buf(), config)));
            }
        }
        Ok(None)
    }

    pub fn parse(text: &str) -> Result<Self> {
        let config: Config = toml::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    pub fn url(&self) -> Result<AgentUrl> {
        AgentUrl::parse(&self.remote.url)
    }

    pub fn excludes(&self) -> Result<ExcludeSet> {
        Ok(ExcludeSet::new(&self.sync.exclude)?)
    }

    fn validate(&self) -> Result<()> {
        self.url()?;
        if let Some(key) = &self.remote.host_key {
            if !is_fingerprint(key) {
                return Err(error(
                    "remote.host_key must look like SHA256:<base64> \
                     (see `cargo-live-agent fingerprint`)",
                )
                .into());
            }
        }
        for pattern in &self.sync.exclude {
            if pattern.is_empty() || pattern.contains('\n') {
                return Err(
                    error("sync.exclude entries must be nonempty single-line patterns").into(),
                );
            }
        }
        self.excludes()?;
        for hint in &self.credentials {
            hint.validate()?;
        }
        for hint in &self.network {
            hint.validate()?;
        }
        Ok(())
    }
}

pub fn is_fingerprint(value: &str) -> bool {
    value.strip_prefix("SHA256:").is_some_and(|b64| {
        b64.len() == 43
            && b64
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";

    #[test]
    fn parses_urls() {
        let u = AgentUrl::parse("Build-Host").unwrap();
        assert_eq!(u.to_string(), "build-host:2222");
        assert_eq!(AgentUrl::parse("h:22").unwrap().port, 22);
        assert_eq!(AgentUrl::parse("ssh://h:22").unwrap().to_string(), "h:22");
        assert_eq!(
            AgentUrl::parse("[::1]:3000").unwrap().to_string(),
            "[::1]:3000"
        );
        assert_eq!(AgentUrl::parse("[::1]").unwrap().port, 2222);
        for bad in ["", ":22", "h:0", "h:x", "-oProxy", "a b", "h:22:33", "[::1"] {
            assert!(AgentUrl::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn validates_config() {
        let good = Config::parse(&format!(
            "[remote]\nurl = 'build:2222'\nhost_key = '{FP}'\n[sync]\nexclude = ['/.env']\n"
        ))
        .unwrap();
        assert_eq!(good.url().unwrap().to_string(), "build:2222");
        let hints = Config::parse(
            "[remote]\nurl = 'a'\n[[credentials]]\nmatch = { kind = 'git', host = 'github.com' }\nsources = ['agent', 'client']\n",
        )
        .unwrap();
        assert_eq!(hints.credentials.len(), 1);
        let net = Config::parse(
            "[remote]\nurl = 'a'\n[[network]]\nmatch = { host = 'gitlab.volka.com', port = 443 }\nvia = ['client']\n",
        )
        .unwrap();
        assert_eq!(net.network.len(), 1);
        for text in [
            "[remote]\nhost = 'old'\nbase_dir = '/x'\n",
            "[remote]\nurl = 'a;b'\n",
            "[remote]\nurl = 'a'\nhost_key = 'MD5:xx'\n",
            "[remote]\nurl = 'a'\n[sync]\nexclude = ['']\n",
            "[remote]\nurl = 'a'\n[sync]\nexclude = ['/']\n",
            "[remote]\nurl = 'a'\nunknown = 1\n",
            // Project hints cannot set phases or extend [forward].
            "[remote]\nurl = 'a'\n[[credentials]]\nmatch = { kind = 'git' }\nsources = ['client']\nphases = ['build']\n",
            "[remote]\nurl = 'a'\n[forward]\ngit = ['*']\n",
            "[remote]\nurl = 'a'\n[[credentials]]\nmatch = { kind = 'git' }\nsources = []\n",
            // Network hints cannot set phases or extend [tunnel].
            "[remote]\nurl = 'a'\n[[network]]\nmatch = { host = 'h' }\nvia = ['client']\nphases = ['build']\n",
            "[remote]\nurl = 'a'\n[tunnel]\nhosts = ['*']\n",
            "[remote]\nurl = 'a'\n[[network]]\nmatch = { host = 'h' }\nvia = []\n",
        ] {
            assert!(Config::parse(text).is_err(), "{text}");
        }
    }
}
