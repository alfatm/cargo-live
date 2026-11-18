# cargo-live

Experimental remote Rust builds with local execution. `cargo live run` sends
your workspace to a build host running `cargo-live-agent`, builds it there,
and copies **only the selected executable** back to run it on your machine.
`cargo live check` runs `cargo check` remotely and streams the diagnostics
back with local paths, so rust-analyzer's check-on-save can use the build
host too.

An optional `cargo` shim makes plain `cargo run` (and `cargo r`) build
remotely in configured workspaces. A configured remote build fails rather
than silently falling back to a local build, and a stale binary is never run
after a failed build or transfer.

## How it works

The project is three crates:

- `cargo-live` (client, your machine): the `cargo live` subcommand and the
  optional `cargo` shim. It has a built-in SSH client and does **not** use the
  system `ssh`, `rsync` or `~/.ssh/config`.
- `cargo-live-agent` (build host): a single binary with a built-in SSH
  server. It needs only Cargo and rustc; it does not use `sh`, `ssh`,
  `rsync`, `flock` or `setsid`. It is meant to run in a container.
- `cargo-live-proto`: the framed protocol shared by both.

One build is one SSH connection:

1. SSH handshake; the client verifies the agent's host key **before**
   sending the token, then authenticates with the token.
2. Version handshake. The agent reports its Cargo/rustc version, host triple
   and glibc version; for `run` the client checks that a binary built there
   can run locally (see [Compatibility](#compatibility)).
3. The agent takes an exclusive lock on the remote workspace; other builds of
   the same workspace wait ("waiting for remote workspace lock").
4. Incremental sync: the client sends a listing (paths, sizes, mtimes,
   modes, symlinks); the agent asks only for changed files and deletes files
   that disappeared locally.
5. The agent runs `cargo fetch` (with the credential broker open, see
   [Credentials](#credentials)), then `cargo run` / `cargo check`, and
   streams the output back.
6. For `run`, the agent records which executable Cargo would start (via a
   runner hook, so Cargo's own target selection, `default-run`, `--bin`,
   `--example` all apply). The client downloads it (skipped when the cached
   copy has the same BLAKE3 hash) and runs it locally from your current
   directory with your environment plus Cargo's `CARGO_*` run variables
   (paths mapped to the local workspace).

## Requirements

- **Local:** Cargo and `cargo-live`. No `ssh`, no `rsync`.
- **Remote:** Docker (or any Linux host with Cargo/rustc) running
  `cargo-live-agent`, reachable on one TCP port (default 2222).
- For `run`, the build host must produce executables your machine can run:
  same target triple and, for `*-gnu`, a glibc that is not newer than the
  local one. The provided image uses Debian bookworm (glibc 2.36) for this
  reason.

## Agent

### Install

From this repository:

```sh
cargo install --locked --path crates/cargo-live-agent
```

(`cargo install --locked cargo-live-agent` from crates.io will work once the
crates are published; they are not yet.)

### Docker

The [`Dockerfile`](Dockerfile) builds the agent in the official Rust image
(`rust:1.99.0-bookworm`, override with `--build-arg RUST_IMAGE=...`) and runs
it in the same image, because builds need Cargo and rustc:

```sh
docker build -t cargo-live-agent .                    # from this source tree
docker build -t cargo-live-agent \
  --build-arg SOURCE=crates-io [--build-arg VERSION=0.1.0] .   # from crates.io
```

The image runs `cargo-live-agent serve` as the non-root user `cargo-live`
(uid/gid 10001, change with `--build-arg UID=... --build-arg GID=...`),
exposes port 2222 and declares `VOLUME /data`. The directories of the
image's rustup and Cargo homes (`/usr/local/rustup`, `/usr/local/cargo`) are
writable by that user, so a project's `rust-toolchain.toml` can install
toolchains, components and targets, and Cargo can fill its registry cache.
rustup self-update is disabled.

```sh
docker volume create cargo-live-data
docker run -d --name cargo-live-agent --init --restart unless-stopped \
  -p 2222:2222 \
  -v cargo-live-data:/data \
  -v cargo-live-registry:/usr/local/cargo/registry \
  -v cargo-live-git:/usr/local/cargo/git \
  cargo-live-agent
docker logs cargo-live-agent                     # shows the host key fingerprint
docker exec cargo-live-agent cargo-live-agent token create --name alice
```

Notes:

- Use `--init` (`init: true` in Compose): the agent would otherwise be PID 1
  and neither reap orphaned build processes nor stop promptly on
  `docker stop`.
- Prefer named volumes. Docker seeds an empty named volume with the image's
  directory, including its ownership; a bind mount must be writable by uid
  10001.
- The registry/git volumes are optional caches. A volume on
  `/usr/local/rustup` keeps toolchains installed for `rust-toolchain.toml`
  across container re-creation, but it then shadows the image's toolchain:
  after upgrading the image, remove that volume to get the new default.
- Flags after the image name are passed to `serve`, e.g.
  `docker run ... cargo-live-agent --max-concurrent-builds 4`; or use
  `-e CARGO_LIVE_AGENT_...` variables or `/data/agent.toml`.

[`compose.yaml`](compose.yaml) is the same setup for Docker Compose:

```sh
docker compose up -d --build
docker compose exec agent cargo-live-agent token create --name alice
docker compose exec agent cargo-live-agent fingerprint
```

### Configuration

Every option is resolved as flag > environment variable > config file >
default:

| flag | environment | config key | default |
| --- | --- | --- | --- |
| `--config PATH` | `CARGO_LIVE_AGENT_CONFIG` | – | `<data_dir>/agent.toml` if it exists |
| `--data-dir DIR` | `CARGO_LIVE_AGENT_DATA_DIR` | `data_dir` | `/data` |
| `--host-key PATH` | `CARGO_LIVE_AGENT_HOST_KEY` | `host_key` | `<data_dir>/host_key` |
| `--tokens-file PATH` | `CARGO_LIVE_AGENT_TOKENS_FILE` | `tokens_file` | `<data_dir>/tokens.toml` |
| `--listen ADDR` | `CARGO_LIVE_AGENT_LISTEN` | `listen` | `0.0.0.0:2222` |
| `--max-concurrent-builds N` | `CARGO_LIVE_AGENT_MAX_CONCURRENT_BUILDS` | `max_concurrent_builds` | `2` |
| `--max-connections N` | `CARGO_LIVE_AGENT_MAX_CONNECTIONS` | `max_connections` | `64` |
| `--lock-timeout SECS` | `CARGO_LIVE_AGENT_LOCK_TIMEOUT` | `lock_timeout` | `600` |
| `--cargo PATH` | `CARGO_LIVE_AGENT_CARGO` | `cargo` | `cargo` from `PATH` |

- The first four apply to every subcommand (`serve`, `token`,
  `fingerprint`); the rest only to `serve`.
- An explicit `--config` file must exist; the default one is optional.
  Unknown keys are errors. Relative paths in the file are relative to the
  file (a bare `cargo` name is looked up in `PATH`).
- `max_concurrent_builds` limits running Cargo processes; further builds wait
  ("waiting for a free build slot"). `max_connections` limits open
  connections, authenticated or not; further connections are closed
  immediately and logged. `lock_timeout` is how long a build waits for a busy
  workspace before failing.

`agent.toml` also holds credential providers (`[[credentials]]`) and
per-token policies (`[tokens.<name>]`), see [Credentials](#credentials).

Example `/data/agent.toml`:

```toml
listen = "0.0.0.0:2222"
max_concurrent_builds = 4
max_connections = 32
lock_timeout = 300
```

### Tokens and host key

Create one token per user or machine. It is printed **once**; the agent
stores only its SHA-256 hash. Names may contain letters, digits, `-`, `_`
and `.` (up to 64, not starting with `.` or `-`) and also name the token's
workspace directory.

```sh
cargo-live-agent token create --name alice     # prints clt_...
cargo-live-agent token list                    # names and creation times
cargo-live-agent token revoke --name alice
```

Tokens can be created and revoked while the server runs; each login attempt
re-reads the tokens file. Revoking does not end connections that are already
authenticated.

The Ed25519 host key is generated on first start (or on first
`fingerprint`). Give its fingerprint to clients to pin:

```sh
cargo-live-agent serve            # logs "host key fingerprint: SHA256:..."
cargo-live-agent fingerprint      # prints it (generates the key if missing)
```

### Data layout

```
<data_dir>/host_key                   Ed25519 host key (0600)
<data_dir>/tokens.toml                token names and hashes (0600)
<data_dir>/audit.log                  credential decisions, JSON lines (0600)
<data_dir>/workspaces/<token>/<workspace-id>/
    source/   mirror of the local workspace, managed by the agent
    target/   Cargo target directory, kept for incremental builds
    index, lock, tmp/, runner.json
```

`<workspace-id>` is the SHA-256 of the local workspace path. Keep
`<data_dir>` on a persistent volume. To reclaim space, delete a token's or a
workspace's directory while no build of it is running.

## Client

### Install

```sh
cargo install --locked --path crates/cargo-live
```

### Configure a workspace

Add `.cargo/live.toml` at the **Cargo workspace root**:

```toml
[remote]
url = "build-host:2222"            # host or host:port; port defaults to 2222
host_key = "SHA256:..."            # optional pin (recommended)

# Optional exclusions. Do not put secrets in synced files.
[sync]
exclude = ["/.env", "/node_modules"]
```

Exclude patterns: a leading `/` anchors to the workspace root, otherwise the
pattern matches at any depth; a trailing `/` matches directories only; `*` and
`?` do not cross `/`, `**` does. `/.git`, `/target` and the local Cargo
target directory are never synced. Hidden files are synced; sockets and other
special files are skipped.

If the workspace has no `Cargo.lock`, the one Cargo generates on the agent is
kept between builds. A local `Cargo.lock` always replaces the agent's copy,
and deleting it locally deletes it on the agent too.

### Tokens

Store a token (read from stdin, not echoed on a terminal). `login` connects,
verifies the host key and the token, then saves it:

```sh
cargo live login build-host:2222
cargo live logout build-host:2222
```

Tokens are looked up in the `CARGO_LIVE_TOKEN` environment variable, then in
`$XDG_CONFIG_HOME/cargo-live/credentials.toml` (default
`~/.config/cargo-live/credentials.toml`, mode 0600), keyed by `host:port`.
Never put tokens in the repository.

### Build

```sh
cargo live run -- --program-argument
cargo live run --release --bin server
cargo live check --workspace --all-targets
```

Cargo options are forwarded to the remote Cargo. The program runs locally
from your current directory; its exit code is cargo-live's exit code.
Downloaded executables are cached in `$XDG_CACHE_HOME/cargo-live` (default
`~/.cache/cargo-live`).

### Transparent `cargo run` (shim)

To opt in, put a symlink named `cargo` to `cargo-live` in a directory
**before** the real Cargo in `PATH`:

```sh
mkdir -p ~/.local/share/cargo-live/shim
ln -s "$(command -v cargo-live)" ~/.local/share/cargo-live/shim/cargo
export PATH="$HOME/.local/share/cargo-live/shim:$PATH"
```

In a workspace with `.cargo/live.toml`, `cargo run` and `cargo r` are then
built remotely, including after Cargo's global options such as `+toolchain`,
`-q`, `--locked`, `-C DIR` or `--config` (a `+toolchain` is forwarded to the
remote Cargo). Every other command, and `run` outside configured workspaces,
goes to the real Cargo. The shim finds the next `cargo` in `PATH`; set
`CARGO_LIVE_REAL_CARGO` to the absolute path of the real Cargo if needed.
Already running editors may need a restart to see the new `PATH`.

### VS Code and rust-analyzer

To move **check-on-save** to the build host, add this to the workspace's
`.vscode/settings.json`:

```json
{
  "rust-analyzer.check.overrideCommand": [
    "cargo", "live", "check",
    "--workspace", "--all-targets", "--message-format=json"
  ]
}
```

`cargo-live` forwards Cargo's JSON on stdout and remaps remote source paths
(including package ids) to the local workspace. If rust-analyzer cancels a
check, the client disconnects and the agent stops the remote build and
releases the workspace lock. Rust-analyzer's build-script and proc-macro
preparation is **not** redirected and still runs locally.

## Credentials

Builds on the agent often need credentials: private git dependencies
(GitHub, GitLab, self-hosted), private Cargo registries, Docker registries.
cargo-live brokers them per job. Secrets are never baked into the image,
never written to disk on the agent, and never put into the environment of
build processes.

### Model

There are two sources, which you can mix per scope:

- **`agent`**: providers configured on the agent (shared/org credentials,
  short-lived tokens such as GitHub App installation tokens). Their root
  secrets come from mounted files or environment variables (Docker/Kubernetes
  secrets) or from external commands.
- **`client`**: forwarded on demand from your machine over the existing SSH
  connection (like ssh-agent forwarding, but for tokens), resolved with your
  local tools (`git credential fill`, Cargo's credentials, Docker credential
  helpers). Your machine only hands out what its `[forward]` allowlist
  permits.

A **scope** is what a credential is for: `git` (host + repository path, e.g.
`github.com` + `acme/foo`, `.git` stripped), `cargo` (registry name and/or
index URL) or `docker` (registry host).

**Resolution**, for each request the agent receives:

1. The best matching client rule: rules from your user config first, then
   project hints; within each, the most specific match (more fields, then
   more literal characters) wins; ties go to the first. Without a rule the
   sources are `["agent", "client"]`, where `client` only applies if the
   scope is in your `[forward]`.
2. The current phase must be in the rule's `phases` (default `["fetch"]`).
3. Sources are tried in order. `agent` is the first agent provider whose
   `match` fits, whose `allow_tokens` includes your token and whose `phases`
   allow the phase. `client` is skipped if your token has
   `allow_client = false` or the scope is not in `[forward]`; otherwise your
   machine is asked, and it checks `[forward]` again itself.
4. The first success wins; failures fall through to the next source.
   Successes are cached in memory for the rest of the connection (until
   shortly before they expire); nothing is cached across connections or
   tokens, and failures are never cached.

**Phase gating.** Every build runs in two steps:

1. `cargo fetch` (with your `+toolchain`, `--locked`, `--frozen`,
   `--offline`, `--config` and `-Z` options) with the credential broker
   open. No third-party code runs in this step.
2. `cargo run` / `cargo check`, which runs build scripts and proc macros
   (third-party code), with the broker **closed**, except for scopes whose
   effective `phases` include `build`.

So dependencies' build scripts never see your credentials unless you opt a
scope in, for example a `build.rs` that pulls from a private Docker
registry. A failing fetch fails the build ("`cargo fetch` failed ... the
build was not started"). Output of both steps is streamed as usual.

How it works on the agent: for each step that may receive credentials the
agent creates a Unix socket `<workspace>/tmp/cred-<id>.sock` (mode 0600)
and a random nonce, passed to Cargo as `CARGO_LIVE_BROKER` and
`CARGO_LIVE_BROKER_NONCE`. Helper modes of the agent binary connect to it:

- **git**: Cargo gets `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_n`/`GIT_CONFIG_VALUE_n`
  entries (appended after existing ones) that clear inherited credential
  helpers, set `credential.helper = !<agent> __cred git` and
  `credential.useHttpPath = true`, and rewrite `git@<host>:` and
  `ssh://git@<host>/` to `https://<host>/` for github.com and every literal
  host your rules, `[forward]` and the agent's providers mention, so SSH
  dependency URLs need no SSH keys. `CARGO_NET_GIT_FETCH_WITH_CLI=true` and
  `GIT_TERMINAL_PROMPT=0` are set.
- **Cargo registries**: the agent is registered as a credential provider
  (`--config credential-alias.cargo-live=[...]` and
  `registry.global-credential-providers=["cargo-live"]`) and answers `get`
  requests with `cache = "expires"` when the expiry is known, otherwise
  `"never"`; `login`/`logout` are refused.
- **Docker registries**: `DOCKER_CONFIG` points at a per-step
  `config.json` with `{"credsStore": "cargo-live"}`, and a per-step `bin`
  directory first in `PATH` contains `docker-credential-cargo-live`, a
  symlink to the agent, which acts as a Docker credential helper (`get`;
  `store`/`erase`/`list` do nothing). Giving builds access to a Docker
  daemon is out of scope, and dangerous: the Docker socket is root on the
  host.

The socket and the per-step directory are removed when the step ends. A
helper whose request fails gets a generic error; the reasons go to the
agent log, the audit log and your terminal.

**Registry definitions.** `[registries]`, `[source]` and
`registry.default` from your Cargo home config (`$CARGO_HOME/config.toml`
or `config`, including files it `include`s, and `.cargo/config.toml` files
in directories above the workspace) are not synced, because only the
workspace is. The client sends them (never tokens or credential providers)
and the agent passes them to remote Cargo as `--config` entries. Entries
that the workspace's own `.cargo/config.toml` defines are left to it, and
local sources (`directory`, `local-registry`) are not sent.

### Client configuration

`$XDG_CONFIG_HOME/cargo-live/config.toml` (default
`~/.config/cargo-live/config.toml`; never put it in the repository):

```toml
[forward]                         # allowlist: what this machine may hand out
git = ["github.com/alfatm/*", "gitlab.acme.dev/*"]   # host/path globs; "host" alone = whole host
cargo = ["acme"]                  # registry names or index URLs
docker = []                       # registry hosts
# interactive = false             # let git credential helpers prompt on a terminal

[[forward.command]]               # optional custom resolver for matching scopes
match = { kind = "git", host = "gitlab.acme.dev" }
command = ["glab", "auth", "token"]   # no shell; stdout = secret, or JSON {secret, username?, expires_at?}
# timeout = 60

[[credentials]]
match = { kind = "git", host = "github.com", path = "acme/*" }
sources = ["agent"]
[[credentials]]
match = { kind = "git", host = "github.com", path = "alfatm/*" }
sources = ["client"]
[[credentials]]
match = { kind = "cargo", registry = "acme" }
sources = ["agent", "client"]
phases = ["fetch"]                # optional, default ["fetch"]; add "build" to opt in
```

`match` takes `kind` plus `host` and `path` (git), `registry` and `index`
(cargo) or `host` (docker); values are globs where `*` matches anything
(including `/`). A `[[forward.command]]` gets the request as JSON on stdin
(`{"kind": "git", "protocol": ..., "host": ..., "path": ...}`, or
`registry`/`index` for cargo, `host` for docker); `expires_at` is Unix
seconds or RFC 3339.

Without a matching `[[forward.command]]` your machine resolves forwarded
requests with:

- git: `git credential fill` with protocol, host and path
  (`GIT_TERMINAL_PROMPT=0` unless `interactive = true`); username, password
  and `password_expiry_utc` are used. Whether helpers see the path depends
  on your `credential.useHttpPath`.
- cargo: `CARGO_REGISTRIES_<NAME>_TOKEN`, then `$CARGO_HOME/credentials.toml`
  (`[registries.<name>] token`), then the registry's credential providers
  from your Cargo config (`registries.<name>.credential-provider` or
  `registry.global-credential-providers`, aliases resolved), run with the
  credential provider protocol. `cargo:token-from-stdout` is supported; other
  built-in `cargo:` providers (`libsecret`, `macos-keychain`, `wincred`) are
  not; use `[[forward.command]]` for those.
- docker: `credHelpers[host]`, then `auths[host].auth`, then `credsStore`
  from `~/.docker/config.json` (or `$DOCKER_CONFIG`), via
  `docker-credential-<helper> get`.

**Project hints.** `.cargo/live.toml` may contain `[[credentials]]` with
`match` and `sources` only. They rank below your user rules and can never
extend `[forward]` or set `phases`:

```toml
[[credentials]]
match = { kind = "git", host = "gitlab.acme.dev" }
sources = ["client"]
```

Each credential served prints one line, and a failure prints the chain
tried:

```
cargo-live: credential for git github.com/acme/foo from agent (acme-github) (fetch phase)
cargo-live: no credential for git github.com/acme/bar: agent → not allowed for token "alice" (acme-github); client → not in [forward]
```

### Agent providers

Providers are `[[credentials]]` tables in `agent.toml`. Every provider has
`name` (used in logs and `creds explain`), `match`, `provider`,
`allow_tokens` (required; token-name globs, `["*"]` for all) and optional
`phases` (a cap on top of the client's rules). Root secrets are references,
`{ file = "..." }` or `{ env = "NAME" }`; inline secret values are rejected.
Relative paths are relative to the config file. The configuration is read at
startup. Environment variables named by `env` providers and `{ env = ... }`
references are removed from Cargo's environment.

**GitHub App** (short-lived git tokens for GitHub and GitHub Enterprise
Server). The agent signs an RS256 JWT with the App's private key, finds the
installation with `GET /repos/{owner}/{repo}/installation` unless
`installation_id` is set, and mints a token with
`POST /app/installations/{id}/access_tokens` for that one repository and the
given `permissions`. The username is `x-access-token`; the expiry comes from
the response.

```toml
[[credentials]]
name = "acme-github"
match = { kind = "git", host = "github.com", path = "acme/*" }
provider = "github-app"
app_id = 123456
private_key = { file = "/run/secrets/gh-app.pem" }   # PKCS#1 or PKCS#8 PEM
# installation_id = 789                # optional; otherwise looked up per repository
# api_url = "https://ghe.acme.dev/api/v3"   # GitHub Enterprise Server
permissions = { contents = "read" }
allow_tokens = ["*"]
```

**GitLab.** Either forward from your machine (OAuth through `glab` or Git
Credential Manager) with `[forward]` and, for example,
`[[forward.command]]` running `glab auth token`; or put a deploy token on
the agent with a `file` provider:

```toml
[[credentials]]
name = "gitlab-deploy"
match = { kind = "git", host = "gitlab.acme.dev" }
provider = "file"
path = "/run/secrets/gitlab-deploy-token"
username = "deploy-bot"
allow_tokens = ["ci", "alice"]
```

**Vault, cloud secret managers, anything else**: `exec` runs a command
(no shell, killed after `timeout` seconds, default 30) with the request as
JSON on stdin (`kind`, the scope fields, `token_name`, `phase`) and expects
`{"secret": ..., "username": ..., "expires_at": ...}` on stdout (`username`
and `expires_at` optional). Its stderr goes to the agent log.

```toml
[[credentials]]
name = "acme-registry"
match = { kind = "cargo", registry = "acme" }
provider = "exec"
command = ["/usr/local/bin/registry-token"]
allow_tokens = ["*"]

[[credentials]]
name = "ghcr"
match = { kind = "docker", host = "ghcr.io" }
provider = "env"
var = "GHCR_TOKEN"
username = "ci-bot"
allow_tokens = ["*"]
phases = ["build"]           # only useful with a client rule that opts ghcr.io into build
```

**Per-token policy.** `allow_client = false` makes the agent never ask the
client for builds of that token (e.g. CI tokens, whose "client" is not a
developer machine):

```toml
[tokens.ci]
allow_client = false
```

### Audit log

Every credential decision is appended as a JSON line to
`<data_dir>/audit.log` (mode 0600) and logged as one line on the agent's
stderr: `ts`, `token`, `workspace`, `kind`, `scope`, `phase`, `source`
(`agent:<name>` or `client`; `none` when denied), `outcome` (`served`,
`cached` or `denied`), `expires_at`, and `chain` (the reasons) for denials.
Secrets never appear in it.

### `cargo live creds explain`

A dry run of the resolution, from the workspace: nothing is minted and no
resolver runs.

```sh
cargo live creds explain git https://github.com/acme/foo.git   # or host/path, git@host:path
cargo live creds explain cargo acme                            # registry name or index URL
cargo live creds explain docker ghcr.io
```

```
credentials for git github.com/acme/foo (agent build-host:2222)
  rule                user rule #1 (match kind=git host=github.com path=acme/*): sources = ["agent"], phases = ["fetch"]
  fetch phase: agent  [allowed] would use provider "acme-github" (github-app)
  build phase         [not allowed] phase build is not in phases
  this machine        not in [forward]: this machine refuses to forward it
```

The rule line says where the rule came from (`user`, `project` or
`default`).

### Limits of the model

- Builds run as the agent's OS user. Root secrets mounted into the agent
  (files, the agent's own environment) are readable by build scripts of any
  token. Phase gating protects what the broker hands out, not what the
  agent can read; prefer short-lived, narrowly scoped credentials
  (GitHub App tokens limited to one repository and `contents: read`) and
  run one agent per trust domain.
- Cargo's git and registry caches (`$CARGO_HOME/git`, `/registry`) are
  shared by all tokens of an agent: once one token fetched a private
  dependency, other tokens can build it from the cache without credentials.

## Security model

- **Transport:** SSH, implemented by russh on both ends with its default
  algorithm set (no SHA-1 MACs, no CBC ciphers). Between `cargo-live` and the
  agent this negotiates ML-KEM-768 + X25519 hybrid key exchange
  (`mlkem768x25519-sha256`) and ChaCha20-Poly1305. The host key is Ed25519;
  the client accepts no other host key type.
- **Server authentication** happens in the handshake, before the token is
  sent: against `remote.host_key` if pinned, otherwise trust-on-first-use in
  `$XDG_CONFIG_HOME/cargo-live/known_hosts` (default
  `~/.config/cargo-live/known_hosts`, keyed by `host:port`). A changed key is
  refused with the expected and actual fingerprints. Pin the key to avoid
  trusting the first connection blindly.
- **Client authentication:** SSH `password` method, user `cargo-live`,
  password = token (`clt_` + 32 random bytes, base64url). The agent stores
  only SHA-256 hashes (tokens file mode 0600) and compares them in constant
  time; the client stores tokens in a 0600 credentials file. All other
  methods are refused.
- **Rate limiting:** every failed attempt takes at least 1 s; after 3
  failures from an IP, each further attempt is delayed 1 s, 2 s, 4 s, ... up
  to 60 s (reset after 15 minutes without failures); at most 3 attempts per
  connection. Connections that are not authenticated within 30 s are
  dropped.
- **Connection cap:** at most `max_connections` (default 64) connections,
  authenticated or not, are open at once; further connections are closed
  right after `accept`. Authenticated connections also count, so a flood of
  unauthenticated connections can delay legitimate users for up to 30 s per
  slot, but cannot exhaust the agent.
- **Channel policy:** one `session` channel per connection, accepting only
  the `cargo-live` exec/subsystem request. Shells, PTYs, env, X11, signals,
  agent forwarding, TCP/IP and Unix-socket forwarding and other channel types
  are refused.
- **Paths:** the agent validates every path from the client (no absolute
  paths, `..`, empty or NUL components), never follows symlinks while
  writing or deleting the mirror (symlinks are replicated as symlinks),
  refuses symlinked workspace directories, and only serves executables
  inside the workspace's target directory. Cargo arguments that would move
  the build elsewhere (`--target-dir`, `--manifest-path`) are refused.
- **Builds run arbitrary code** (build scripts, proc macros, and Cargo
  itself) as the agent's OS user, with access to the whole data directory.
  Token namespaces keep workspaces apart for convenience but are **not** a
  security boundary: anyone with a token can read and modify other tokens'
  workspaces, the tokens file and the host key. Give tokens only to people
  who trust each other, and run one agent (container, with its own volume)
  per user or trust domain.
- Do not sync secrets: everything in the workspace except excluded paths is
  copied to the build host. For credentials builds need, see
  [Credentials](#credentials).

## Compatibility

For `cargo live run`, the client compares the agent's host triple (from
`rustc -vV` on the agent) with its own target triple, and, for `*-gnu`
triples, the agent's glibc version with the local one. A different triple or
a newer remote glibc is an error, because the executable would not start
locally. Set `CARGO_LIVE_SKIP_COMPAT_CHECK=1` to try anyway (for example for
statically linked programs). `cargo live check` does not run anything locally
and skips the check.

The client and agent must speak the same protocol version; install matching
versions of both.

## Limitations

This is an early prototype, not a complete replacement for Cargo:

- Supported commands: `run` and `check` (plus `login`/`logout` and
  `creds explain`). `build`,
  `test`, `bench` and others are not forwarded.
- `--target-dir` and `--manifest-path` are refused. For `run`,
  `--message-format` is refused, and cross-compilation (`--target`,
  `build.target`) and custom runners are not supported: the agent only
  records executables built for its own host.
- Programs run locally get Cargo's `CARGO_*` run variables, but their
  executable lives in cargo-live's cache, not in `target/`. Dynamic libraries
  or other build outputs they need must be provided locally.
- In `check` JSON, artifact `filenames` still point into the agent's target
  directory (source paths and package ids are remapped).
- Rust-analyzer's build scripts and proc macros still run locally.
- No per-token disk quotas: source mirrors and target directories grow
  without limit until deleted (see [Data layout](#data-layout)). Size the
  volume accordingly or clean up periodically.
- Workspaces are identified by token and local path: two machines using the
  same token and the same workspace path share one remote workspace (and its
  lock).
- Path dependencies outside the workspace are not synced. Interactive builds
  are not supported (Cargo's stdin is closed). Credentials for private
  dependencies are brokered per job, see [Credentials](#credentials).
