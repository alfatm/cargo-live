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
5. The agent runs `cargo run` / `cargo check` and streams the output back.
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
  copied to the build host.

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

- Supported commands: `run` and `check` (plus `login`/`logout`). `build`,
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
- Private registries and git dependencies need credentials on the agent;
  path dependencies outside the workspace are not synced. Interactive builds
  are not supported (Cargo's stdin is closed).
