# cargo-live-agent container image.
#
#   docker build -t cargo-live-agent .                          # from this source tree
#   docker build -t cargo-live-agent --build-arg SOURCE=crates-io \
#       [--build-arg VERSION=0.1.0] .                           # from crates.io
#
# The runtime image is the full official Rust image, because the agent runs
# Cargo and rustc for the projects it builds. Debian bookworm (glibc 2.36) is
# used on purpose: binaries built here must run on the client machines, and
# an older glibc runs on more of them. Pin RUST_IMAGE to an exact tag.

ARG RUST_IMAGE=rust:1.99.0-bookworm

FROM ${RUST_IMAGE} AS build
# local: build crates/cargo-live-agent from the build context.
# crates-io: `cargo install cargo-live-agent` from crates.io (VERSION optional).
ARG SOURCE=local
ARG VERSION=
WORKDIR /src
COPY . .
RUN set -eu; \
    case "$SOURCE" in \
      local) cargo install --locked --root /out --path crates/cargo-live-agent ;; \
      crates-io) cargo install --locked --root /out cargo-live-agent ${VERSION:+--version "$VERSION"} ;; \
      *) echo "SOURCE must be 'local' or 'crates-io', not '$SOURCE'" >&2; exit 1 ;; \
    esac

FROM ${RUST_IMAGE}
ARG UID=10001
ARG GID=10001
# The directories of the image's rustup and Cargo homes (/usr/local/rustup,
# /usr/local/cargo) are made writable by the agent user, so a project's
# rust-toolchain.toml can install toolchains, components and targets, and
# Cargo can fill its registry cache. Only directories are re-owned: files are
# replaced by rename, and a recursive chown would copy the ~600 MB toolchain
# into another layer. Mount named volumes on /usr/local/cargo/registry,
# /usr/local/cargo/git and (optionally) /usr/local/rustup to keep them across
# container re-creation.
RUN set -eu; \
    rustup set auto-self-update disable; \
    groupadd --gid "$GID" cargo-live; \
    useradd --uid "$UID" --gid "$GID" --create-home --shell /usr/sbin/nologin cargo-live; \
    mkdir -p /data "$CARGO_HOME/registry" "$CARGO_HOME/git"; \
    chown cargo-live:cargo-live /data "$RUSTUP_HOME/settings.toml"; \
    find "$CARGO_HOME" "$RUSTUP_HOME" -type d -exec chown cargo-live:cargo-live {} +
COPY --from=build /out/bin/cargo-live-agent /usr/local/bin/cargo-live-agent
USER cargo-live
WORKDIR /data
ENV CARGO_LIVE_AGENT_DATA_DIR=/data
VOLUME /data
EXPOSE 2222
ENTRYPOINT ["cargo-live-agent", "serve"]
