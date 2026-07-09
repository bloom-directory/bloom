# syntax=docker/dockerfile:1.7
#
# Bloom multi-stage build.
#
# Why cargo-chef: the workspace has 33 member crates with rich internal
# path-dependencies. Maintaining a hand-written "copy every Cargo.toml +
# dummy lib.rs" cache layer would be brittle (one new member silently
# busts the cache or breaks the build). cargo-chef does the recipe
# generation automatically and keeps the dep-build layer reusable for the
# host-target binary (bloom).
#
# Stages:
#   chef          — installs cargo-chef on rust:1-bookworm
#   planner       — generates recipe.json from the full source tree
#   builder-deps  — cooks deps for the host target
#   builder       — copies real sources and builds the binary
#   runtime       — debian:bookworm-slim with the produced artefacts

# ----------------------------------------------------------------------------
# Use a concrete stable Rust image so rustup does not refresh the floating
# `stable` channel during every Docker build.
ARG RUST_VERSION=1.96.0
ARG DEBIAN_RELEASE=bookworm

FROM rust:${RUST_VERSION}-${DEBIAN_RELEASE} AS chef
WORKDIR /build
ENV CARGO_TERM_COLOR=always \
    CARGO_NET_RETRY=10 \
    RUST_BACKTRACE=1 \
    RUSTUP_TOOLCHAIN=${RUST_VERSION}
# Pre-install all components that the workspace's rust-toolchain.toml lists
# (channel = "stable", components = ["rustfmt", "clippy"]). Without this,
# the first cargo invocation in the planner stage triggers a rustup channel
# sync to install the missing components — which fails inside BuildKit when
# its DNS path is flaky, killing the build before cargo even starts.
RUN rustup component add rustfmt clippy \
 && cargo install cargo-chef --locked --version ^0.1

# ----------------------------------------------------------------------------
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path /recipe.json

# ----------------------------------------------------------------------------
FROM chef AS builder-deps
COPY --from=planner /recipe.json /recipe.json
# Cook all workspace dependencies for the host target. We don't scope to
# specific packages because `cargo chef cook -p <pkg>` doesn't always pick
# up workspace examples reliably; cooking the whole tree is more robust and
# the resulting layer is reused by every host-target build below.
RUN cargo chef cook --release --recipe-path /recipe.json \
    -p bloom --bin bloom --all-features


# ----------------------------------------------------------------------------
FROM builder-deps AS builder
COPY . .

RUN cargo build --release -p bloom --bin bloom --all-features

# Stage outputs into /out so the runtime COPY is dead-simple.
RUN set -eux; \
    mkdir -p /out/bin; \
    cp target/release/bloom        /out/bin/bloom; \
    ls -la /out/bin

# ----------------------------------------------------------------------------
FROM debian:${DEBIAN_RELEASE}-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        netcat-openbsd \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/bin/bloom      /usr/local/bin/bloom

ENTRYPOINT ["/usr/local/bin/bloom"]
