# syntax=docker/dockerfile:1.7
#
# Bloom multi-stage build.
#
# Why cargo-chef: the workspace has 33 member crates with rich internal
# path-dependencies. Maintaining a hand-written "copy every Cargo.toml +
# dummy lib.rs" cache layer would be brittle (one new member silently
# busts the cache or breaks the build). cargo-chef does the recipe
# generation automatically and keeps the dep-build layer reusable across
# both the host-target binary (bloom) and the wasm petals.
#
# Stages:
#   chef          — installs cargo-chef and the wasm target on rust:1-bookworm
#   planner       — generates recipe.json from the full source tree
#   builder-deps  — cooks deps for host target AND wasm32 target
#   builder       — copies real sources and builds the binary + wasm
#   runtime       — debian:bookworm-slim with the produced artefacts

# ----------------------------------------------------------------------------
# Use `rust:1-bookworm` (latest stable in the 1.x series) rather than pinning
# to 1.85 — the workspace MSRV is 1.85 (lower bound) and several build-time
# tools (cargo-chef and its deps) now require >=1.86.
ARG RUST_VERSION=1
ARG DEBIAN_RELEASE=bookworm

FROM rust:${RUST_VERSION}-${DEBIAN_RELEASE} AS chef
WORKDIR /build
ENV CARGO_TERM_COLOR=always \
    CARGO_NET_RETRY=10 \
    RUST_BACKTRACE=1
# Pre-install all components that the workspace's rust-toolchain.toml lists
# (channel = "stable", components = ["rustfmt", "clippy"]). Without this,
# the first cargo invocation in the planner stage triggers a rustup channel
# sync to install the missing components — which fails inside BuildKit when
# its DNS path is flaky, killing the build before cargo even starts.
RUN rustup target add wasm32-unknown-unknown \
 && rustup component add rustfmt clippy \
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
RUN cargo chef cook --release --recipe-path /recipe.json
# We deliberately skip a wasm32 `cargo chef cook` step: most workspace deps
# (tokio, rocksdb, alloy providers, …) don't compile for wasm32 and would
# fail. The DEX petals have a small, self-contained dep tree that builds
# fresh in the next stage in seconds.

# ----------------------------------------------------------------------------
FROM builder-deps AS builder
COPY . .

# The workspace ships a `rust-toolchain.toml` that pins `channel = "stable"`.
# Once the source tree lands in /build, rustup will auto-install whichever
# toolchain that resolves to — potentially different from the one used in the
# `chef` stage where we ran `rustup target add wasm32-unknown-unknown`.
# Re-add the wasm target here so it's guaranteed to be present for the
# resolved toolchain. (Idempotent and fast when already installed.)
RUN rustup target add wasm32-unknown-unknown

# Host binary.
RUN cargo build --release -p bloom

# DEX petal wasm artefacts. Build each petal in its own `cargo build`
# invocation because sibling petals use `features = ["no-entrypoint"]` when
# imported as rlib dependencies; a single multi-package build would unify those
# features and can suppress a root petal's exported entrypoints.
RUN cargo build --release --target wasm32-unknown-unknown -p bloom-petal-dex-pool
RUN cargo build --release --target wasm32-unknown-unknown -p bloom-petal-dex-wallet
RUN cargo build --release --target wasm32-unknown-unknown -p bloom-petal-dex-faucet
RUN cargo build --release --target wasm32-unknown-unknown -p bloom-petal-dex-cpmm
RUN cargo build --release --target wasm32-unknown-unknown -p bloom-petal-dex-router

# Stage outputs into /out so the runtime COPY is dead-simple.
RUN set -eux; \
    mkdir -p /out/bin /out/wasm; \
    cp target/release/bloom        /out/bin/bloom; \
    for w in bloom_petal_dex_pool bloom_petal_dex_wallet bloom_petal_dex_faucet \
             bloom_petal_dex_cpmm bloom_petal_dex_router; do \
        cp "target/wasm32-unknown-unknown/release/${w}.wasm" "/out/wasm/${w}.wasm"; \
    done; \
    ls -la /out/bin /out/wasm

# ----------------------------------------------------------------------------
FROM debian:${DEBIAN_RELEASE}-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        netcat-openbsd \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/bin/bloom      /usr/local/bin/bloom
COPY --from=builder /out/wasm/          /wasm/

ENTRYPOINT ["/usr/local/bin/bloom"]
