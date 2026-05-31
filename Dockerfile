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
RUN cargo chef cook --release --recipe-path /recipe.json \
    -p bloom --bin bloom --all-features \
    -p bloom-petal-dex-it --tests
# We deliberately skip a wasm32 `cargo chef cook` step: most workspace deps
# (tokio, rocksdb, alloy providers, …) don't compile for wasm32 and would
# fail. The DEX petals have a small, self-contained dep tree that builds
# fresh in the next stage in seconds.

# ----------------------------------------------------------------------------
FROM builder-deps AS builder
COPY . .

# RUSTUP_TOOLCHAIN is set in the base stage so cargo uses the already-installed
# Docker toolchain instead of syncing the workspace `rust-toolchain.toml`
# override after every source COPY. Re-add the wasm target here so it is
# guaranteed to be present for the active toolchain.
RUN rustup target add wasm32-unknown-unknown

# Host/validator binary plus Docker acceptance driver. Build them in one Cargo
# invocation so the shared graph is planned and compiled once in this layer.
RUN rm -f target/release/deps/docker_petal_dex-* \
 && cargo build --release \
    -p bloom --bin bloom --all-features \
    -p bloom-petal-dex-it --test docker_petal_dex

# DEX petal wasm artefacts. Build each petal in its own `cargo build`
# invocation because sibling petals use `features = ["no-entrypoint"]` when
# imported as rlib dependencies; a single multi-package build would unify those
# features and can suppress a root petal's exported entrypoints.
RUN cargo build --release --target wasm32-unknown-unknown -p bloom-petal-dex-pool
RUN cargo build --release --target wasm32-unknown-unknown -p bloom-petal-dex-wallet
RUN BLOOM_DEX_FAUCET_ADMIN_HEX=6252e10b0fae9107bdf13f3dfe482e81099df4ef93e7373516f94b7fde3da72f \
    cargo build --release --target wasm32-unknown-unknown -p bloom-petal-dex-faucet
RUN cargo build --release --target wasm32-unknown-unknown -p bloom-petal-dex-cpmm
RUN cargo build --release --target wasm32-unknown-unknown -p bloom-petal-dex-router

# Stage outputs into /out so the runtime COPY is dead-simple.
RUN set -eux; \
    mkdir -p /out/bin /out/tests /out/wasm; \
    cp target/release/bloom        /out/bin/bloom; \
    test_bin="$(find target/release/deps -maxdepth 1 -type f -executable -name 'docker_petal_dex-*' | head -n1)"; \
    test -n "$test_bin"; \
    cp "$test_bin" /out/tests/docker_petal_dex; \
    for w in bloom_petal_dex_pool bloom_petal_dex_wallet bloom_petal_dex_faucet \
             bloom_petal_dex_cpmm bloom_petal_dex_router; do \
        cp "target/wasm32-unknown-unknown/release/${w}.wasm" "/out/wasm/${w}.wasm"; \
    done; \
    ls -la /out/bin /out/tests /out/wasm

# ----------------------------------------------------------------------------
FROM debian:${DEBIAN_RELEASE}-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        netcat-openbsd \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/bin/bloom      /usr/local/bin/bloom
COPY --from=builder /out/tests/         /tests/
COPY --from=builder /out/wasm/          /wasm/

ENTRYPOINT ["/usr/local/bin/bloom"]
