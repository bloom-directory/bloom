# syntax=docker/dockerfile:1.7
#
# Bloom multi-stage build.
#
# Why cargo-chef: the workspace has 33 member crates with rich internal
# path-dependencies. Maintaining a hand-written "copy every Cargo.toml +
# dummy lib.rs" cache layer would be brittle (one new member silently
# busts the cache or breaks the build). cargo-chef does the recipe
# generation automatically and keeps the dep-build layer reusable across
# both the host-target binaries (bloom, bloom-dex) and the wasm petals.
#
# Stages:
#   chef          — installs cargo-chef and the wasm target on rust:1-bookworm
#   planner       — generates recipe.json from the full source tree
#   builder-deps  — cooks deps for host target AND wasm32 target
#   builder       — copies real sources and builds the binaries + wasm
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
RUN rustup target add wasm32-unknown-unknown \
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

# Host binaries.
RUN cargo build --release -p bloom -p bloom-dex-cli

# DEX petal wasm artefacts.
RUN cargo build --release --target wasm32-unknown-unknown \
        -p bloom-dex-erc20 \
        -p bloom-dex-factory \
        -p bloom-dex-pair \
        -p bloom-dex-wloom \
        -p bloom-dex-router

# Stage outputs into /out so the runtime COPY is dead-simple.
RUN set -eux; \
    mkdir -p /out/bin /out/wasm; \
    cp target/release/bloom        /out/bin/bloom; \
    cp target/release/bloom-dex    /out/bin/bloom-dex; \
    for w in bloom_dex_erc20 bloom_dex_factory bloom_dex_pair \
             bloom_dex_wloom bloom_dex_router; do \
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
COPY --from=builder /out/bin/bloom-dex  /usr/local/bin/bloom-dex
COPY --from=builder /out/wasm/          /wasm/

ENTRYPOINT ["/usr/local/bin/bloom"]
