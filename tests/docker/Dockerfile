# Dockerfile for the bloom NFS mount integration test.
#
# Mirrors the bloom approach: rust:bookworm + nfs-common provides the
# mount.nfs4 binary so the in-process embednfs server can be attached
# inside the container. We use the bookworm tag to match the kernel
# headers shipped by Docker Desktop for Mac and most Linux hosts.
FROM rust:bookworm

# Toolchain extras the test harness leans on:
#   nfs-common      mount.nfs4 (the kernel's NFS client mounter)
#   ca-certificates HTTPS to public RPC providers, Enso, Etherscan
#   netbase         /etc/services so Rust net stacks resolve cleanly
#   procps          ps + kill -0 in cleanup loops
#   curl            anvil_setBalance JSON-RPC pokes from lib.sh
#   jq              receipt/gas/head sanity checks (cheaper than grep
#                   for nested-field assertions in future tests)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nfs-common \
        ca-certificates \
        netbase \
        procps \
        curl \
        jq \
    && rm -rf /var/lib/apt/lists/*

# rust-toolchain.toml at the repo root pins `stable` + rustfmt + clippy.
# Without these baked in, rustup tries to fetch them on every cargo
# invocation inside the container, and a transient DNS hiccup on the
# fastly endpoint kills the test before cargo even starts. Pin them
# here so the container is hermetic.
RUN rustup component add rustfmt clippy

WORKDIR /workspace

# Steer cargo to a container-local target dir. Without this, `cargo build`
# writes to /workspace/target which is the host bind mount — and a host
# (often macOS) toolchain can't share rmeta files with the in-container
# Linux toolchain (E0460 "possibly newer version of crate"). The host
# driver mounts a named docker volume here so deps stay warm across
# `--rm` runs.
ENV CARGO_TARGET_DIR=/tmp/cargo-target \
    RUST_LOG=info

# The host driver bind-mounts the repo at /workspace and runs
# `tests/docker/test.sh` inside. The container is otherwise stateless.
CMD ["bash", "tests/docker/test.sh"]
