#!/usr/bin/env bash
set -euo pipefail

fixture_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "${fixture_root}/../../.." && pwd -P)"
target_root="${fixture_root}/target"
core_wasm="${target_root}/wasm32-unknown-unknown/release/bloom_triad_authority_petal_fixture.wasm"
component="${fixture_root}/petal/triad-authority-fixture/wallets/[wallet]/[index]/session.json.wasm"
bloom_builder="${BLOOM_FIXTURE_BUILDER:-${repo_root}/target/debug/bloom}"

cargo build \
  --manifest-path "${fixture_root}/Cargo.toml" \
  --target wasm32-unknown-unknown \
  --release
mkdir -p "$(dirname "$component")"
wasm-tools component new "$core_wasm" -o "$component"
wasm-tools validate "$component"

if [[ ! -x "$bloom_builder" ]]; then
  cargo build --manifest-path "${repo_root}/Cargo.toml" --package bloom --bin bloom
fi
"$bloom_builder" petals build "$fixture_root"
