#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
build_root="$root/build"
mkdir -p "$build_root"

build_one() {
  local name="$1"
  local src="$root/$name"
  local out="$build_root/$name"
  rm -rf "$out"
  mkdir -p "$out"
  cp "$src/petal.toml" "$src/README.md" "$src/AGENTS.md" "$out/"
  while IFS= read -r -d '' wat; do
    local rel="${wat#$src/}"
    local wasm="$out/${rel%.wat}.wasm"
    mkdir -p "$(dirname "$wasm")"
    wat2wasm "$wat" -o "$wasm"
  done < <(find "$src/app" -name '*.wat' -print0 | sort -z)
  echo "built $out"
}

if [[ $# -eq 0 ]]; then
  build_one echo
  build_one hash
  build_one gas-now
else
  for name in "$@"; do
    build_one "$name"
  done
fi
