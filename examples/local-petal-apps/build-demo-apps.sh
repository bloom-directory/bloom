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

copy_polymarket_route() {
  local out="$1"
  local wasm="$2"
  local rel="$3"
  mkdir -p "$(dirname "$out/app/polymarket/$rel")"
  cp "$wasm" "$out/app/polymarket/$rel"
}

build_polymarket() {
  local src="$root/polymarket"
  local out="$build_root/polymarket"
  local wasm="$root/../../target/wasm32-wasip1/release/bloom_local_petal_polymarket.wasm"

  cargo build -p bloom-local-petal-polymarket --target wasm32-wasip1 --release

  rm -rf "$out"
  mkdir -p "$out"
  cp "$src/petal.toml" "$src/README.md" "$src/AGENTS.md" "$out/"

  copy_polymarket_route "$out" "$wasm" '$index.wasm'
  copy_polymarket_route "$out" "$wasm" 'markets/$list.wasm'
  copy_polymarket_route "$out" "$wasm" 'markets/[slug]/market.json.wasm'
  copy_polymarket_route "$out" "$wasm" 'markets/[slug]/book.json.wasm'
  copy_polymarket_route "$out" "$wasm" 'markets/[slug]/prices.json.wasm'
  copy_polymarket_route "$out" "$wasm" 'meta/parity.json.wasm'
  copy_polymarket_route "$out" "$wasm" 'search/[query].wasm'
  copy_polymarket_route "$out" "$wasm" 'positions/$list.wasm'
  copy_polymarket_route "$out" "$wasm" 'positions/[wallet]/positions.json.wasm'
  copy_polymarket_route "$out" "$wasm" 'positions/[wallet]/trades.json.wasm'
  copy_polymarket_route "$out" "$wasm" 'positions/[wallet]/activity.json.wasm'
  copy_polymarket_route "$out" "$wasm" 'onboard/$list.wasm'
  copy_polymarket_route "$out" "$wasm" 'onboard/[wallet]/begin.wasm'
  copy_polymarket_route "$out" "$wasm" 'onboard/[wallet]/status.json.wasm'
  copy_polymarket_route "$out" "$wasm" 'onboard/[wallet]/plan.md.wasm'
  copy_polymarket_route "$out" "$wasm" 'onboard/[wallet]/approvals.json.wasm'
  copy_polymarket_route "$out" "$wasm" 'account/$list.wasm'
  copy_polymarket_route "$out" "$wasm" 'account/[wallet]/portfolio.json.wasm'
  copy_polymarket_route "$out" "$wasm" 'account/[wallet]/orders.json.wasm'
  copy_polymarket_route "$out" "$wasm" 'fund/$list.wasm'
  copy_polymarket_route "$out" "$wasm" 'fund/[wallet]/new.wasm'
  copy_polymarket_route "$out" "$wasm" 'fund/[wallet]/[id]/plan.md.wasm'
  copy_polymarket_route "$out" "$wasm" 'fund/[wallet]/[id]/request.json.wasm'
  copy_polymarket_route "$out" "$wasm" 'fund/[wallet]/[id]/status.json.wasm'
  copy_polymarket_route "$out" "$wasm" 'trade/$list.wasm'
  copy_polymarket_route "$out" "$wasm" 'trade/[wallet]/new.wasm'
  copy_polymarket_route "$out" "$wasm" 'trade/[wallet]/drafts/$list.wasm'
  copy_polymarket_route "$out" "$wasm" 'trade/[wallet]/drafts/[id]/plan.md.wasm'
  copy_polymarket_route "$out" "$wasm" 'trade/[wallet]/drafts/[id]/order.json.wasm'
  copy_polymarket_route "$out" "$wasm" 'trade/[wallet]/drafts/[id]/policy_check.json.wasm'
  copy_polymarket_route "$out" "$wasm" 'trade/[wallet]/drafts/[id]/quote.json.wasm'
  copy_polymarket_route "$out" "$wasm" 'trade/[wallet]/drafts/[id]/review_intent.json.wasm'
  copy_polymarket_route "$out" "$wasm" 'trade/[wallet]/drafts/[id]/post_attempt.json.wasm'
  copy_polymarket_route "$out" "$wasm" 'trade/[wallet]/drafts/[id]/revalidate.wasm'
  copy_polymarket_route "$out" "$wasm" 'trade/[wallet]/drafts/[id]/post.wasm'
  copy_polymarket_route "$out" "$wasm" 'trade/[wallet]/receipts/$list.wasm'
  copy_polymarket_route "$out" "$wasm" 'trade/[wallet]/receipts/[id]/receipt.json.wasm'
  copy_polymarket_route "$out" "$wasm" 'trade/[wallet]/receipts/[id]/cancel.wasm'

  echo "built $out"
}

if [[ $# -eq 0 ]]; then
  build_one echo
  build_one hash
  build_one gas-now
else
  for name in "$@"; do
    if [[ "$name" == "polymarket" ]]; then
      build_polymarket
    else
      build_one "$name"
    fi
  done
fi
