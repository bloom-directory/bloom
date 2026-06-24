#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
APP="$ROOT/examples/local-petal-apps/polymarket"
PROXY="$ROOT/examples/local-petal-apps/polymarket-route-proxy"
OUT="$APP/app/polymarket"
TMP="$ROOT/target/polymarket-v2"
CORE="$PROXY/target/wasm32-unknown-unknown/release/bloom_polymarket_v2_route_proxy.wasm"
COMPONENT="$TMP/polymarket-route-proxy.wasm"

routes=(
  '$index'
  '$list'
  'markets/$index'
  'markets/$list'
  'markets/[slug]/$index'
  'markets/[slug]/$list'
  'markets/[slug]/market.json'
  'markets/[slug]/book.json'
  'markets/[slug]/prices.json'
  'search/$index'
  'search/$list'
  'search/[query]'
  'positions/$index'
  'positions/$list'
  'positions/[wallet]/$index'
  'positions/[wallet]/$list'
  'positions/[wallet]/positions.json'
  'positions/[wallet]/trades.json'
  'positions/[wallet]/activity.json'
  'onboard/$index'
  'onboard/$list'
  'onboard/[wallet]/$index'
  'onboard/[wallet]/$list'
  'onboard/[wallet]/begin'
  'onboard/[wallet]/status.json'
  'onboard/[wallet]/plan.md'
  'onboard/[wallet]/approvals.json'
  'account/$index'
  'account/$list'
  'account/[wallet]/$index'
  'account/[wallet]/$list'
  'account/[wallet]/portfolio.json'
  'account/[wallet]/orders.json'
  'fund/$index'
  'fund/$list'
  'fund/[wallet]/$index'
  'fund/[wallet]/$list'
  'fund/[wallet]/new'
  'fund/[wallet]/[id]/$index'
  'fund/[wallet]/[id]/$list'
  'fund/[wallet]/[id]/plan.md'
  'fund/[wallet]/[id]/request.json'
  'fund/[wallet]/[id]/status.json'
  'trade/$index'
  'trade/$list'
  'trade/[wallet]/$index'
  'trade/[wallet]/$list'
  'trade/[wallet]/new'
  'trade/[wallet]/drafts/$index'
  'trade/[wallet]/drafts/$list'
  'trade/[wallet]/drafts/[id]/$index'
  'trade/[wallet]/drafts/[id]/$list'
  'trade/[wallet]/drafts/[id]/plan.md'
  'trade/[wallet]/drafts/[id]/order.json'
  'trade/[wallet]/drafts/[id]/policy_check.json'
  'trade/[wallet]/drafts/[id]/quote.json'
  'trade/[wallet]/drafts/[id]/review_intent.json'
  'trade/[wallet]/receipts/$index'
  'trade/[wallet]/receipts/$list'
  'trade/[wallet]/receipts/[id]/$index'
  'trade/[wallet]/receipts/[id]/$list'
  'trade/[wallet]/receipts/[id]/receipt.json'
)

cargo build \
  --manifest-path "$PROXY/Cargo.toml" \
  --target wasm32-unknown-unknown \
  --release

mkdir -p "$TMP"
wasm-tools component new "$CORE" -o "$COMPONENT"
wasm-tools validate "$COMPONENT"

rm -rf "$OUT"
for route in "${routes[@]}"; do
  mkdir -p "$(dirname "$OUT/$route.wasm")"
  cp "$COMPONENT" "$OUT/$route.wasm"
  chmod 0644 "$OUT/$route.wasm"
done

echo "wrote ${#routes[@]} v2 route components under $OUT"
