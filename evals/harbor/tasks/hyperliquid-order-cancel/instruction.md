Use the Bloom filesystem mounted at `/bloom` to perform this exact task on **Hyperliquid mainnet**:

`/bloom` is a dynamic virtual filesystem: directory traversal can execute live
venue reads. Never run `find`, `tree`, `rg --files`, recursive `ls`, or any
broad enumeration under `/bloom`, and never issue concurrent `/bloom` commands.
You may reduce model round trips by using one shell invocation to read multiple
exact paths named below sequentially, with each path labeled in the output. Do
not use background jobs or parallel tools. A direct read may take several
seconds; let it finish before the next read starts. If a command runner reports
that a process is still running, wait on that same process instead of starting
another `/bloom` command.

1. Use the dedicated wallet in `BLOOM_EVAL_WALLET` and the stable session ID in `BLOOM_EVAL_SESSION_ID`. Two identifiers name this wallet and they are not interchangeable. `BLOOM_EVAL_WALLET_ID` is the Bloom wallet id, and it is the path segment for every session route: `/bloom/petals/hyperliquid/mainnet/agent_sessions/$BLOOM_EVAL_WALLET_ID/$BLOOM_EVAL_SESSION_ID/`. `BLOOM_EVAL_WALLET` is the on-chain address, and it is the path segment for Hyperliquid account reads such as `/bloom/petals/hyperliquid/mainnet/users/$BLOOM_EVAL_WALLET/`. Using one where the other belongs fails as an unqualified permission error.
2. The trusted host has already created and owner-approved the session. Read its `status.json` and refuse to continue unless it is active, mainnet, BTC-only (asset ID `0`), capped at `11` USD notional and 1x leverage.
3. Read the session's `update_leverage.json` leaf and follow its `request_schema`, `example`, and `success_evidence` exactly to set BTC cross leverage to 1 and confirm it on the venue.
4. Read the current BTC mark from `/bloom/petals/hyperliquid/mainnet/mids.json`. Then read the session's `order.json` leaf and follow its `request_schema` and `example` to submit one BTC **post-only (ALO) buy** with client order ID `BLOOM_EVAL_CLOID`. Its limit price must be 5% below the observed mark, rounded down to a valid Hyperliquid BTC price: first floor the target to one decimal place; if that result has more than five significant figures, floor the original target to a whole-dollar integer instead. Choose a five-decimal-or-less BTC size whose notional at the limit price is at least $10 and no more than $11.
5. Follow `order.json`'s `success_evidence`: under the session route from step 1, poll the exact immutable `receipts/$BLOOM_EVAL_CLOID/order.json` leaf, confirm its CLOID and nested resting response match the submitted order, and record the venue order ID from that response. Do not substitute `last_response.json` or infer success from the write itself.
6. Read the session's `cancel.json` leaf and cancel the exact order by CLOID using its documented `cancelByCloid` request shape. Under the same session route, poll `receipts/$BLOOM_EVAL_CLOID/cancel.json` until its response records success, then poll `/bloom/petals/hyperliquid/mainnet/users/$BLOOM_EVAL_WALLET/open_orders.json` sequentially until no entry has that CLOID.
7. Invoke the session's `cancel_all` cleanup endpoint, but leave the session active so the verifier and host can independently repeat cleanup and stop it.
8. Write exactly one JSON object to `/logs/artifacts/result.json`, matching the schema below. Harbor re-materializes that conventional artifact path unchanged for the verifier. Decimal values must be JSON strings.

```json
{
  "schema": "bloom.eval.hyperliquid_order_cancel.v1",
  "status": "complete",
  "network": "mainnet",
  "wallet": "<BLOOM_EVAL_WALLET>",
  "session_id": "<BLOOM_EVAL_SESSION_ID>",
  "asset": "BTC",
  "asset_id": 0,
  "side": "buy",
  "leverage": 1,
  "post_only": true,
  "mark_price": "<observed mark>",
  "limit_price": "<submitted price>",
  "size": "<submitted BTC size>",
  "notional_usd": "<limit_price times size>",
  "cloid": "<BLOOM_EVAL_CLOID>",
  "order_status": "resting",
  "order_id": 123,
  "cancel_status": "success",
  "matching_open_orders_after_cancel": 0,
  "session_left_active_for_harness_cleanup": true
}
```

Read `/bloom/petals/hyperliquid/README.md`, then address the exact session and account leaves described above directly; do not enumerate their parent directories. The installed route leaves are the authoritative API contract; follow their request and live-venue success-evidence descriptions instead of substituting payloads from external documentation or another repository revision. A successful filesystem write only means an asynchronous action was dispatched. This task authorizes writes only to the exact bounded Hyperliquid session named above. Do not use any other wallet, asset, network, amount, side, order type, or client order ID. Submit exactly one order action and do not place a replacement order if it is rejected. Never stop the session yourself. If any step fails, invoke `cancel_all`, leave the session active for host cleanup, and do not report `complete`.
