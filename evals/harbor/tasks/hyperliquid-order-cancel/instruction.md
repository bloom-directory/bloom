Use the Bloom filesystem mounted at `/bloom` to perform this exact task on **Hyperliquid mainnet**:

1. Use the dedicated wallet in `BLOOM_EVAL_WALLET` and the stable session ID in `BLOOM_EVAL_SESSION_ID`. Two identifiers name this wallet and they are not interchangeable. `BLOOM_EVAL_WALLET_ID` is the Bloom wallet id, and it is the path segment for every session route: `/bloom/petals/hyperliquid/mainnet/agent_sessions/$BLOOM_EVAL_WALLET_ID/$BLOOM_EVAL_SESSION_ID/`. `BLOOM_EVAL_WALLET` is the on-chain address, and it is the path segment for Hyperliquid account reads such as `/bloom/petals/hyperliquid/mainnet/users/$BLOOM_EVAL_WALLET/`. Using one where the other belongs fails as an unqualified permission error.
2. The trusted host has already created and owner-approved the session. Read its `status.json` and refuse to continue unless it is active, mainnet, BTC-only (asset ID `0`), capped at `11` USD notional and 1x leverage.
3. Set BTC cross leverage to exactly 1 through the session's `update_leverage.json` route and confirm that action succeeded.
4. Read the current BTC mark/mid through Bloom. Submit one BTC **post-only (ALO) buy** with client order ID `BLOOM_EVAL_CLOID`. Its limit price must be 5% below the observed mark (round down only as needed for Hyperliquid's tick rules). Choose a five-decimal-or-less BTC size whose notional at the limit price is at least $10 and no more than $11.
5. Confirm the order response says the order is resting. Cancel that exact order, preferably by its returned order ID, and confirm the cancel succeeded.
6. Read open orders through Bloom and confirm no order with `BLOOM_EVAL_CLOID` remains. Invoke the session's `cancel_all` cleanup endpoint, but leave the session active so the verifier and host can independently repeat cleanup and stop it.
7. Write exactly one JSON object to `/logs/artifacts/result.json`, matching the schema below. Harbor re-materializes that conventional artifact path unchanged for the verifier. Decimal values must be JSON strings.

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

Read `/bloom/petals/hyperliquid/README.md`, the relevant route descriptions, status, response, and error files before writing. A successful filesystem write alone is not evidence that Hyperliquid accepted an action. The complete `/bloom` mount is available for normal discovery, but this task authorizes writes only to the exact bounded Hyperliquid session named above. Do not use any other wallet, asset, network, amount, side, order type, or client order ID. Submit exactly one order action and do not place a replacement order if it is rejected. Never stop the session yourself. If any step fails, invoke `cancel_all`, leave the session active for host cleanup, and do not report `complete`.
