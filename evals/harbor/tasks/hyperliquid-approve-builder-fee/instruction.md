Use the Bloom filesystem mounted at `/bloom` to perform this exact task on **Hyperliquid**, on the network named in `BLOOM_EVAL_NETWORK` (`mainnet` or `testnet`):

Exercise the mounted filesystem using ordinary shell filesystem operations only
(for example, `cat` for reads and shell redirection for writes). Do not invoke
`bloom vfs`, the `bloom` executable, a Machine RPC endpoint, or any alternate
transport. If a mounted operation fails, treat it as a task failure; do not
bypass or replace the mount.

Never issue concurrent `/bloom` commands. A direct read may take several
seconds; let it finish before the next read starts.

1. Read `/bloom/petals/hyperliquid/README.md` for the exact request and
   response contract of `approve_builder_fee.json` and `max_builder_fee`.
2. This task uses the dedicated wallet in `BLOOM_EVAL_WALLET_ID` (a Bloom
   wallet id, the path segment for the exchange write below) and its on-chain
   address in `BLOOM_EVAL_WALLET` (the path segment for the venue read
   below). The two identifiers are not interchangeable; using one where the
   other belongs fails as an unqualified permission error.
3. A trusted host has already completed the one owner ceremony this action
   requires, using the exact request body below — do not vary any field, and
   do not expect a ceremony URL to appear. Write exactly this JSON object to
   `/bloom/petals/hyperliquid/$BLOOM_EVAL_NETWORK/exchange/$BLOOM_EVAL_WALLET_ID/approve_builder_fee.json`:

   ```json
   {"builder":"$BLOOM_EVAL_BUILDER","max_fee_tenths_bps":$BLOOM_EVAL_BUILDER_MAX_FEE_TENTHS_BPS,"nonce":$BLOOM_EVAL_APPROVAL_NONCE}
   ```

   (Substitute the literal values of `BLOOM_EVAL_BUILDER`,
   `BLOOM_EVAL_BUILDER_MAX_FEE_TENTHS_BPS`, and `BLOOM_EVAL_APPROVAL_NONCE`
   from your environment — do not compute a new nonce.)
4. Poll
   `/bloom/petals/hyperliquid/$BLOOM_EVAL_NETWORK/exchange/$BLOOM_EVAL_WALLET_ID/last_response.json`
   until it exists, then read it. It must be Hyperliquid's own response to
   the `approveBuilderFee` action, not a local Bloom error.
5. Poll
   `/bloom/petals/hyperliquid/$BLOOM_EVAL_NETWORK/users/$BLOOM_EVAL_WALLET/max_builder_fee/$BLOOM_EVAL_BUILDER.json`
   until its value is at least `$BLOOM_EVAL_BUILDER_MAX_FEE_TENTHS_BPS`. This
   is the independent, venue-side confirmation that the approval actually
   took effect — do not treat step 4's response alone as sufficient
   evidence.
6. Write exactly one JSON object to `/logs/artifacts/result.json`, matching
   the schema below. Harbor re-materializes that conventional artifact path
   unchanged for the verifier. The `max_fee_tenths_bps` field must be a JSON
   number, not a string.

   ```json
   {
     "schema": "bloom.eval.hyperliquid_approve_builder_fee.v1",
     "status": "complete",
     "network": "<BLOOM_EVAL_NETWORK>",
     "wallet": "<BLOOM_EVAL_WALLET>",
     "wallet_id": "<BLOOM_EVAL_WALLET_ID>",
     "builder": "<BLOOM_EVAL_BUILDER>",
     "max_fee_tenths_bps": <BLOOM_EVAL_BUILDER_MAX_FEE_TENTHS_BPS>,
     "nonce": <BLOOM_EVAL_APPROVAL_NONCE>,
     "hyperliquid_response": <the exact object read in step 4>,
     "observed_max_builder_fee": <the exact number read in step 5>
   }
   ```

This task authorizes writes only to the exact
`approve_builder_fee.json` leaf for the exact wallet and builder named above.
Do not use any other wallet, builder address, network, or fee value. Submit
exactly one write and do not retry with a different nonce if it is rejected —
report the rejection as the observed `hyperliquid_response` instead of
substituting a different request. Never invoke any other exchange route.
