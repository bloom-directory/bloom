# Polygon default RPC review — 2026-10-28

## Findings and change

The original PR incorrectly treated a local DNS failure as proof that
`polygon-bor-rpc.publicnode.com` was retired. Both Google and Cloudflare DNS
returned A records for it; HTTPS JSON-RPC calls using those answers succeeded.
[PublicNode still advertises that exact hostname](https://polygon.publicnode.com/).
Keep it in the defaults and preserve existing configurations that use it.

The other old default, `polygon-rpc.com`, really did lose keyless access:
[Polygon announced its retirement](https://forum.polygon.technology/t/deprecation-of-polygons-public-rpc-endpoints-mainnet-amoy/22014),
and [the endpoint's own site](https://polygon-rpc.com/) now requires an API key.
A local HTTP failure alone would not establish this. Authenticated URLs and
operator-specified `rpc_endpoints` are not migrated.

Use three providers: dRPC, PublicNode and Tenderly. dRPC and Tenderly are
listed in [Polygon's current RPC documentation](https://docs.polygon.technology/pos/reference/rpc-endpoints).
Multiple PublicNode aliases are not provider diversity. Bloom already races
two HTTP transports per call and scores the larger pool; this PR does not
change that transport policy or increase simultaneous fan-out.

Saved lists containing the exact retired URL replace it with dRPC (unless
already present), remove repeated retired entries, and append any missing
defaults. Other entries retain their relative order. Lists without the retired
URL, near-matching URLs with credentials/query strings/trailing slash, and
explicit endpoint configurations stay unchanged. Migration is idempotent.

## Read-only network checks

The probes used one workstation, not multiple independent geographic hosts.
System DNS failed for several valid hostnames; Python and curl also produced
different HTTP results. Provider-wide reachability is not inferred from these
local failures. For the method matrix below, curl used `--resolve` with live
Google DNS A-record answers, retaining normal hostname/TLS verification.
Those addresses are test inputs only, never hardcoded into Bloom.

| Provider | Chain ID, recent block, pending nonce, fee history, priority fee, gas estimate | Recent mined receipt | Unknown-hash receipt |
|---|---|---|---|
| dRPC | Passed | Returned | `null` |
| PublicNode original hostname | Passed | Returned | Archive-token JSON-RPC error |
| PublicNode two alternate aliases | Passed | Returned | Same archive-token error |
| Tenderly | Passed | Returned | `null` |
| 1RPC | Passed | Returned | Endpoint-discontinued response |
| OnFinality | Intermittent rate limits; incomplete | Not checked | Rate limited |

Keep the three usable providers, rather than adding known problematic responses
or treating every advertised public URL as verified. Rate limits and DNS/IP
reachability can change. This snapshot does not guarantee global availability.

Probes used `eth_chainId`, `eth_getBlockByNumber("latest", false)`,
`eth_getTransactionCount(address, "pending")`, `eth_feeHistory`,
`eth_maxPriorityFeePerGas`, zero-value `eth_estimateGas`, and
`eth_getTransactionReceipt` for a hash from the recent block and an unknown
all-`ff` hash. No wallet was signed and no transaction was broadcast.

## Remaining verification

Existing receipt-error regressions remain: a provider error must not become
"no transaction" or permit a new signing/broadcast attempt. An unknown-hash
error is not proof of how that provider handles an actually pending transaction.

Config tests cover fresh defaults, saved-config migration, custom URL order,
preserving PublicNode, duplicates, explicit endpoints and idempotence. Live
signed stage → broadcast → receipt acceptance on the exact release services
is still required. Linux release build and both macOS conformance runs remain
release gates; read-only endpoint probes do not replace them.
