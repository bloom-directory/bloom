# Private peer review over Iroh

Bloom can exchange advisory intent reviews with explicitly enrolled Bloom
peers. Connectivity, endpoint authentication, NAT traversal, direct-path
upgrades, and relay fallback are provided by Iroh 1.1. This feature is disabled
by default and is not a chat system, marketplace, copy-trading protocol, or
remote execution API.

## Security boundary

A remote message is untrusted data. Bloom verifies the Iroh transport peer,
application signature, payload digest, schema, expiration, durable replay
nonce, peer policy, evaluator alias, and immutable local Petal binding before
evaluation. The remote peer never selects a package, route, capability, wallet,
Broker operation, Signer operation, or transaction path.

Automatically invoked evaluators must be zero-authority Petals:

- no `bloom:vfs.read` or `bloom:vfs.write`;
- no HTTP, store, signing, chain, transaction-outbox, or key-derive capability;
- no WASI directory or socket inheritance;
- a deny-all host, empty capability mask, bounded fuel and memory, and a host
  timeout are applied on every invocation.

An `approve` decision is advisory only. It cannot stage, sign, confirm, or
broadcast a trade.

## Configuration

```toml
[coordination]
enabled = true
listen = true
auto_evaluate = true
request_ttl_secs = 30
max_envelope_bytes = 65536
max_concurrent_connections = 32
max_requests_per_minute = 10

[coordination.iroh]
mode = "n0" # address lookup, NAT traversal, direct paths, relay fallback

[coordination.evaluators.dummy-risk]
petal = "dummy-reviewer"
package_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
route = "review.json"
input_schema = "bloom.trade-review-request/v1"
output_schema = "bloom.trade-review-decision/v1"
auto_run = true
timeout_ms = 3000
fuel = 5000000
memory_pages = 256
```

Bloom fails startup when an auto-run evaluator is not installed at the pinned
hash, its route is missing, or the Petal declares any capability. The same
checks run again immediately before evaluation.

## Enrollment

Exchange tickets over an already authenticated private channel:

```sh
bloom peer identity
bloom peer invite --expires-secs 600
bloom peer add 'bloom-peer-v1:...' --allow-evaluator dummy-risk
bloom peer list
```

The ticket contains a signed Iroh `EndpointAddr` and expiration. Iroh address
lookup resolves a known endpoint; it is not a semantic directory of agents or
review capabilities. Bloom exchanges no public discovery announcements in this
version.

Changing the evaluator permission is explicit and local:

```sh
bloom peer allow ENDPOINT_ID dummy-risk
```

Restart the daemon after enrollment or policy changes in this initial version.

## Sending a review

Create a request JSON:

```json
{
  "schema": "bloom.trade-review-request/v1",
  "request_id": "018f47e0-b25c-7b1a-9c1a-4d77ae741234",
  "evaluator_alias": "dummy-risk",
  "intent": {
    "venue": "hyperliquid",
    "instrument": "BTC",
    "side": "buy",
    "order_type": "limit",
    "quantity": "0.01",
    "limit_price": "62000"
  },
  "facts": { "strategy_confidence": "0.78" },
  "requested_output_schema": "bloom.trade-review-decision/v1",
  "expires_at_ms": 1893456000000
}
```

Then queue and inspect it:

```sh
bloom peer review ENDPOINT_ID request.json
bloom peer review-status REQUEST_ID
```

The mounted equivalent is `coordination/requests/new` followed by the request
directory under `coordination/requests/`.

## Protocol limits

The ALPN is `bloom/peer-review/1`. Messages are length-prefixed JSON with a
default maximum envelope size of 64 KiB. Payloads use JCS canonicalization,
domain-separated SHA-256 digests, and the dedicated Iroh Ed25519 endpoint key.
The durable replay key is `(sender endpoint, nonce)`.

The first protocol deliberately excludes gossip, blobs, docs, broadcast,
groups, quorum, public discovery, remote mailboxes, and execution requests.
