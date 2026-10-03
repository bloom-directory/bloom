# Triad authority Petal fixture

This is a developer/test fixture, not a production Petal. It proves that an
ordinary mounted write can request a Signer-owned Petal child key and use its
public `KeyRef` for payload-bearing signing. The follow-up mounted read exposes
only public metadata, ceremony state, or the resulting signature.

Reproduce the checked-in component and generated package artifacts with
`./build-fixture.sh` (set `BLOOM_FIXTURE_BUILDER` to select a Bloom binary),
install this directory with `bloom petals install`, then use only the mounted
filesystem:

```sh
cp request.json "$BLOOM_MOUNT/petals/triad-authority-fixture/wallets/<wallet>/<index>/session.json"
cat "$BLOOM_MOUNT/petals/triad-authority-fixture/wallets/<wallet>/<index>/session.json"
```

When the result reports a pending key operation, obtain its owner-only ceremony
URL through the same mounted filesystem (the guest never receives the token):

```sh
ls "$BLOOM_MOUNT/petal-key-requests"
cat "$BLOOM_MOUNT/petal-key-requests/"*.json
```

Repeat the exact same fixture write after completing that custody ceremony.
Signing ceremonies, when required, are reported directly in the fixture's
public result; repeat the exact same write after completing one. A request has
this shape:

```json
{
  "request_id": "mounted-fixture-1",
  "wallet_id": "wallet",
  "purpose": "fixture-agent",
  "maximum_lifetime_ms": 300000,
  "preimage_hex": "66697874757265207061796c6f6164",
  "nonce_hex": "00112233445566778899aabbccddeeff",
  "approval_hint": "<64-lowercase-hex approval id>"
}
```

The fixture deliberately supports only
`secp256k1-sha256-recoverable`. It computes both payload digests itself and
constructs the canonical `PetalUseClaim`; it never offers hash-only signing.
