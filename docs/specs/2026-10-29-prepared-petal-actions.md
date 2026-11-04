# Prepared Petal actions

Status: current phase 1 contract, updated for persona-ready Petals revision 3.
The [revision 3 specification](2026-11-02-persona-ready-petals.md) supersedes
the earlier unreleased prepared-format and protocol-profile drafts.

A prepared action carries one typed signing payload, its complete review
artifact and an explicit spend declaration. The manifest declares `bloom:sign`
and separately `bloom:sign.status`. Automatic routes declare
`economic_effects_schema = 1`; explicit zero-spend classes are a subset of the
manifest's allowed signing intents. The installer certifies those declarations
in the exact package's route provenance.

Machine accepts `bloom.message.review` version 1 EIP-712 typed data or EIP-191
personal messages. It reconstructs the standard preimage and rejects payload or
hash mismatches. These checks establish the review/signature binding, not the
truth of the package's declared economic effects. No Petal-specific prepared
format, verifier or class exception is supported.

`Spend::Bounded` contains positive, nonduplicate raw-unit debits.
`Spend::None` explicitly declares no wallet assets move; an empty or zero
bounded declaration is invalid. `Spend::Unspecified` always retains exact
review. Machine supplies the authenticated spending `KeyRef` and ordered
payload context; guest fields cannot select another account.

Broker trusts pinned, installer-certified declarations. Automatic bounded
coverage requires all declared assets in the active grant's token policy.
Zero-spend coverage requires a Trader or Degen grant listing that certified
class, within one aggregate per-grant rate cap. Institutional always requires
exact review. Unsupported scope and exhausted limits use exact review only
after authenticated operation status proves no earlier signature can exist.
Malformed input, invalid provenance and review hash mismatches are rejected.

The immutable operation identity includes package, route, wallet, account and
Petal domain operation key. Retries preserve the exact action and recover its
original result without another charge. Changed bytes under a retained key
conflict. A terminal key does not silently create a fresh approval; a new
reviewed attempt needs a new operation key. Status returns explicit pending,
recovery, signed or terminal outcomes without authorizing a signature.

Phase 2 adds shared SDK orchestration and catalog-driven presentation. It does
not add protocol-specific authority branches. Existing custody and process
boundaries remain unchanged: Machine talks only to Broker, and only Broker
asks Signer to sign.

Phase 1 discovery proposes only recoverable secp256k1/Keccak grants, matching
the supported EIP-712 and EIP-191 generic review formats. It does not propose
unused Ed25519 grants or selections with neither token nor certified zero-spend
coverage. Other key families need a supported generic review format first.
