//! What each canonical Petal's EVM transactions need the wallet policy to
//! allow.
//!
//! Machine refuses an outbox transaction whose `to` address is not in the
//! wallet policy's `allowed_destinations`, and an empty list refuses every
//! transaction. The default policy proposes these alongside the chosen Petal
//! packages so a wallet can use its Petals without another ceremony. They live
//! in Bloom's source, never in config or in anything a Petal supplies at
//! runtime, and the owner still approves the policy ceremony that adds them.
//!
//! No contract address is listed. Machine takes a contract call's `to` as its
//! recipient, so listing a token contract or a router would let any staged
//! call to it, from any Petal or the agent, transfer, approve or forward funds
//! to anyone. Destinations that change per transaction, such as an approval's
//! token or a NEAR Intents deposit address, cannot be listed either. Each
//! Petal instead gets a `petal:<name>` entry on the chains it uses, which
//! Machine matches only against what that Petal staged.

/// A wallet policy destination: a Bloom chain name and an address on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PetalPolicyDestination {
    pub chain: &'static str,
    /// Lowercase `0x` address, matching what Machine's planner compares.
    pub destination: &'static str,
}

/// The destinations a Petal needs, by catalog name. Unknown or non-transacting
/// Petals have none.
pub fn for_petal(name: &str) -> &'static [PetalPolicyDestination] {
    match name {
        "enso" => ENSO_POLICY_DESTINATIONS,
        "near-intents" => NEAR_INTENTS_POLICY_DESTINATIONS,
        "polymarket" => POLYMARKET_POLICY_DESTINATIONS,
        _ => &[],
    }
}

/// Enso swaps through its Router V2, which runs whatever command sequence a
/// transaction's calldata gives it, so it can forward the value or tokens it
/// receives anywhere. Listing the router's address would let any call to it
/// pass, including the agent's own raw call or an approval naming it as
/// spender. `petal:enso` instead trusts only what this Petal stages, as with
/// Polymarket and NEAR Intents: the router call, and the exact approval of a
/// route's input token, which varies per route. Every transaction is still an
/// approval the owner signs.
///
/// The chains are the ones Enso's shipped route rules allow, by Bloom chain
/// name; Machine refuses an outbox transaction on a chain missing here, so
/// such a chain cannot swap even though Enso plans the route. A chain Enso's
/// rules stop allowing comes out: Enso v0.1.7 dropped Arc, so it is not listed.
pub const ENSO_POLICY_DESTINATIONS: &[PetalPolicyDestination] = &[
    PetalPolicyDestination {
        chain: "arbitrum",
        destination: ENSO_STAGED,
    },
    PetalPolicyDestination {
        chain: "avalanche",
        destination: ENSO_STAGED,
    },
    PetalPolicyDestination {
        chain: "base",
        destination: ENSO_STAGED,
    },
    PetalPolicyDestination {
        chain: "bsc",
        destination: ENSO_STAGED,
    },
    PetalPolicyDestination {
        chain: "ethereum",
        destination: ENSO_STAGED,
    },
    PetalPolicyDestination {
        chain: "gnosis",
        destination: ENSO_STAGED,
    },
    PetalPolicyDestination {
        chain: "hyperliquid",
        destination: ENSO_STAGED,
    },
    PetalPolicyDestination {
        chain: "optimism",
        destination: ENSO_STAGED,
    },
    PetalPolicyDestination {
        chain: "polygon",
        destination: ENSO_STAGED,
    },
    PetalPolicyDestination {
        chain: "linea",
        destination: ENSO_STAGED,
    },
    PetalPolicyDestination {
        chain: "robinhood",
        destination: ENSO_STAGED,
    },
    PetalPolicyDestination {
        chain: "tempo",
        destination: ENSO_STAGED,
    },
];

/// What Enso stages, as Machine records it on an outbox entry.
const ENSO_STAGED: &str = "petal:enso";

/// NEAR Intents deposits go to a fresh address for every quote, signed by the
/// 1Click API, so no fixed address can be listed. `petal:near-intents` instead
/// says the wallet trusts this Petal to choose the destination on these chains:
/// Machine accepts the address it staged, and nothing else on the wallet is
/// loosened. The pinned release verifies the quote's signature, sends refunds
/// to the wallet and caps slippage, but does not cap the input or pin the
/// payout to the wallet (bloom-petal-near#11 adds both). Every deposit is
/// still an approval the owner signs. Removing this entry gates NEAR again.
///
/// The chains are the ones the pinned release maps (`route/src/assets.rs`).
const NEAR_INTENTS_POLICY_DESTINATIONS: &[PetalPolicyDestination] = &[
    PetalPolicyDestination {
        chain: "arbitrum",
        destination: NEAR_INTENTS_STAGED,
    },
    PetalPolicyDestination {
        chain: "avalanche",
        destination: NEAR_INTENTS_STAGED,
    },
    PetalPolicyDestination {
        chain: "base",
        destination: NEAR_INTENTS_STAGED,
    },
    PetalPolicyDestination {
        chain: "bsc",
        destination: NEAR_INTENTS_STAGED,
    },
    PetalPolicyDestination {
        chain: "ethereum",
        destination: NEAR_INTENTS_STAGED,
    },
    PetalPolicyDestination {
        chain: "gnosis",
        destination: NEAR_INTENTS_STAGED,
    },
    PetalPolicyDestination {
        chain: "optimism",
        destination: NEAR_INTENTS_STAGED,
    },
    PetalPolicyDestination {
        chain: "polygon",
        destination: NEAR_INTENTS_STAGED,
    },
];

/// The destination form meaning "whatever this Petal stages". It matches the
/// `petal_id` Machine records on an outbox entry.
const NEAR_INTENTS_STAGED: &str = "petal:near-intents";

/// Polymarket funds its deposit wallet on Polygon with a direct pUSD transfer
/// to that wallet, or an Enso swap after an exact ERC-20 approval, all staged
/// as calls to the token contracts and the Enso router. Listing those
/// contracts would let any Petal, or the agent, call them too, so a raw
/// `transfer` or `approve` of pUSD, USDC or USDC.e to anyone would pass.
/// `petal:polymarket` instead trusts only what this Petal stages on Polygon,
/// as NEAR Intents is trusted; every transaction is still an approval the
/// owner signs. The pinned release checks a direct funding transfer against
/// its spend cap and the wallet's balance.
pub const POLYMARKET_POLICY_DESTINATIONS: &[PetalPolicyDestination] = &[PetalPolicyDestination {
    chain: "polygon",
    destination: POLYMARKET_STAGED,
}];

/// What Polymarket stages, as Machine records it on an outbox entry.
const POLYMARKET_STAGED: &str = "petal:polymarket";
