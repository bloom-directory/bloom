//! Fixed contracts each canonical Petal stages EVM transactions to.
//!
//! Machine refuses an outbox transaction whose `to` address is not in the
//! wallet policy's `allowed_destinations`, and an empty list refuses every
//! transaction. The default policy proposes these alongside the chosen Petal
//! packages so a wallet can use its Petals without another ceremony. They live
//! in Bloom's source, never in config or in anything a Petal supplies at
//! runtime, and the owner still approves the policy ceremony that adds them.
//!
//! Destinations that change per transaction cannot be listed here: an ERC-20
//! approval's token contract, a NEAR Intents deposit address, or the deposit
//! wallet Polymarket funds. Nor can a token contract a Petal calls: Machine
//! takes a contract call's `to` as its recipient, so listing a token would let
//! any staged call to it, from any Petal or the agent, transfer or approve
//! that token to anyone. Such Petals get a `petal:<name>` entry instead.

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

/// Enso Router V2 on every chain Enso's shipped route rules allow, by Bloom
/// chain name. Machine refuses an outbox transaction whose destination is not
/// in the wallet policy, so a chain missing here cannot swap even though Enso
/// plans the route.
///
/// Each address is Enso's published deployment for that chain
/// (https://docs.enso.build/pages/build/reference/deployments) and was checked
/// with `eth_getCode`: identical bytecode wherever the address repeats, and a
/// distinct deployment on Linea and on Robinhood Chain and Tempo. Adding a
/// chain means checking its router the same way, and a chain Enso's rules stop
/// allowing comes out: Enso v0.1.7 dropped Arc, so its router is not listed.
///
/// Enso's approvals go to the input token, which varies per route, so a swap
/// from an ERC-20 still needs that token allowed separately.
pub const ENSO_POLICY_DESTINATIONS: &[PetalPolicyDestination] = &[
    PetalPolicyDestination {
        chain: "arbitrum",
        destination: ENSO_ROUTER_V2,
    },
    PetalPolicyDestination {
        chain: "avalanche",
        destination: ENSO_ROUTER_V2,
    },
    PetalPolicyDestination {
        chain: "base",
        destination: ENSO_ROUTER_V2,
    },
    PetalPolicyDestination {
        chain: "bsc",
        destination: ENSO_ROUTER_V2,
    },
    PetalPolicyDestination {
        chain: "ethereum",
        destination: ENSO_ROUTER_V2,
    },
    PetalPolicyDestination {
        chain: "gnosis",
        destination: ENSO_ROUTER_V2,
    },
    PetalPolicyDestination {
        chain: "hyperliquid",
        destination: ENSO_ROUTER_V2,
    },
    PetalPolicyDestination {
        chain: "optimism",
        destination: ENSO_ROUTER_V2,
    },
    PetalPolicyDestination {
        chain: "polygon",
        destination: ENSO_ROUTER_V2,
    },
    PetalPolicyDestination {
        chain: "linea",
        destination: ENSO_ROUTER_V2_LINEA,
    },
    PetalPolicyDestination {
        chain: "robinhood",
        destination: ENSO_ROUTER_V2_ROBINHOOD_TEMPO,
    },
    PetalPolicyDestination {
        chain: "tempo",
        destination: ENSO_ROUTER_V2_ROBINHOOD_TEMPO,
    },
];

/// Enso Router V2 on every covered chain except Linea, Robinhood Chain and Tempo.
const ENSO_ROUTER_V2: &str = "0xf75584ef6673ad213a685a1b58cc0330b8ea22cf";
/// Enso's separate Linea deployment.
const ENSO_ROUTER_V2_LINEA: &str = "0xa146d46823f3f594b785200102be5385cafce9b5";
/// Enso's deployment shared by Robinhood Chain and Tempo.
const ENSO_ROUTER_V2_ROBINHOOD_TEMPO: &str = "0xcfbaa9cfce952ca4f4069874ff1df8c05e37a3c7";

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
