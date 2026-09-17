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
//! approval's token contract, or a NEAR Intents deposit address.

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
/// distinct deployment on Linea and on the Arc/Robinhood/Tempo family. Adding
/// a chain means checking its router the same way.
///
/// Enso's approvals go to the input token, which varies per route, so a swap
/// from an ERC-20 still needs that token allowed separately. Enso v0.1.5 also
/// names BNB Chain `bnb` while Bloom names it `bsc`, so its own rules refuse
/// `bsc` routes until Enso accepts Bloom's name; the destination is listed
/// here so the policy is ready when it does.
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
        chain: "arc",
        destination: ENSO_ROUTER_V2_ARC_FAMILY,
    },
    PetalPolicyDestination {
        chain: "robinhood",
        destination: ENSO_ROUTER_V2_ARC_FAMILY,
    },
    PetalPolicyDestination {
        chain: "tempo",
        destination: ENSO_ROUTER_V2_ARC_FAMILY,
    },
];

/// Enso Router V2 on every covered chain except Linea and the Arc family.
const ENSO_ROUTER_V2: &str = "0xf75584ef6673ad213a685a1b58cc0330b8ea22cf";
/// Enso's separate Linea deployment.
const ENSO_ROUTER_V2_LINEA: &str = "0xa146d46823f3f594b785200102be5385cafce9b5";
/// Enso's deployment shared by Arc, Robinhood Chain, and Tempo.
const ENSO_ROUTER_V2_ARC_FAMILY: &str = "0xcfbaa9cfce952ca4f4069874ff1df8c05e37a3c7";

/// Polymarket funds its deposit wallet on Polygon with a direct pUSD transfer,
/// or an Enso swap after an exact ERC-20 approval. The pUSD and USDC.e
/// addresses are Polymarket's own constants (`polymarket/eip712.rs` in the
/// pinned release); the router is Enso Router V2. Funding from another token
/// needs that token allowed separately.
pub const POLYMARKET_POLICY_DESTINATIONS: &[PetalPolicyDestination] = &[
    PetalPolicyDestination {
        chain: "polygon",
        destination: "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb",
    },
    PetalPolicyDestination {
        chain: "polygon",
        destination: "0x2791bca1f2de4661ed88a30c99a7a9449aa84174",
    },
    PetalPolicyDestination {
        chain: "polygon",
        destination: ENSO_ROUTER_V2,
    },
];
