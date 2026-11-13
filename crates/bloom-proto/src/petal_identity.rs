//! Public Petal provenance labels used in plans and audit projections.

/// `petal_id` for the EVM wallet transaction surface.
pub const PETAL_ID_EVM_WALLET: &str = "evm-wallet";
/// `petal_id` for the paid HTTP (x402/MPP) surface.
pub const PETAL_ID_PAID_HTTP: &str = "paid-http";
/// `petal_id` for the DeFi surface.
pub const PETAL_ID_DEFI: &str = "defi";
/// `petal_id` for wallet-policy edits and credential management.
pub const PETAL_ID_WALLET_POLICY: &str = "wallet-policy";

/// Version recorded for first-party placeholder identities.
pub const FIRST_PARTY_PETAL_VERSION_V0: &str = "v0";
/// Prefix used by dynamically installed Petal identities.
pub const PETAL_ID_PREFIX: &str = "petal:";
/// Prefix shared by first-party placeholder digests.
pub const PLACEHOLDER_DIGEST_PREFIX: &str = "first-party-placeholder:";

pub const PLACEHOLDER_DIGEST_EVM_WALLET: &str = "first-party-placeholder:evm-wallet:v0";
pub const PLACEHOLDER_DIGEST_PAID_HTTP: &str = "first-party-placeholder:paid-http:v0";
pub const PLACEHOLDER_DIGEST_DEFI: &str = "first-party-placeholder:defi:v0";
pub const PLACEHOLDER_DIGEST_WALLET_POLICY: &str = "first-party-placeholder:wallet-policy:v0";

/// True when `digest` is a placeholder rather than reproducible provenance.
pub fn is_placeholder_digest(digest: &str) -> bool {
    digest.starts_with(PLACEHOLDER_DIGEST_PREFIX)
}

/// Human-readable provenance class for audit and status projections.
pub fn label_petal_digest(digest: &str) -> &'static str {
    if is_placeholder_digest(digest) {
        "placeholder"
    } else {
        "build"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_placeholder_and_build_digests() {
        assert_eq!(
            label_petal_digest(PLACEHOLDER_DIGEST_EVM_WALLET),
            "placeholder"
        );
        assert_eq!(label_petal_digest("sha256:abcdef"), "build");
        assert_eq!(label_petal_digest(""), "build");
    }
}
