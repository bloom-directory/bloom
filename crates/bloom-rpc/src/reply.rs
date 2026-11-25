//! What a JSON-RPC error reply says, for the decisions that depend on it:
//! whether to retry it, whether it is the node's answer, and which reply
//! reports a broadcast.

use alloy::rpc::json_rpc::ErrorPayload;

/// Whether a JSON-RPC error reply reports that the call reverted, rather
/// than that the node could not or would not run it.
///
/// Nodes report a revert in one of two ways:
/// - code 3 with the revert data, which geth, erigon, reth, anvil and
///   current nethermind send when the revert carries data;
/// - a message that says so, such as geth's and erigon's `-32000
///   "execution reverted"` for a revert without data, besu's "Execution
///   reverted", or hardhat's `-32603` "reverted with reason string".
///
/// Every other reply is about the node or the request, not the contract:
/// an invalid API key, an unsupported method, an internal error, missing
/// state, out of gas. Older nethermind's `-32015 "VM execution error."`
/// also lands here, since its message does not mention the revert.
///
/// A revert's message carries the revert reason, which the contract
/// chooses, so nothing else may read meaning into it: a reason such as
/// "Vault capacity exceeded" is not a rate limit.
pub fn is_revert_reply<E>(payload: &ErrorPayload<E>) -> bool {
    payload.code == 3 || payload.message.to_ascii_lowercase().contains("revert")
}

/// Whether a reply to a broadcast says the node already has the
/// transaction, which proves it was accepted. The broadcast path reads the
/// same words.
pub(crate) fn is_already_known<E>(payload: &ErrorPayload<E>) -> bool {
    payload
        .message
        .to_ascii_lowercase()
        .contains("already known")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(code: i64, message: &str) -> ErrorPayload {
        serde_json::from_value(serde_json::json!({ "code": code, "message": message })).unwrap()
    }

    #[test]
    fn reverts_are_recognised_by_code_or_wording() {
        for (code, message, revert) in [
            (3, "execution reverted: Vault capacity exceeded", true),
            (3, "custom error", true),
            (-32000, "execution reverted", true),
            (
                -32603,
                "Error: VM Exception: reverted with reason string 'x'",
                true,
            ),
            (-32000, "Execution Reverted", true),
            (-32000, "nonce too low", false),
            (-32005, "rate limited", false),
            (-32015, "VM execution error.", false),
        ] {
            assert_eq!(
                is_revert_reply(&payload(code, message)),
                revert,
                "{code} {message}"
            );
        }
    }

    #[test]
    fn already_known_is_recognised_in_any_case() {
        assert!(is_already_known(&payload(-32000, "already known")));
        assert!(is_already_known(&payload(-32000, "Already Known")));
        assert!(!is_already_known(&payload(-32000, "nonce too low")));
    }
}
