/// The pay-word list and the card-secret predicate, substituted into the page scripts.
/// Payment words locate candidate controls; they are not an authorization boundary.
/// CheckoutService refuses generic agent interactions before dispatching scripts.
pub(crate) fn prepare(source: &str) -> String {
    source
        .replace("BLOOM_PAY_WORDS", include_str!("pay-words.js").trim())
        .replace("BLOOM_CARD_SECRET", include_str!("card-secret.js").trim())
}
