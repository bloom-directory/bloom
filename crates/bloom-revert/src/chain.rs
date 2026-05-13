//! Decoder pipeline. Tries each registered decoder in order; the first
//! `Some(_)` wins. Falls back to a [`DecodedRevert::unknown`] result so
//! callers can always render *something*.

use std::sync::Arc;

use crate::{DecodeContext, DecodedRevert, RevertDecoder};

/// Ordered list of decoders. `decode` walks them once.
#[derive(Clone, Default)]
pub struct DecoderChain {
    decoders: Vec<Arc<dyn RevertDecoder>>,
}

impl DecoderChain {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a decoder. The conventional order is builtin → ABI →
    /// public selector lookup → bytecode decompile.
    pub fn push(&mut self, d: Arc<dyn RevertDecoder>) -> &mut Self {
        self.decoders.push(d);
        self
    }

    /// Builder-style sibling of [`Self::push`].
    pub fn with(mut self, d: Arc<dyn RevertDecoder>) -> Self {
        self.decoders.push(d);
        self
    }

    /// Names of registered decoders, in order. Useful for debug logs.
    pub fn decoder_names(&self) -> Vec<&'static str> {
        self.decoders.iter().map(|d| d.name()).collect()
    }

    /// Run the chain. Empty returndata short-circuits even when no
    /// decoder is registered.
    pub async fn decode(&self, ctx: &DecodeContext) -> DecodedRevert {
        if ctx.returndata.is_empty() && self.decoders.is_empty() {
            return DecodedRevert::empty();
        }
        for d in &self.decoders {
            tracing::trace!(decoder = d.name(), "revert.try");
            if let Some(out) = d.try_decode(ctx).await {
                tracing::debug!(decoder = d.name(), "revert.decoded");
                return out;
            }
            tracing::debug!(decoder = d.name(), "revert.declined");
        }
        DecodedRevert::unknown(ctx.returndata.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BuiltinDecoder, DecodeSource};
    use alloy::primitives::Bytes;
    use alloy::sol_types::SolError as _;

    fn ctx(raw: Vec<u8>) -> DecodeContext {
        DecodeContext {
            returndata: Bytes::from(raw),
            to: None,
            chain_id: 1,
        }
    }

    #[tokio::test]
    async fn empty_chain_returns_unknown_for_unknown_selector() {
        let chain = DecoderChain::new();
        let out = chain.decode(&ctx(vec![1, 2, 3, 4, 0, 0, 0, 0])).await;
        assert_eq!(out.source, DecodeSource::Unknown);
        assert!(out.selector.is_some());
    }

    #[tokio::test]
    async fn empty_returndata_no_decoders_yields_empty_marker() {
        let chain = DecoderChain::new();
        let out = chain.decode(&ctx(Vec::new())).await;
        assert_eq!(out.source, DecodeSource::Builtin);
        assert!(out.selector.is_none());
    }

    alloy::sol! {
        error Error(string);
    }

    #[tokio::test]
    async fn builtin_first_match_wins() {
        let chain = DecoderChain::new().with(crate::boxed(BuiltinDecoder::new()));
        let encoded = Error("hi".to_string()).abi_encode();
        let out = chain.decode(&ctx(encoded)).await;
        assert_eq!(out.source, DecodeSource::Builtin);
        assert_eq!(out.message.as_deref(), Some("hi"));
    }

    #[tokio::test]
    async fn falls_through_when_decoder_returns_none() {
        let chain = DecoderChain::new().with(crate::boxed(BuiltinDecoder::new()));
        let raw = vec![0xab, 0xcd, 0xef, 0x12];
        let out = chain.decode(&ctx(raw)).await;
        assert_eq!(out.source, DecodeSource::Unknown);
    }

    /// Smoke test for `decoder_names` ordering.
    #[test]
    fn names_in_push_order() {
        let chain = DecoderChain::new().with(crate::boxed(BuiltinDecoder::new()));
        assert_eq!(chain.decoder_names(), vec!["builtin"]);
    }

    #[tokio::test]
    async fn order_is_first_match_wins() {
        // First decoder always returns Some; the second is never queried.
        struct AlwaysHit;
        #[async_trait::async_trait]
        impl RevertDecoder for AlwaysHit {
            fn name(&self) -> &'static str {
                "always_hit"
            }
            async fn try_decode(&self, ctx: &DecodeContext) -> Option<DecodedRevert> {
                Some(DecodedRevert {
                    selector: None,
                    name: Some("HIT".into()),
                    signature: None,
                    args: vec![],
                    message: None,
                    raw: ctx.returndata.clone(),
                    source: DecodeSource::Unknown,
                })
            }
        }
        struct NeverHit;
        #[async_trait::async_trait]
        impl RevertDecoder for NeverHit {
            fn name(&self) -> &'static str {
                "never"
            }
            async fn try_decode(&self, _ctx: &DecodeContext) -> Option<DecodedRevert> {
                panic!("must not be reached");
            }
        }
        let chain = DecoderChain::new()
            .with(crate::boxed(AlwaysHit))
            .with(crate::boxed(NeverHit));
        let out = chain.decode(&ctx(vec![1, 2, 3, 4])).await;
        assert_eq!(out.name.as_deref(), Some("HIT"));
    }
}
