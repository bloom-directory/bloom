# Icon artwork

Compiled into the handler and served as sibling files under `views/icons/`,
so every mark renders offline, the pages contact no CDN, and an image that
appears many times on a page is transferred once instead of being duplicated
into the HTML. See `handlers/views.rs` (`token_icon`, `chain_icon`,
`asset_mark`, `ICON_FILES`) for the mapping rules.

## Provenance

- Captured locally during the PR #118 views research and copied from the
  `pr118-live` preview directory. The upstream URL and license of each mark
  were not recorded at capture time, so treat this set as unverified artwork
  for personal, local display only — not as redistributable assets.
- `chain-*.webp` are network marks; `token-*.png|jpg` are asset marks.
- The Avalanche, Blast, Gnosis, Linea, Optimism, Polygon, and Scroll JPGs were
  fetched on 2026-09-13 from DefiLlama's public chain-icon endpoint
  (`https://icons.llamao.fi/icons/chains/rsz_<name>.jpg`). They remain local
  display assets; the dashboard never contacts that endpoint.
- Every file here must be referenced by the mapping in `views.rs`; unused
  copies are removed so the set stays auditable.

## Rules the mapping keeps

- Match on the canonical identity where one exists: chain id for networks,
  symbol for traded assets. A display name is only a fallback.
- Unknown names keep an initials fallback. A familiar logo is never
  substituted for an unrelated asset: a development chain that calls its
  faucet unit "ETH" is not ether and keeps initials.
