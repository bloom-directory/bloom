# What the owner sees when approving

Machine exposes this VFS, Broker runs approval ceremonies and policy, and
Signer holds the keys. The approval page shows Broker's own reading of the
signed bytes: action, account, amounts, recipient and limits.

Give the human the complete ceremony URL, including any `#` fragment, with
host and port unchanged. Launch URLs are owner capabilities: keep them out of
logs and Petal-visible data. Name an unknown token only by its address and
raw units, never a guessed ticker. Point out **No output protection**,
**Spending limit: Unlimited**, or **Contract call Bloom cannot read** if
shown.

An approval proves what was signed, not that an order filled or funds
arrived; report outcomes from receipts and the Petal's status files.
