# Which wallet, account and chain

`wallets/<wallet>/<n>/holdings.json` lists an account's non-zero native and
major token balances on every configured chain, and names any chain it could
not read under `errors`. Any other token is at
`chains/<chain>/addresses/<address>/tokens/<token>/`. On Solana it shows SOL
only.

Infer what Bloom state settles; ask only for what it cannot:

- With one wallet or account, use it.
- A read that names no chain covers every chain: read `holdings.json`.
- For a write, use the only chain where `holdings.json` shows the asset, or
  the network the Petal's documentation names as its default. If two or
  more funded chains remain, drop testnets unless the user names one; if two
  or more still remain, ask one question that names them.
- If `holdings.json` has an `errors` entry for a chain that could hold the
  asset, say so rather than treating that chain as empty.

`wallets/<wallet>/accounts.json` lists the wallet's accounts; each entry's
`number` is its derivation index, and `wallets/<wallet>/<n>/` is that account.
Never select an account by list position or address alias. Stage through the
numbered path (`wallets/<wallet>/<n>/chains/<chain>/outbox/new.tx`, using `0`
explicitly for the first account); it fixes the sender to that account's key.
Keep every follow-up, including Petal routes and outbox confirmations, in the
same account.

Writing a petname to `wallets/new` requests asynchronous passkey registration;
it does not create a local wallet. Follow
`wallets/registrations/<petname>/status.json`. Details are in `wallets/creating-a-wallet.md`.
