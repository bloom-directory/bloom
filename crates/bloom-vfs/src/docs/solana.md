# Native Solana transfers

Use this guide for native SOL transfers through a wallet outbox. Paths are
relative to the Bloom mount root unless shown with `/bloom`.

## Choose the signing account

Read `wallets/<wallet>/accounts.json` and select an account whose `lifecycle` is
active and whose `derivation_profile` is the Solana profile. Record its `path`
and `public_key_fingerprint`, plus the base58 `address` from its Solana
`chain_projections` entry. Do not assume the first account belongs to Solana.

If the wallet has more than one active Solana account, include the selected
account's full fingerprint as `account_fingerprint` when staging. With exactly
one active Solana account, omit it. Bloom refuses to guess when that choice is
ambiguous.

The transfer outbox is:

```
wallets/<wallet>/chains/<solana-chain>/outbox/
```

## Write action routes directly

Bloom action leaves are virtual routes, not ordinary files. Editor write tools
often rename a temporary sibling into place, which targets a nonexistent route.
Shell redirection can also report success before a late NFS write error reaches
the process. For consequential route writes, open the exact path unbuffered,
flush it, and close it:

```sh
python3 -c 'import os,sys; f=open(sys.argv[1], "wb", buffering=0); f.write(sys.argv[2].encode()); os.fsync(f.fileno()); f.close()' EXACT_PATH EXACT_PAYLOAD
```

A zero exit status means Bloom accepted the action for dispatch. It does not
mean the chain action completed; always read the resulting artifacts.

## Stage and review

Write one JSON object to `outbox/new.tx`:

```json
{"destination":"<base58-address>","lamports":1000000}
```

`lamports` is an integer in base units, not a string or SOL-denominated decimal.
The only optional field is `account_fingerprint`, as described above. Do not add
unknown fields.

The blockhash validity clock starts when staging succeeds. Finish account and
payload discovery before writing `new.tx`. From that write onward, stay on the
single entry's critical path: discover its id, review `intent.json` and
`plan.md`, then confirm. Do not inspect capabilities, approval indexes, general
documentation, balances, or unrelated wallet surfaces between those steps.

List `outbox/pending/` once to discover the allocated id. Before confirming,
read that entry's `intent.json` and `plan.md`; verify the source account, fee
payer, destination, lamports, fee, network, and recent blockhash against the
request.

## Confirm through Sealed Approval

Write `y` directly to
`outbox/pending/<id>/confirm`. If fresh owner approval is required, this first
write fails with permission denied after Bloom creates
`approval_challenge.json`. This is the expected fail-closed boundary.

Read the challenge and verify its action id, wallet, chain, destination, amount,
and expiry. Give its ceremony URL to the owner; an agent must not complete the
owner ceremony or handle owner credentials. After the owner approves, retry the
same path with byte-identical confirmation bytes. After validating the challenge,
start a bounded serial retry loop immediately; do not pause to inspect approval
or capability state. Repeated permission errors before approval are expected,
but do not suppress their stderr because a different error must stop the loop.
Do not restage or create a second transfer while waiting. A Solana blockhash
expires quickly, so cancel a stale pending entry rather than trying to force it
through.

## Prove completion

After confirmation succeeds, the entry moves to `outbox/sent/<id>/`. Read
`broadcast_attempted.json`, then poll `receipt.json`. Completion requires
`outcome: "success"` and `confirmation_status: "finalized"`; record its
signature and slot. Finally, verify the original id is absent from `pending/`.

If the workflow cannot safely continue, write `cancel` to the pending entry and
report the failure. Never infer finality from a successful route write and never
stage a compensating transfer unless the owner explicitly authorizes one. If the
entry has already moved to `failed/`, it is terminal: do not investigate recovery
or restage it; report failure and stop.
