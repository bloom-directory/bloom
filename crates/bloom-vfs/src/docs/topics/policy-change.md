# Changing a wallet's policy

Only propose a policy change when the owner explicitly asks for that change;
do not initiate one to make a refused transaction succeed.

To add a payee, write only the addition to `wallets/<wallet>/policy.json`; it
proposes the current policy plus it:

```json
{"add_destinations":[{"chain":"ethereum","destination":"0x..."}]}
```

Any other change is the complete new policy written there. Either write
starts a Broker ceremony (`policy.validate_update`). Show the human the link,
then write the exact same proposed bytes again (`policy.commit_update`).
Through `bloom vfs write` or MCP the error carries the link, and the repeat
waits for the approval and installs the policy. On a mount the link is in
`policy-updates/latest/status.json`; write again after they approve, then
read `policy-updates/confirmed/<action_id>/status.json`.

Reusable authority is under `wallets/<wallet>/sealed-approvals/`. A Petal can
use it but cannot create, broaden, renew or revoke it.
