# Outbox

Write a body to `send.tx` to stage it and ask the owner, or to `new.tx` only to
stage it; the body forms are in `/AGENTS.md`. `latest/` is that entry:
`latest/plan.md` is what will be signed, and `y` written to `latest/confirm`
waits for the approval, sends, and leaves `latest/receipt.json`. Entries already staged go together by
writing their `chain:id` references, in order, to `../../../confirm-batch`;
reading that file gives the link, then the hashes.
`pending/`, `sent/` and `failed/` hold every entry by id.
