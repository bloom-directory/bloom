# Enso settlement follow-up preserved from PM80

The clear-signing candidate removes the destination tracker and reports
source-chain status plus explicit `destination_unverified` after source success.
It retains safe source calldata, same-chain receipt accounting, selected-account
binding and the durable original reviewed floor. It does not poll an unsupported
tracker or offer a misleading retry action.

Preserved Enso code: commit `53b0b7328df9f060c3e65f0283954edd9709fb83`, branch
`pm80-settlement-preservation-20261020` in `bloom-directory/bloom-petal-enso`.
Prepared Machine support: commit `905fef29b8557db2ba135c5143119aa3180df75a`,
branch `enso-destination-receipt-reads` in `bloom-directory/bloom`.
Coordinate with the existing receipt-read owner / Bloom #318 before implementing
host changes; do not maintain competing host adapters.

These findings remain open for any future package that re-enables the tracker:

| Requirement | Acceptance evidence |
| --- | --- |
| I2 bounded host reads | Reconcile the preserved host methods; run the actual compiled Enso component through DaemonPetalHost. Cover pending/null, denied methods, invalid hashes, RPC errors, oversized results and noncanonical block reads. No arbitrary RPC forwarding. |
| I5 provider outcomes | Distinguish valid pending, no observation/not found, rate limit, transport failure, malformed response, refund in progress, refund reported and manual execution. No valid observation means unavailable/unverified, not ordinary pending. Preserve bounded errors in cached status without credentials/raw unbounded bodies. |
| Conflicting providers | Keep per-provider evidence; aggregation is independent of provider order. Test permutations. Conflicting valid observations remain explicitly conflict/unverified, never arbitrarily completion or refund. |
| I7 original floor | Consume the schema-2 persisted effective `Session.route_request.min_amount_out` from the signing candidate. Quote 1000 / 50 bps retains 995 through refresh/restart; destination receipt 992 fails. Old sessions lacking the original reviewed baseline need new review or explicit unverified minimum. Do not invent a baseline from the latest quote. |
| Receipt meaning | Bind network/source hash and delivery/execution linkage; require contiguous multi-hop matching, removed-log exclusion and net inflow. Direct native receipts need matching transaction/EOA evidence. Internal native transfers stay unverified without traces. Provider linkage is asserted and a receipt is not finality. |

Use representative bounded captured provider responses and adapter tests.
Any claim of live settlement requires a separately authorized real-service /
venue test. Do not add automatic refund execution, retry signed transactions
as fresh ones, move funds, or treat this handoff as that authorization.

The preserved code is a recovery point, not a reviewed merge candidate. Rebase
or integrate only under the workspace pin/ownership rules and against the
landed signing/session schema. See
[verification and remaining gates](pm80-clear-signing-verification-2026-10-20.md).
