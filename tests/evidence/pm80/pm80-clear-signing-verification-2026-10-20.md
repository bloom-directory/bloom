# PM80 clear-signing implementation and verification

Implementation is published on isolated branches owned by `cs-plan-1020`.
Existing PR heads were not overwritten, and nothing was merged or released.
This record supplements, rather than rewrites, the October 19 plan and original review.

## Published candidates

| Component | Candidate commit | Branch |
| --- | --- | --- |
| Broker | `731defa43780d1b0ad06b0029f00c0b6b2fc48fa` | `finish-clear-signing-broker` |
| Machine | `44fb83470c7d981b81a67abd9ed01420bcd85e36` | `finish-clear-signing-machine` |
| Enso | `57bd2aa06878edec5b5311b5c5a8533fd9410aa4` | `finish-clear-signing-enso` |
| Polymarket | `c2902cdb514347abb51b4c10e259110903fe956a` | `finish-clear-signing-polymarket` |
| Hyperliquid | `17652ac832314a75b8b9b079cb5aacf74b498891` | `finish-clear-signing-hyperliquid` |
| Released Broker diagnostic fixture | `4885a77f7741f63aa04b131d091039716b14dffc` | `released-policy-fixture` |
| Standalone Signer Rustls fix | `c17f4bf42404548e07fddc749c740b0a8eb01119` | `preserve-rustls-security-fix`, [draft PR #73](https://github.com/bloom-directory/bloom-signer/pull/73) |

Repositories are under `https://github.com/bloom-directory/`, named respectively
`bloom-broker`, `bloom`, `bloom-petal-enso`, `bloom-petal-polymarket`,
and `bloom-petal-hyperliquid`. Checkouts are
`worktrees/cs-plan-1020/<repository>/<branch>`. Machine evidence-only commits
may follow its implementation checkpoint above without changing the tested runtime.

The diagnostic fixture is based on released Broker
`9f394aebbc9c04a6031de31a12385e5485f8ca9b`. Its production source, API source,
Cargo manifest and lockfile are unchanged from that release. Only tests create
disposable software-owner stores and check the released downgrade refusal.
The tested core compatibility/migration baseline keeps Signer
`bc88ad690757165ebf1978410ea5c7ec652215d3` and runtime
`ad0072512bb97fb4eb68d249ce785ea3ea4a49ab`.

Release compilation revealed that baseline Signer still locks Rustls 0.23.45,
while Broker/Machine retain 0.23.46. The standalone Signer patch changes only
the lockfile's version/checksum to 0.23.46. It does not alter service/API source
and is deliberately not added as a second unmerged parent of Machine. Keep
the released Signer baseline for upgrade tests; land the security patch first,
then update the release's landed pins in dependency order. This observation
does not establish that every advisory is exploitable through Signer's current
TLS configuration.

## Finding matrix

| Finding | Implementation/disposition | Executable evidence | Limit |
| --- | --- | --- | --- |
| I1 | Polymarket candidate splits `begin` CLOB authentication from `continue` deposit-wallet exact batches. Machine producer test uses the rebuilt components and selected account 1. | Polymarket 94 tests; installed producer test captures auth on r000042 and onboard on r000043; stored credentials cause no auth signature. | Production release-catalog activation remains pending landed inputs. No funded onboarding or CLOB API call. |
| I2 | Enso candidate removes unsupported destination RPC consumer; source success reports `destination_unverified`, without a tracker retry promise. | Enso 145 tests; installed package builds/checks; settlement tests exercise explicit unsupported status. | Host support and tracker implementation remain open in the separate follow-up. |
| I3 | Broker strictly round-trips released signed policies, blocks signing with legacy restrictions, and requires explicit owner removal through the authority diff. Existing durable downgrade floor advances to 3 before incompatible ceremony mutation. Machine preserves the compatibility field. | Released plain and legacy stores pass the upgrade script; real Broker–Signer software-owner ceremony covers inspection, pre-migration refusal, cancellation, interrupted completion/reconciliation, committed reopen, stale approval refusal and post-migration exact signing. W4 tests cover tampered policy and legacy verifier removal; custody tests retain reusable-grant checks. Released reader refuses upgraded floor and accepts the untouched backup. | Disposable test owner and actual service library/RPC boundaries, not a physical owner's live wallet or installed-service upgrade. |
| I4 | Broker integrates the prepared bounded Weiroll reader, retains runtime symbolism, and renders primary command/call/target/value/argument summaries. | Reader 81 tests; six pinned official Solidity encoding cases pass Forge; rendered fixture has visible summaries at 390px and 1280px with details closed/open and no overflow or JS errors. Existing Broker exact-binding tests pass. | No interpreter, execution simulation, funded route or destination settlement claim. Browser test supplies a preview transport fixture, not a human signature. |
| I5 | Defective provider/refund tracker is excluded from the Enso candidate and preserved remotely. | Same package/status tests as I2. | Provider failure/refund/conflict handling remains an explicit settlement follow-up requirement. |
| I6 | Broker catalog range no longer computes `chain_id + 1`. | Catalog boundary tests cover max-1/max, direct/standard/unknown selectors; real Broker preparation regression at maximum ID passes. | Normal unsupported cases remain ordinary errors/opaque review according to existing policy. |
| I7 | Enso schema-2 sessions normalize and persist one effective minimum before review; refresh retains the original request text and floor. Legacy sessions require new review when the baseline is unavailable. | Original 1000 at 50 bps stays 995 after repeated refresh/reload; 992 is rejected; explicit and calldata stronger minima and byte changes have regressions. | Cross-chain floor is a requested expectation. Its destination-receipt consumption remains with the excluded tracker. |
| I8 | Broker token generator separates capture from deterministic offline derivation, recording source documents/digests, identity, code and state at a checked block hash. | Captured pUSD fixture regenerates offline; decimals/source/chain/address mutations are rejected or visibly differ; CI runs offline comparison. | Provenance improvement, not proof of an observed wrong token row. Historical rows are not assigned invented block provenance. Known proxy slots are bounded observations. |
| I9 | Broker cancellation labels identify market ID with identity-unverified qualification, order/client ID and fast cancellation. | Actual compiled normal, fast and client-ID cancellations reach the host; all three captured witnesses reconstruct and label correctly in Broker’s 14 message-review tests. Missing/changed evidence is refused. Custody tests also pass. | No market registry or verified ticker identity. |
| I10 | Machine component/SDK/host test captures actual Hyperliquid delegated signing requests, selected account and complete witness; Broker reconstructs their preimages/hashes. | `real_signing_producers_reach_the_host_with_selected_account_and_full_witness`; Broker fixture test rejects missing/mutated witness. Existing custody test rejects bad evidence and permits two legitimate grant uses after reopen. | Coverage improvement, not a repaired observed production forwarding bug. VM host captures requests; no exchange effects. |
| I11 | Machine candidate uses final Broker 731defa consistently in production/API/lock/release/CI/default/fallback locations. | Committed pin scan and affected Machine checks. Original b10cc950→2b7033a difference confirmed as 27 test-only lines. Final 55fe84d→731defa also changes only cancellation test cases/fixtures; API and production behavior are unchanged. | Broker is not landed; final squash SHA repin remains mandatory. Schema-1 predecessor fixture intentionally keeps its historical pin. |
| S1 | Machine–Broker advances once from exact minor 1.7 to 1.8; frozen frames/ranges updated. | Real candidate processes start and read wallets; released Machine/new Broker and new Machine/released Broker both refuse broker.readiness with UNSUPPORTED_VERSION. Policies, grants, approvals, operations and ceremony sessions remain empty. Socket range/frozen-frame tests also pass. | Process binaries use explicit triad-dev-harness diagnostics. This is not installed production containment conformance. |
| S2 | Signer edge remains unchanged at 1.6; state/downgrade compatibility records reflect Broker floor 3. | Independent edge-range tests and real released-Signer boundary in upgrade/custody suites. | Full Linux release and both macOS conformance gates are still unmet. |

## Scope preservation

- Broker original `2b7033a39163513a39b387a83abbaca80fcd0268` is preserved on
  `pm80-artwork-preservation-20261020`. The candidate removes 644 generated
  PNGs and their acquisition/manifest/allowlist pipeline while keeping exact
  issuer SVGs, ETH, neutral pUSD, USDC and missing-art behavior. Negative
  identity/artwork tests remain.
- Enso original `53b0b7328df9f060c3e65f0283954edd9709fb83` is preserved on
  `pm80-settlement-preservation-20261020`. Machine receipt support
  `905fef29b8557db2ba135c5143119aa3180df75a` remains on its published
  `enso-destination-receipt-reads` branch. See the separate settlement handoff.
- Machine's copied Safe/Venice logs are replaced with immutable source links.
  Existing historical counts/revisions remain historical evidence.
- Broker/Machine retain Rustls 0.23.46; Signer #73 prepares the same lockfile
  update separately. The security refresh must not be reverted to 0.23.45:
  [RUSTSEC-2026-0346](https://rustsec.org/advisories/RUSTSEC-2026-0346.html),
  [0347](https://rustsec.org/advisories/RUSTSEC-2026-0347.html),
  [0348](https://rustsec.org/advisories/RUSTSEC-2026-0348.html) and
  [0349](https://rustsec.org/advisories/RUSTSEC-2026-0349.html) identify 0.23.46
  as patched. Applicability depends on the specific TLS paths/features.

## Reproduction and results

Set `B`, `M`, `E`, `P`, `H` to the owned candidate roots listed above and `R`
to `worktrees/cs-plan-1020/bloom-broker/released-policy-fixture`.

| Check | Command/result |
| --- | --- |
| Broker workspace | `(cd "$B" && cargo test --workspace --locked)` → 519 passed, 2 ignored. The two are privileged W0 and the separately invoked external-store upgrade test. Strict workspace Clippy and format pass. |
| Final reader change | `(cd "$B" && cargo test --locked -p bloom-evm-clear-signing)` → 81 passed. This follows the final text-only native-unit correction after the full workspace run. |
| Official encoder | `forge test --root "$B/crates/bloom-evm-clear-signing/tests/fixtures/weiroll"` → 6 passed. Pinned Solidity source is vendored in the fixture. |
| Released store | `BLOOM_RELEASED_BROKER_FIXTURE_ROOT="$R" bash "$B/scripts/test-released-policy-upgrade.sh"` → both store variants upgrade/sign; released rollback refusal and backup restore check pass. No live wallet database is opened. |
| Machine affected suites | `(cd "$M" && cargo test --locked -p bloom-machine-client -p bloom-daemon -p bloom-vfs -p bloom-tx -p bloom-proto -p bloom-solana-tx -p bloom-petals)` → 1065 passed, 2 explicit package-fixture ignores. Affected Clippy/format pass. This suite used Broker be9e9da; 55fe84d changes only a reader summary unit string and final 731defa adds test coverage. Final 731defa-pinned three-cancellation component test and Clippy are separate evidence. |
| Petal routes | `cargo test --manifest-path "$E/route/Cargo.toml" --locked` → 145; corresponding P → 94, H → 55; all pass. Relevant strict Clippy and format pass. |
| Component builds | Exact SDK/tool commit `2beed2ff344ce2b0c112e07096027e1ae0404007`: Enso 31, Polymarket 110, Hyperliquid 74 components build and `petal check` pass. Used direct pinned CLI build for Enso because its wrapper recursively force-deletes artifacts. No deletion approval was inferred. |
| Installed isolation | `BLOOM_HD_PACKAGE_ROOT=STAGED_ROOT BLOOM_HD_PACKAGE_NAMES=enso,polymarket,hyperliquid,near-intents cargo test --locked -p bloom-petals --test explicit_account_packages installed_packages_keep_explicit_account_routes_and_private_state -- --ignored --exact` → passes all four compiled packages. |
| Real producer | `BLOOM_PM80_POLYMARKET_ROOT=STAGED_ROOT/bloom-petal-polymarket BLOOM_PM80_HYPERLIQUID_ROOT=STAGED_ROOT/bloom-petal-hyperliquid cargo test --locked -p bloom-petals --test explicit_account_packages real_signing_producers_reach_the_host_with_selected_account_and_full_witness -- --ignored --exact` → passes against final Broker 731defa pin, including all three cancellation kinds. Optional `BLOOM_PM80_PRODUCER_WITNESS` and `BLOOM_PM80_PACKAGE_RECORDS` export the produced evidence. |
| Other default Petals | Installed NEAR v0.1.4 source/package matches its declared hash; 54 existing route tests pass including ERC-20 preparation. Installed Feedback v0.1.0 has five routes, no sign/outbox capability; source policy declares only HTTP/store. Neither component was changed. |
| Real local activation | Three Machine-composed archives build through a dedicated Machine Unix endpoint, then install/activate in that disposable home. This verifies local package activation, not production GitHub release-catalog provenance. The owned daemon was stopped by its PID. |
| Real mixed processes | `python3 scripts/test-mixed-release-processes.py` with its five explicit binary environment variables → three cases pass. Released Machine is v0.4.0 `caefe751baae789a82a0451ff3ee56971ddfe769`; released Broker is production-identical 9f394aeb. Process binaries use Machine 0d7215ec and Broker 55fe84d with unchanged released Signer; final candidate changes add only test coverage and an API-identical pin update. Binary hashes/results are retained. |
| Production compilation | Locked `cargo build --release` passes for Machine 44fb8347, Broker 731defa and baseline Signer bc88ad6, including signer-migrate. All four ELF x86-64 binaries pass `--version`; hashes/architecture are recorded in production-binaries.json. This is compilation, not signed-bundle verification or the future combination after Signer #73 lands. |
| Standalone Signer fix | Default and all-features workspace tests each pass 316 with one ignored origin test; that test separately passes under production and developer features with BLOOM_TRIAD_DEV_CEREMONY_PORT=28735. Strict all-features/all-targets Clippy and format pass. No live TLS exploitation or venue test is claimed. |
| Workspace doctor | Same pre-existing 4 errors and 30 warnings as baseline; no unrelated checkout/claim repair attempted. |

`STAGED_ROOT` for this run is `/tmp/pm80-packages-f0iy_e7s`. It holds clean
source snapshots plus exact pinned compiled components. Machine-composed
hashes, archive digests and generated authority route IDs are recorded in
Machine's `tests/evidence/pm80-package-candidates.json`. CLI-only package
hashes differ from composed packages and must not be copied into the release
catalog. No release tags or archive hashes were invented.

The process harness builds Machine with `--no-default-features --features
mount,triad-dev-harness` and Broker/Signer with `--features triad-dev-harness`.
Its adapter changes only the launcher's own repository path and retains its
two disposable template/runtime cleanup directories rather than deleting them.
Services still run through the normal isolated enrollment and user-unit paths.
It never copies the operator's Machine config. Fresh test chain configuration
uses loopback port 1 and contains no credentials. Each run stops only its own
recorded launcher/service handles. Final process evidence is
`/tmp/pm80-wire-61jznykr/results.json`; no installed custody instance is involved.

The committed pin helper correctly refuses the unlanded Broker candidate and
also reports its pre-existing whole-lockfile inconsistency diagnostics for the
deliberate schema-1 Broker/runtime predecessor fixture. The resolved production
`cargo tree --locked -p bloom -e normal,build` contains only Broker 731defa and
runtime ad007251, not the historical dd2add2b/5db670e1 fixture revisions. The
helper result is retained as blocked, not presented as a passed release gate.

Durable verification logs and browser fixtures are published with the Machine
candidate under `tests/evidence/pm80/`. Scratch-only stores, package archives
and the stopped Machine home remain under `/tmp/cs-plan-1020-*` and
`/tmp/pm80-packages-f0iy_e7s`; they are disposable, not future release inputs.

## Unmet landing and release gates

1. Existing PR writer claims remain with other owners. Explicit writer-stop /
   takeover assignment was requested; absent a reply, existing PR heads were
   preserved. Integrate through their owners or transfer explicitly.
2. Obtain independent review of the combined candidates. No review approval
   was manufactured or bypassed. Privileged W0 remains a conformance gate.
   Final GitHub refresh found all five original PR heads unchanged, OPEN and
   REVIEW_REQUIRED; their earlier reviews do not approve these new branches.
3. Specific user approval is required for each merge. Land standalone Signer
   #73 first, then Broker before Machine;
   repin to the actual landed squash commit, then land dependent Petals and
   generate immutable release packages/catalog entries. Do not treat these
   isolated candidate branches as an authorized integration stack.
4. The current production catalog still references its old releases. Do not
   release it with the new services: regenerate Polymarket authority IDs from
   the candidate record (begin auth r42, continuation onboard r43, later IDs
   r59/r68/r89/r107), retain proper predecessor declarations, and update all
   selected compatible package records atomically after their inputs land.
5. Run the exact clean Linux `packaging/triad/release.sh build linux` entry
   with explicit candidate Broker/Signer roots. Its bundle helpers execute
   `rm -rf` only on their fresh mktemp directories; explicit cleanup approval
   was requested because AGENTS.md requires it. This gate has not run.
6. Run both macOS conformance workflows with explicit final Broker/Signer
   refs. Two-login requires two real GUI login names/UIDs; these were
   requested. Runner inventory returned HTTP 403. No workflow is reported
   passed or even dispatched.
7. Complete one representative human review/approve/cancel demonstration when
   authorized. Automated software-owner and preview fixtures are labelled as
   such and do not claim that demonstration.

Custody port 18734 was untouched. No user credentials were read, no funds
moved, and no venue settlement claim is made.
