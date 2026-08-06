# Wallet Projection Refresh Lifecycle Design

## Goal

Keep wallet projection refresh out of `Daemon` construction, run the boot refresh only for the long-lived `bloom serve` lifecycle, and make `/next.md` explicitly request live projections while retaining validated stale-cache degraded operation.

## Design

`Daemon::from_home_inner` will only construct the projection reader and load its validated disk cache. It will not launch a Broker request. `Daemon::spawn_background_tasks`, already called by `bloom serve`, will launch the existing audited boot refresh without delaying startup. Refresh failure remains a warning and does not prevent the daemon from serving Broker-independent or cached projection routes.

The VFS root dynamic renderer will support asynchronous rendering. `/next.md` will use that facility to call `WalletProjectionReader::list_wallets` explicitly. That operation performs a live Broker refresh when possible and falls back to validated, visibly stale cached projections on transport unavailability. If neither live nor cached projections are available, `/next.md` renders its existing unavailable section.

No other VFS route gains a global Broker readiness requirement. In particular, constructing a daemon and listing `/` will not initiate projection refresh.

## Error Handling

The serve boot refresh stays best-effort and audited. `/next.md` treats a projection-reader error as unavailable and continues rendering a diagnostic document. Authority-bearing operations retain their existing fail-closed behavior.

## Verification

Tests will prove that the constructor has no refresh launch site, long-lived background startup launches one refresh, `/next.md` invokes the projection reader before rendering, and root VFS listing remains independent of Broker projection refresh.
