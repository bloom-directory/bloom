# System Petals TODO

Date: 2026-05-26

Goal: make Bloom services like oracles, events, keepers, simulation helpers,
math libraries, type registries, escrow helpers, and risk engines extensible as
upgradable petals instead of hardcoding them into the protocol.

The protocol should stay small. It should enshrine objects, ownership, PTB
execution, petal loading, deterministic host imports, capability enforcement,
and the registry/governance machinery needed for system petals. Everything else
should be implemented as governed petals with explicit capabilities.

## Target Shape

```text
Bloom kernel
  deterministic object VM
  PTB atomicity
  minimal host imports
  capability enforcement
  path/interface registry

System petals
  /bloom/std/oracle
  /bloom/std/events
  /bloom/std/keeper
  /bloom/std/simulation
  /bloom/std/math
  /bloom/std/type-registry
  /bloom/std/object-escrow
  /bloom/std/risk

Application petals
  lending markets
  DEXs
  vaults
  games
  governance apps
```

System petals may be privileged, but privileges must come from explicit
capability objects and governed bindings, not from special cases compiled into
the node.

## Implementation TODOs

1. Cross-petal calls.

   Add deterministic synchronous `petal.call` support so petals can call stable
   service interfaces without inlining logic. Calls must share the PTB borrow
   table, meter fuel across the full call tree, propagate reverts, and resolve
   callees by either hash or governed path.

2. Stable interfaces.

   Separate interface identity from implementation identity:

   ```text
   InterfaceId = hash(canonical ABI)
   Implementation = petal hash
   Binding = path/interface -> implementation hash
   ```

   App petals should depend on interface IDs such as `OracleV1` or
   `EventSinkV1`, not on whatever hash currently backs a path.

3. Governed path registry.

   Represent important system bindings as objects:

   ```text
   PathBinding {
     path,
     interface_id,
     implementation_hash,
     version,
     admin_cap_or_governance_owner,
     activation_epoch,
     previous_hash,
   }
   ```

   Upgrades should support delay, auditability, rollback metadata, and eventual
   veto/governance flows.

4. Capability objects for system privileges.

   Model privileges as resources:

   ```text
   OraclePublishCap
   PathUpgradeCap
   EventIndexCap
   KeeperRewardCap
   TypeRegistryWriteCap
   EscrowAdminCap
   ```

   A system petal only performs privileged work when it holds or is passed the
   corresponding capability.

5. Service state objects.

   System petals should store state in ordinary durable objects, for example:

   ```text
   OracleRegistry
   PriceFeed<T, Quote>
   EventStream
   KeeperRegistry
   TypeRegistry
   MathConfig
   RiskConfig
   SimulationProfile
   ```

   Code is upgradable; state persists.

6. Schema and migration framework.

   Add support for schema hashes, schema versions, migration entrypoints,
   upgrade prechecks, and upgrade postchecks. Upgrades should declare which
   previous object schemas they can read or migrate.

7. Deterministic chain context imports.

   Expose deterministic execution facts, not business logic:

   ```text
   chain.height()
   chain.timestamp_ms()
   chain.epoch()
   chain.id()
   tx.digest()
   tx.signers()
   ```

   System petals can build oracle freshness, keeper scheduling, interest
   accrual, and governance delays on top of these.

8. End-of-PTB invariant hooks.

   Support generic tx-end checks registered by object-defining petals:

   ```text
   register_tx_end_check(object_id, petal_hash_or_interface, function)
   ```

   If any registered check fails, the whole PTB reverts. Lending petals can use
   this for final health-factor checks, flash-loan repayment, reserve
   reconciliation, and similar invariants without protocol-level lending logic.

9. Event and indexing standard.

   Keep `log.emit` minimal, but build a system event petal for typed event
   schemas, topics, indexed object IDs, indexed owners, and canonical payloads.

10. Simulation as a first-class execution mode.

   Protocol should support dry-run execution over a snapshot. A simulation
   service can format and expose:

   ```text
   simulate(ptb) -> {
     success,
     object_diffs,
     command_outputs,
     events,
     fuel_used,
     touched_objects,
     invariant_failures
   }
   ```

11. Keeper and automation service.

   Build a generic system petal for registered watch specs, trigger predicates,
   reward checks, and keeper execution. It should support liquidation/oracle
   use cases without being lending-specific.

12. Object escrow ergonomics.

   Add standard-library petals and/or host helpers around object-owned custody:

   ```text
   transfer_to_object(coin, object_id)
   assert_owned_by(object, owner_object)
   withdraw_from_object_owner(...)
   ```

   This should help reserves, vaults, and other apps custody assets without
   custom unsafe conventions.

## Initial Priority

1. Cross-petal calls.
2. Interface IDs and ABI compatibility checks.
3. Governed path bindings with delayed upgrades.
4. Capability objects for privileged services.
5. Deterministic chain context imports.
6. Schema and migration framework.
7. Tx-end invariant hooks.
8. Simulation/diff mode.
9. Event schema/indexing service.
10. Keeper service.

## Non-Goals

- Do not enshrine lending interest models.
- Do not enshrine liquidation logic.
- Do not enshrine collateral factors or reserve configs.
- Do not make protocol-owned price feeds mandatory.
- Do not make aTokens/debtTokens core protocol types.

Those should be petals or standard-library examples built on the system-petal
framework.
