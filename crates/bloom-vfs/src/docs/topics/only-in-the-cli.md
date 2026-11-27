# Operations with no file route

These are done with `bloom <command>` at a terminal. No file does them, on
purpose: each removes something, rebinds who controls a wallet, or changes
what code this machine runs.

- `bloom wallet delete`, `bloom wallet account-retire`
- `bloom wallet rebind-passkey`, `bloom wallet migrate-passkey`
- `bloom petals install`, `uninstall`, `build`
- `bloom audit reconcile`
- `bloom deploy` from a Foundry or Hardhat project. Bytecode you already
  have deploys through the outbox: `{"kind":"deploy","data":"0x..."}`.

Run one only when the owner asks for it by name.

A ceremony is followed and cancelled through its own files, not by operation
id: `status.json` and `cancel` beside a wallet registration, a passkey
enrollment or a policy update.
