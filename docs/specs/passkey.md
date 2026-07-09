# Passkey wallets

Status: implemented — passkeys branch
Date: 2026-05-28

---

## What WebAuthn passkeys actually are

WebAuthn passkeys are a **public-key authentication mechanism**, not an
encryption mechanism. When you register a passkey:

1. The authenticator (Touch ID, Face ID, hardware security key, etc.) generates
   an asymmetric keypair internally.
2. The **public key** is returned to the relying party — stored in bloom's
   `passkey.json`.
3. The **private key never leaves the authenticator** — it is protected by
   the device's secure enclave or hardware security module.

During authentication, the authenticator signs a server-provided challenge.
The relying party verifies the signature. That is the extent of what the
authenticator can do for *authentication*: **sign challenges**.

---

## How bloom passkey wallets derive encryption keys (PRF extension)

Bloom uses the WebAuthn **PRF extension** (Pseudo-Random Function, defined in
the WebAuthn Level 3 spec on top of the CTAP2 `hmac-secret` extension) to
derive an encryption key from the authenticator's internal secret.

During each ceremony, the caller provides a `prf_salt`:

> Provide an application-controlled salt → receive a deterministic 32-byte
> secret derived from the authenticator's internal master secret. The
> authenticator never exports the master secret; the same salt always yields
> the same 32 bytes on the same authenticator.

The browser JS extracts the PRF output and sends it to the local ceremony
server. The Rust keystore then derives a wrap key:

```
prf_salt    — 32 random bytes, stored in prf.salt (public, not secret)
prf_output  — PRF(authenticator_secret, prf_salt)  ←  derived live, never stored
wrap_key    — blake3::derive_key("bloom passkey wrap key", prf_output)
encrypted.key ← ChaCha20Poly1305(private_key, wrap_key)
```

Without the physical authenticator you cannot reproduce `prf_output`, therefore
you cannot decrypt the private key. This is the intended security guarantee.

### Recovery

Since there is no plaintext `wrap.key` on disk, the wallet **cannot be
recovered without the original authenticator**. Immediately after creation, a
browser page opens at `localhost:18735` showing the recovery key (raw hex
private key) with a copy button; the page requires an explicit "I've saved
this" confirmation before closing. If the browser cannot be launched (headless
env, port conflict), a terminal prompt on stdout is shown as fallback.
Store the recovery key like a seed phrase — bloom will never show it again.

To recover: `bloom wallet import <name> 0x<recovery-key>`

---

## Current wallet directory layout

```
~/.bloom/wallets/<name>/
├── kind              — "passkey"
├── prf.salt          — 64 hex chars (32 bytes), NOT secret
├── encrypted.key     — JSON { nonce_hex, ciphertext_hex }
├── passkey.json      — WebAuthn credential (public key + counter)
├── policy.toml       — spend caps, routing policy
└── policy.toml.sig   — BLAKE3(policy.toml) signed by the wallet key
```

No `wrap.key`. PRF output is never written to disk.

---

## Policy signing review

Passkey wallets treat `policy.toml` as a signed authorization boundary. If the
file changes, Bloom refuses policy-gated actions until the owner runs:

```sh
bloom wallet sign-policy <wallet>
```

The command opens a local browser review page before the WebAuthn ceremony. The
review page is the user-facing source of truth; the native OS/browser passkey
sheet only confirms user presence for `bloom/localhost`.

For policy signing, the page must show the decision in plain language:

- **Ask me every time** maps to `agent_autonomy = "prompt_all"`.
- **Let Bloom use these rules** maps to `agent_autonomy = "under_policy"`.

The page may update the in-memory policy draft before signing, validates the
final TOML, writes it back to `policy.toml` if the user changed the approval
mode, then signs exactly that final text. Signing a policy does not move funds;
it changes which future actions Bloom may allow.

Main review copy should avoid internal labels such as `wallet_unlock`,
`canonical_subject`, `intent_hash`, or `kind`. Those values are audit/debug
details and belong behind an advanced details disclosure.

---

## PRF browser support

| Platform | PRF support |
|---|---|
| Chrome ≥ 116 | ✅ |
| Safari ≥ 18 | ✅ |
| Firefox | ⚠️ — no built-in passkey manager on Linux; does not support WebAuthn PRF |
| macOS Secure Enclave (Touch ID) | ✅ |
| Windows Hello | ✅ (Chrome 147+) |
| YubiKey 5 series | ✅ (via `hmac-secret`) |
| Old FIDO U2F keys | ❌ — bloom rejects with clear error |

---

## PRF support in webauthn-rs

webauthn-rs 0.5.5 does not implement the PRF extension natively. Bloom works
around this by:

1. Patching the WebAuthn challenge JSON to inject the PRF extension before
   serving it to the browser (same technique already used for `residentKey`).
2. Adding a `/prf-output` HTTP endpoint to the local ceremony server.
3. The browser JS extracts the PRF output from `getClientExtensionResults()`
   and POSTs it to `/prf-output` before submitting the credential.

This is identical to how Bitwarden implements PRF-based vault encryption with
WebAuthn passkeys.

---

## What is and is not protected

| Threat | Protected? |
|---|---|
| AI agent calling `bloom` daemon and signing without user | ✅ blocked by WebAuthn ceremony |
| Automated script calling `bloom` and signing without user | ✅ blocked |
| Attacker who reads `~/.bloom/` from disk | ✅ cannot decrypt without authenticator |
| Stolen laptop / disk image copy | ✅ cannot decrypt without authenticator |
| Compromised user account (attacker runs as your user) | ✅ cannot decrypt without physical authenticator |
| Malware active during unlock | ⚠️ could intercept PRF output at ceremony time |

The remaining attack vector is malware that hooks the local ceremony server
during an active unlock — it could intercept the PRF output as it is POSTed.
This requires active compromise at the moment of signing, which is a much
narrower attack surface than persistent disk access.

---

## Comparison to passphrase wallets

| Property | Passphrase wallet | Passkey wallet |
|---|---|---|
| Private key at rest | Encrypted: argon2id(passphrase, salt) | Encrypted: wrap_key = BLAKE3(PRF(authenticator, prf_salt)) |
| At-rest attacker needs | Crack the passphrase (argon2id, expensive) | Physical authenticator (impossible without device) |
| Daemon signing without user | Not blocked | Blocked by WebAuthn ceremony |
| AI agent can sign? | Yes, if passphrase is available to it | No — requires physical gesture |
| Recovery if authenticator lost | Passphrase in head is the key | Recovery key shown once at creation |
| Stolen disk exposure | Safe (passphrase in head only) | Safe (PRF output not on disk) |
