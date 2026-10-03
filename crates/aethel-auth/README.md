# aethel-auth

Delegated authority for post-quantum identities.

`aethel-core` proves *who*. This crate expresses **what an entity may do, within what bounds, until when, and unless revoked**.

> **Status: built, unpublished.** Login proof, sessions (including persistence for a real store via `Session::into_stored`), step-up, delegation, succession and revocation, and enrolment, with builders behind `holder`. Not yet on crates.io.

## What a service hosts, and what an agent holds

This repository is `aethel-runtime`, and it holds two crates that are the two halves of acting on someone's behalf.

| | `aethel-vault` (repository root) | `aethel-auth` (this crate) |
|---|---|---|
| Holds the authority to | **spend** | — |
| Verifies the authority to | — | **act** |
| Runs where | the agent, always | the relying party |
| Hosted? | **Never.** `hosted` is a hard compile error | Hosted by definition |
| Holds secrets? | Yes, and they never leave | No, not in the default build |

They are separate crates for one reason: the vault advertises never being hosted, and a verifier is hosted by definition. Merging them would void that claim. They are still meant to compose — a delegation issued here is the generalisation of the vault's `SpendPolicy` beyond money.

## Verifier-first

The default build verifies and holds no secret of any kind. It depends on `aethel-core` alone: no WASM runtime, no wallet, no ECDSA.

```toml
[features]
default = ["std", "verify"]
verify  = []   # check statements. Public material only
holder  = []   # produce statements. Pulls the SDK, which embeds wasmtime
```

A server should not link a WASM engine to check a signature, so `holder` is opt-in. `default_build_stays_verifier_only` fails the build if a holder-side or wallet dependency ever appears in `[dependencies]`, the same way the vault's `manifest_contains_no_ecdsa_crates` guards its own claim.

Plain `rlib`, deliberately. A server-side verifier has no use for a `cdylib`, and a `cdylib` is what stopped `erand-nats` publishing on Linux.

## Purpose bytes

This crate registers its purposes in `aethel-core`'s central registry rather than defining its own, the way `aethel-vault` does. The convention is `<crate>/<thing>/v<n>`, passed as a FIPS 204 context. See `aethel-core/docs/PURPOSES.md`.

## Two constraints this crate is built under

**No correlating identifier may travel between verifiers.** A per-verifier handle is permitted and is how a service recognises a returning entity. Anything correlatable *across* verifiers is not, and no cost saving buys it back. Within one verifier, recognition is opt-in and documented to the consumer.

**A session is a deviation, not a default.** The architecture's position is a one-time context-bound nullifier per interaction, and per-request verification was measured as viable. A session exists here for exactly one reason: a browser has no signer, so a human at a page cannot sign each request. It is scoped to that case, and it ends when a browser signer exists.
