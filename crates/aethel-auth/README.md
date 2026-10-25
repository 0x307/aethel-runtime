# aethel-auth: delegated authority for agents

> **Tier:** Preview · **MSRV:** 1.87 · **License:** Apache-2.0 · Not independently audited, see [the crate family](#the-0x307-crate-family)

**Crate: `aethel-auth`. Repository: `aethel-runtime`.**

Delegated authority for post-quantum agent identities.

`aethel-core` proves *who*. This crate expresses **what an entity may do, within what bounds, until when, and unless revoked**.

> **Status: 0.1.0, not yet on crates.io.** Per-request login proof, bounded delegation, step-up approval, and succession and revocation statements, with builders behind `holder`. For agents, which sign every request. There are no sessions in this release. See `CHANGELOG.md`.

## What a service hosts, and what an agent holds

This repository is `aethel-runtime`, and it holds two crates that are the two halves of acting on someone's behalf.

| | `aethel-vault` (repository root) | `aethel-auth` (this crate) |
|---|---|---|
| Holds the authority to | **spend** | — |
| Verifies the authority to | — | **act** |
| Runs where | the agent, always | the relying party |
| Hosted? | **Never.** `hosted` is a hard compile error | Hosted by definition |
| Holds secrets? | Yes, and they never leave | No, not in the default build |

They are separate crates for one reason: the vault advertises never being hosted, and a verifier is hosted by definition. Merging them would void that claim. They are still meant to compose: a delegation issued here is the generalisation of the vault's `SpendPolicy` beyond money.

## Verifier-first

The default build verifies and holds no secret of any kind. Its runtime dependencies are `aethel-core`, `sha3`, `subtle` and, by default, `serde`: no WASM runtime, no wallet, no ECDSA. `ctutils` is also named, as a version floor only (see [Version policy](#version-policy)).

```toml
[features]
default = ["std", "verify", "serde"]
verify  = []   # check statements. Public material only
serde   = []   # move statements as JSON; the signature covers canonical bytes either way
legacy-number-arrays = ["serde"]   # also read bytes as JSON number arrays. Off: one spelling per value
holder  = []   # produce statements. Adds no dependency; it is a guardrail
```

A server should never reach for a builder, so `holder` is opt-in and doing so is a compile error rather than a code review. `default_build_stays_verifier_only` fails the build if a holder-side or wallet dependency ever appears in `[dependencies]`, the same way the vault's `manifest_contains_no_ecdsa_crates` guards its own claim.

Plain `rlib`, deliberately. A server-side verifier has no use for a `cdylib`, and a `cdylib` is what stopped `erand-nats` publishing on Linux.

## Purpose bytes

This crate registers its purposes in `aethel-core`'s central registry rather than defining its own, the way `aethel-vault` does. The convention is `<crate>/<thing>/v<n>`, passed as a FIPS 204 context. See `aethel-core/docs/PURPOSES.md`.

## Two constraints this crate is built under

**No correlating identifier may travel between verifiers.** A per-verifier handle is permitted and is how a service recognises a returning entity. Anything correlatable *across* verifiers is not, and no cost saving buys it back. Within one verifier, recognition is opt-in and documented to the consumer.

**Every request proves itself.** The architecture's position is a one-time context-bound proof per interaction, and per-request verification was measured as viable. An agent signs a fresh login proof for each request and presents its delegation beside it.

## What the relying party still enforces

`authorise` checks that a delegation is genuine, live, for this relying party, issued to the key that just proved itself, and that the action and amount fall inside its declared bounds. It returns `RemainingObligations` for what only the relying party can check:

- **The running total.** Keep a total per delegation over `window_secs` and refuse once a request would exceed `max_total`.
- **Human approval.** Above `approval_required_above`, hold the request until the **principal** signs a step-up for that action. Verify it with `verify_step_up`, then `check_approval`, which refuses a step-up from the agent itself.
- **Revocation.** Keep the revocations you have verified, and refuse a delegation whose principal or delegate key is revoked. A principal ends its delegates' authority by revoking its own key at that relying party. `Delegation::id` gives you a stable key for the running total and for this.

A caller that ignores the return value has left a cap unchecked. That is why it is returned rather than checked silently.

## Wire format: one spelling per value

With `serde`, byte fields are base64url text, and decoding is strict. Only the canonical form is accepted: no padding, and no set bits after the last byte. A relying party stores and compares keys, and signatures cover the decoded bytes. A decoder that accepted several spellings of one key would let a revoked key come back under another spelling. The older JSON number-array shape is behind `legacy-number-arrays`, off by default.

## Version policy

- **We never yank.** A security defect is fixed forward in a new release and reported as a RustSec advisory, so `cargo audit` and `cargo deny` flag the affected versions.
- **More than one line may be live.** A line is a `0.x` minor series, such as `0.1`.
- **A legacy line gets 6 months of security patches**, starting the day its successor line ships.
- **After the window, the line is unsupported.** It gets no more fixes. Every version stays downloadable.

**Security exception for the MSRV.** A security fix may raise the MSRV in a patch release, when the fixed dependency needs a newer Rust and no fixed version builds on the old one. The changelog entry names the advisory and says which Rust versions are dropped.

The MSRV is 1.87. `ctutils` below 0.4.4 has RUSTSEC-2026-0385, and `aethel-core` reaches it through `pqc-sig`'s ML-DSA on every build. Every fixed `ctutils` needs Rust 1.87, so this crate names a `ctutils >= 0.4.4` floor and declares 1.87.

The full policy is the family's [STABILITY.md](https://github.com/0x307/aethel-runtime/blob/main/STABILITY.md).

---

## The 0x307 crate family

`aethel-auth` is one of seven open-source crates from [0x307](https://0x307.com/crates), held to one
audit and stability standard.

| Crate | Tier | What it does |
|---|---|---|
| [pqc-sig](https://crates.io/crates/pqc-sig) | Production | ML-DSA, SLH-DSA and FN-DSA signatures (FIPS 204/205/206) |
| [pqc-kem](https://crates.io/crates/pqc-kem) | Production | ML-KEM (FIPS 203), the X25519 + ML-KEM-768 hybrid, X-Wing, and sealed boxes |
| [aethel-core](https://crates.io/crates/aethel-core) | Production | Post-quantum anonymous identity: a separate identifier per context, context-bound ML-DSA signing |
| [aethel-sdk](https://crates.io/crates/aethel-sdk) | Preview | The SDK over aethel-core, and the place to start |
| [aethel-vault](https://crates.io/crates/aethel-vault) | Preview | Agent-held wallet: policy-gated x402 / EIP-3009 signing with ML-DSA-65 spend records |
| [aethel-auth](https://crates.io/crates/aethel-auth) (this crate) | Preview | Delegated authority for agents: bounded, revocable delegation and per-request proofs a relying party verifies |
| [pqc-privacy](https://crates.io/crates/pqc-privacy) | Lab | Research bundle, kept off every identity and payment path |

**Production** crates are thin, standards-bound libraries meant to be depended on today. **Preview** crates work and are published, with APIs still settling. **Lab** crates are research, never on an identity or payment path.

**Runnable examples:** [0x307/examples](https://github.com/0x307/examples), one program per
crate, pinned to the published versions.

**Audit status:** None of these crates has been independently audited, and none holds a CMVP / FIPS 140-3 validation. "FIPS 203/204/205/206" means the algorithms follow those standards, not that the code is certified. Known issues for this crate are in
[SECURITY.md](https://github.com/0x307/aethel-runtime/blob/main/SECURITY.md). Version policy:
[STABILITY.md](https://github.com/0x307/aethel-runtime/blob/main/STABILITY.md).
