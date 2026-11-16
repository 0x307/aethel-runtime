# aethel-auth: delegated authority for agents

> **Tier:** Preview · **MSRV:** 1.87 · **License:** Apache-2.0 · Not independently audited, see [the crate family](#the-0x307-crate-family)

**Crate: `aethel-auth`. Repository: `aethel-runtime`.**

Delegated authority for post-quantum agent identities.

`aethel-core` proves *who*. This crate expresses **what an entity may do, within what bounds, until when, and unless revoked**.

> **Status: 0.4.0.** Per-request login proof (optionally bound to one request), bounded delegation with optional named approvers, an approval of one request, step-up, and succession and revocation statements (of a key, or of one delegation), a canonical binary encoding, and a verify-once delegation handle, with builders behind `holder`. For agents, which sign every request. There are no sessions in this release. 0.4.0 is a breaking release: see the migration notes in `CHANGELOG.md`.

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
default = ["std", "serde"]
std     = []   # required in this release, see below
serde   = []   # move statements as JSON; the signature covers canonical bytes either way
legacy-number-arrays = ["serde"]   # also read bytes as JSON number arrays. Off: one spelling per value
holder  = []   # produce statements. Adds no dependency; it is a guardrail
verify  = []   # enables nothing; kept so manifests that name it still resolve
```

Verification is always built. It needs only public material and no extra dependency, so there is nothing to gate behind a feature.

**`std` is required in this release.** A build without it stops with a `compile_error!` that says so. The crate's own code is close to `no_std`, but `aethel-core` 0.7 also builds as a `cdylib`, which cannot link without std. Real `no_std` support waits on that, and adding it later is additive.

A server should never reach for a builder, so `holder` is opt-in and doing so is a compile error rather than a code review. `default_build_stays_verifier_only` fails the build if a holder-side or wallet dependency ever appears in `[dependencies]`, the same way the vault's `manifest_contains_no_ecdsa_crates` guards its own claim.

Plain `rlib`, deliberately. A server-side verifier has no use for a `cdylib`, and a `cdylib` is what stopped `erand-nats` publishing on Linux.

## Purpose bytes

Every statement type has its own purpose, `aethel-auth/<thing>/v<n>`, passed to ML-DSA as its FIPS 204 context, so a signature for one statement type never verifies as another. This crate owns the `aethel-auth/` prefix. The first five purposes (login, step-up, delegation, revocation, succession) were registered in `aethel-core`'s registry and are re-exported from it unchanged; newer ones are defined here in `purposes`: `aethel-auth/approval/v1`, `aethel-auth/delegation-revocation/v1` and `aethel-auth/delegation/v2` (a delegation that names approvers), so a new statement type does not need an `aethel-core` release. A test checks that this crate's purposes are distinct, stay under its prefix, and repeat nothing in `aethel-core`'s registry.

## Two constraints this crate is built under

**No correlating identifier may travel between verifiers.** A per-verifier handle is permitted and is how a service recognises a returning entity. Anything correlatable *across* verifiers is not, and no cost saving buys it back. Within one verifier, recognition is opt-in and documented to the consumer.

**Every request proves itself.** The architecture's position is a one-time context-bound proof per interaction, and per-request verification was measured as viable. An agent signs a fresh login proof for each request and presents its delegation beside it.

## What the relying party still enforces

`authorise` checks that a delegation is genuine, live, for this relying party, from a principal the relying party recognises, with neither key nor the delegation itself revoked, issued to the key that just proved itself, and that the action and amount fall inside its declared bounds. The relying party brings two things it alone knows:

- **Which principals it recognises.** A delegation is signed by its own principal, so anyone can make one. Pass the principal keys you have enrolled (or the one account the request is for). Any other principal is refused.
- **What it has seen revoked.** Keep the revocations you have verified and pass them as `RevokedKeys`: a slice or set of keys, or a closure over your own store. A delegation whose principal or delegate key is revoked is refused. A principal ends all its delegates' authority by revoking its own key at that relying party, or ends one delegation with a [`DelegationRevocation`](#revoking-one-delegation) and the set of revoked delegation ids, passed as `RevokedDelegations` directly after `revoked` (`&[] as &[[u8; 32]]` when you hold none). Compare keys as bytes, never as text.

An amount is required under a delegation that sets any amount bound. `None` there is refused, because a caller that failed to read the amount and one with nothing to count look the same. An action with no quantity under a bounded delegation passes `Some(0)`.

`authorise` returns `RemainingObligations` for what only the relying party can do:

- **The running total.** Keep a total per delegation over `window_secs` and refuse once a request would exceed `max_total`. `Delegation::id` gives you a stable key for it. It is one id per distinct signed statement. Signing is deterministic, so a principal that signs identical terms twice gets the same id and one shared total; to give a separate budget, change a term such as `not_before`.
- **Human approval.** Above `approval_required_above`, hold the request until the **principal, or an approver the principal named in the delegation** (see [Named approvers](#named-approvers)), approves it. The approval is its own signed statement, an `Approval` under `aethel-auth/approval/v1`, never a step-up. It names, in the clear, the audience, the delegation (`Delegation::id`), your digest of the request, the action and the exact amount, so the principal's software can show each one before signing (`Holder::approve`). `check_approval` checks the delegation again as it stands *now* (signature, window, principal, both revoked sets), then that the approval is signed by the principal or a named approver (any other signer is `NotAuthorised`, and a signer in your revoked keys is `Revoked`), names exactly the request, action and amount you are about to perform, and has an unspent nonce. The signer is `Approval::approver_key`, named `principal_key` in 0.3. `approval_required_above: None` means no request needs approval; it applies to each request on its own, so set `max_total` to bound the sum.
- **Succession.** After a verified succession, put `retired_key(&succession, audience)` in your revoked set, or the old key still approves under its delegations.

`RemainingObligations` is `#[must_use]`: a caller that ignores it has left a cap unchecked. `is_clear()` is true only when there is no running total and no approval left to the caller.

## Revoking one delegation

A key `Revocation` ends every delegation its principal ever signed at a relying party. To end one, the principal signs a `DelegationRevocation`: the audience, the delegation's id (`Delegation::id`) and `issued_at`, under `aethel-auth/delegation-revocation/v1`. Its signed bytes can never be read as a key `Revocation`, or the reverse.

```rust
// The principal's side (needs the `holder` feature). Panics if `principal` is not
// the delegation's principal: only the principal can revoke a delegation.
let rev = Holder::new(&principal, audience).revoke_delegation(&delegation, now);

// The relying party's side. Keep the id once the revocation verifies.
verify_delegation_revocation(&rev, &delegation, audience)?;
revoked_ids.push(delegation.id()); // revoked_ids: Vec<[u8; 32]>, revoked_keys: Vec<Vec<u8>>

// From now on, pass the set to authorise and check_approval.
let refused = authorise(
    &delegation, audience, &principals, &revoked_keys, &revoked_ids,
    &delegate_key, b"transfer", Some(5), now,
); // Err(AuthError::Revoked)
```

`verify_delegation_revocation` checks, in this order: no field is empty; the revocation's audience, the audience you expect and the delegation's all agree (`AudienceMismatch`); the revocation names this delegation and is signed by its principal (`NotAuthorised`, which is what a delegate, an authority or a named approver gets); the signature (`BadSignature`). There is no time cutoff, and the delegation need not still be live: once you accept a revocation it holds from then on. `RevokedDelegations` is implemented for a slice or `Vec` of ids, `HashSet<[u8; 32]>`, `BTreeSet<[u8; 32]>` and any `Fn(&[u8; 32]) -> bool`, so a closure over your own store works.

## Verify once, re-check cheaply

`authorise` verifies the delegation's signature on every call. A relying party that sees the same delegation on many requests keeps a `VerifiedDelegation` instead:

```rust
// Once: everything authorise checks except the per-attempt parts.
let verified = VerifiedDelegation::verify(
    &delegation, audience, &principals, &revoked_keys, &revoked_ids, now,
)?;

// Per request: no signature check. Audience, window and both revoked sets are
// checked again against what you pass now.
verified.recheck(audience, &revoked_keys, &revoked_ids, now)?;
let obligations = verified.authorise(
    audience, &revoked_keys, &revoked_ids, &delegate_key, b"transfer", Some(5), now,
)?;
```

The free `authorise` is `VerifiedDelegation::verify` followed by the handle's `authorise`, with the same errors. The handle holds no signature, has no public fields, no constructor but `verify`, and no serde or `Default`. It is a record that *this process* verified a delegation, not a credential: do not persist it or send it anywhere, and drop it if your set of enrolled principals changes, because it does not remember that set. Send the `Delegation` and let the receiver verify it.

## Named approvers

By default only the principal can sign an `Approval` under a delegation. A principal can name others in `Bounds::approvers`, for example a finance team's key, so a person other than the principal can approve a large request. An approver can approve and nothing else: nothing but `check_approval` reads the list, so an approver cannot sign a delegation or a `DelegationRevocation` for the principal.

```rust
let delegation = Holder::new(&principal, audience).delegate_to_with_approvers(
    delegate_key,
    bounds,
    vec![approver_key], // ML-DSA-65 public keys
    not_before,
    expires_at,
);

// The approver signs with Holder::approve, as the principal would.
let approval = Holder::new(&approver, audience)
    .approve(&delegation, &digest, b"transfer", 500, nonce, now, 300);

check_approval(
    &delegation, &approval, params, &principals, &revoked_keys, &revoked_ids,
    &digest, b"transfer", 500, &nonces,
).await?;
```

- **Content picks the version.** An empty list is a version 1 delegation: byte for byte what 0.3 signs, under `aethel-auth/delegation/v1`, with the same id. A non-empty list is version 2: the version 1 bytes, then a `u32` big-endian count and each approver length-prefixed, under `aethel-auth/delegation/v2`, with its own id label. So adding or removing an approver needs a new signature: the old one is `BadSignature`.
- **Limits**, checked by `verify_delegation` before the signature, each `Malformed`: at most 8 approvers (`MAX_APPROVERS`), none empty, no duplicates, none equal to the principal's or the delegate's key.
- **Who `check_approval` accepts.** The principal or a named approver. Any other signer is `NotAuthorised`. An approver in your revoked keys is `Revoked`.
- The signer of an `Approval` is `approver_key`, named `principal_key` in 0.3. 0.3 JSON that says `principal_key` still decodes.

## Binary encoding

`Delegation`, `LoginProof`, `Approval` and `DelegationRevocation` each have `to_bytes()` and `from_bytes(&[u8]) -> Result<Self, AuthError>`. It is the compact form for a transport that carries bytes. JSON stays supported.

```rust
let bytes: Vec<u8> = delegation.to_bytes();
let back = Delegation::from_bytes(&bytes)?; // AuthError::Malformed on any defect
assert_eq!(back, delegation);
assert_eq!(back.to_bytes(), bytes);

// Structure only. Before acting on it, check it the way you check any
// delegation: authorise (or VerifiedDelegation::verify), which also checks the
// principal set and both revoked sets. verify_delegation alone does not.
let obligations = authorise(
    &back, audience, &principals, &revoked_keys, &revoked_ids,
    &delegate_key, b"transfer", Some(5), now,
)?;
```

The layout is the same for every type:

```text
type_tag   u8        0x01 Delegation, 0x02 LoginProof, 0x03 Approval, 0x04 DelegationRevocation
version    u8        0x01 (a Delegation that names approvers is 0x02)
signer     u32 BE length || bytes    the key the signature verifies under
signed     u32 BE length || bytes    exactly signing_input()
signature  u32 BE length || bytes
```

The `signed` block is the type's own `signing_input()`, so the bytes a signature covers are visible inside the encoding. Decoding is strict and canonical: trailing bytes, an unknown tag or version, a length past the end of the input, a nonce, digest or delegation id that is not 32 bytes, a `session_commitment` that is not 0 or 32, an option flag other than 0 or 1, and a version byte that disagrees with a delegation's approvers are all `Malformed`, and there is one encoding per value. No length in the input is trusted for an allocation. Test vectors are in [`tests/vectors/`](https://github.com/0x307/aethel-runtime/tree/main/crates/aethel-auth/tests/vectors).

## Binding a login proof to one request

A plain login proof is bound to one relying party, one window and one nonce, but not to a request. Anyone who sees it before the relying party claims its nonce (a proxy that terminates TLS, a gateway, a log) can attach it to a different request at the same audience.

To close that, the holder signs a digest of the request with `Holder::login_for_request`, and the relying party checks it with `verify_login_for_request(proof, params, &expected_digest, &revoked, nonces)`. The digest is an optional field, `LoginProof::request_digest`, signed under the same `aethel-auth/login/v1` purpose. This is composition over the existing login proof, not a new construction.

- **The relying party computes the expected digest** from the request it actually received. Never take it from the client: comparing the proof's digest with a digest the client also chose checks nothing.
- **A proof without a digest is refused** by `verify_login_for_request`, because an unbound proof is good for any request.
- **A proof with a digest is refused** by plain `verify_login`, with `AuthError::RequestDigestNotChecked`. The holder asked for the binding, and a verifier must not drop it silently.
- **The digest is compared in constant time**, before the signature is checked and before the nonce is claimed.

The crate does not interpret the digest. The relying party defines what it covers, the way it does for a step-up's `action_digest`. The recommended form, with `lp(x)` meaning the 4-byte big-endian length of `x` followed by `x`:

```text
request_digest = SHA-256( lp(method) || lp(path) || lp(SHA-256(body)) )

method  the HTTP method in upper case, such as "POST"
path    the path and query exactly as sent, such as "/v1/pay?invoice=7"
body    the body bytes exactly as sent; an empty body hashes as SHA-256("")
```

The host is not in it because the audience is already signed. Headers are not in it; a relying party that relies on a header adds it as a further `lp(..)` field, and the holder must do the same. Compute the digest where the request arrives in the form the holder sent it, before any proxy rewrites the path. SHA-256 is recommended because browsers and HTTP stacks have it built in. The signature covers the 32 bytes either way.

A proof without a digest has the same signed bytes and the same JSON as before the field existed, so every existing proof still verifies. A verifier older than the field refuses a proof that carries one: it checks the signature over bytes without the digest, so it fails closed.

## Login proofs and revocation

`verify_login`, `verify_login_for_request` and `verify_step_up` each take the relying party's revoked-key set, `revoked: &R where R: RevokedKeys`, directly before `nonces`. A proof signed by a key in it is refused with `AuthError::Revoked`. The set is the one you keep: a slice or `Vec<Vec<u8>>`, a `HashSet<Vec<u8>>` or `BTreeSet<Vec<u8>>`, or a closure over your store.

```rust
let who = verify_login(&proof, params, &revoked, &nonces).await?;
```

The checks run in this order: the envelope (audience and clock), the digest checks, the signature, revocation, then the nonce claim. Revocation sits after the signature, so a caller who cannot sign as a key cannot tell whether it is revoked: a bad signature from a revoked key is `BadSignature`. It sits before the nonce claim, so a revoked key's proof never spends a nonce. Keys are compared as bytes, as in `authorise`. A relying party with no revoked keys passes `&[] as &[Vec<u8>]`.

## A server challenge

A login proof is built by the client alone, so nothing in it comes from the server. When a relying party wants a login tied to a value it chose, it sends the client 32 random bytes. The client adds them to the request digest as one more `lp(challenge)` field, using the same `lp` framing as the recommended digest above, and signs that with `Holder::login_for_request`. The server recomputes the digest from the challenge it issued and stored, and checks with `verify_login_for_request`. A challenge is good once: the server deletes it on first use, so a second proof over the same challenge finds nothing to compute a digest from.

```text
request_digest = SHA-256( lp(method) || lp(path) || lp(SHA-256(body)) || lp(challenge) )
```

## Not in this crate

Three things are left out on purpose. Each is something the app does itself.

- **A free-form constraints field on a delegation.** A delegation's limits are `Bounds`, which the crate can check. Any other limit is the app's own: it signs the limit as its own app state and checks it itself.
- **Per-action bounds beyond `Bounds`.** `Bounds` has one set of ceilings for all of a delegation's actions. An app that wants a different ceiling per action keeps its own table keyed by `Delegation::id` and enforces it.
- **A session statement.** After a login, the app runs its own session, such as a MAC over a key only the server holds. `LoginProof::session_commitment` is reserved in the wire format and does nothing in this release.

## Nonces and more than one instance

Every proof's nonce is claimed in your `NonceStore` under its purpose and its signer's key, so one party's statement never spends another's nonce. The store keeps a nonce until the earlier of the proof's own expiry and `issued_at + MAX_AGE_CEILING_SECS` (3,600 s; a larger `max_age_secs` is clamped to it), plus `NONCE_SKEW_SECS` (300 s). That depends only on the proof, so instances with different `max_age_secs` agree. Two things are still yours: **every instance at one audience must share one store**, and their clocks must stay within the skew margin of the store's.

## Wire format: one spelling per value

With `serde`, byte fields are base64url text, and decoding is strict. Only the canonical form is accepted: no padding, and no set bits after the last byte. A relying party stores and compares keys, and signatures cover the decoded bytes. A decoder that accepted several spellings of one key would let a revoked key come back under another spelling. The older JSON number-array shape is behind `legacy-number-arrays`, off by default. The [binary encoding](#binary-encoding) has the same property: one encoding per value.

## Version policy

- **Fix forward, and yank only with a recorded reason.** A fix ships as a new release, and a security fix also gets a RustSec advisory, so `cargo audit` and `cargo deny` flag the affected versions. A security bug alone is not a reason to yank. A version is yanked only when it can't be installed or would mislead, with the reason in `CHANGELOG.md`.
- **More than one line may be live.** A line is a `0.x` minor series, such as `0.1`.
- **A legacy line gets 6 months of security patches**, starting the day its successor line ships.
- **After the window, the line is unsupported.** It gets no more fixes. Every version stays downloadable.

**Security exception for the MSRV.** A security fix may raise the MSRV in a patch release, when the fixed dependency needs a newer Rust and no fixed version builds on the old one. The changelog entry names the advisory and says which Rust versions are dropped.

The MSRV is 1.87. `ctutils` below 0.4.4 has RUSTSEC-2026-0385, and `aethel-core` reaches it through `pqc-sig`'s ML-DSA on every build. Every fixed `ctutils` needs Rust 1.87, so this crate names a `ctutils >= 0.4.4` floor and declares 1.87.

The full policy is the family's [STABILITY.md](https://github.com/0x307/aethel-runtime/blob/main/STABILITY.md).

---

## The 0x307 crate family

`aethel-auth` is one of nine open-source crates from [0x307](https://0x307.com/crates), held to one
audit and stability standard.

| Crate | Tier | What it does | Builds on |
|---|---|---|---|
| [pqc-kem](https://crates.io/crates/pqc-kem) | Production | ML-KEM (FIPS 203), the X25519 + ML-KEM-768 hybrid, X-Wing, and sealed boxes | none in the family |
| [pqc-sig](https://crates.io/crates/pqc-sig) | Production | ML-DSA, SLH-DSA and FN-DSA signatures (FIPS 204/205/206) | none in the family |
| [aethel-core](https://crates.io/crates/aethel-core) | Production | Post-quantum anonymous identity: a separate identifier per context, context-bound ML-DSA signing | pqc-sig 0.5 |
| [aethel-auth](https://crates.io/crates/aethel-auth) (this crate) | Preview | Delegated authority for agent identities: login proofs, bounded delegation, step-up approval, revocation | aethel-core 0.7 |
| [aethel-sdk](https://crates.io/crates/aethel-sdk) | Preview | The SDK over aethel-core, and the place to start | pqc-sig 0.5 (aethel-core 0.7 vendored) |
| [erand-nats](https://crates.io/crates/erand-nats) | Preview | A post-quantum NATS client inside a WASM component | pqc-kem 0.2, pqc-sig 0.4 |
| [witan](https://crates.io/crates/witan) | Preview | Post-quantum gossip engine with message-level authentication, as a WASM component | pqc-kem 0.2, pqc-sig 0.4 |
| [aethel-vault](https://crates.io/crates/aethel-vault) | Lab | Agent-held wallet: policy-gated x402 / EIP-3009 signing with ML-DSA-65 spend records | aethel-core 0.7 |
| [pqc-privacy](https://crates.io/crates/pqc-privacy) | Lab | Research bundle, kept off every identity and payment path | pqc-kem 0.3, pqc-sig 0.5 |

**Production** crates are thin, standards-bound libraries meant to be depended on today. **Preview** crates work and are published, with APIs still settling. **Lab** crates are research and experiments: try them, but keep them off a production identity or payment path.

**Runnable examples:** [0x307/examples](https://github.com/0x307/examples), one program per
crate, pinned to the published versions.

**Audit status:** None of these crates has been independently audited, and none holds a CMVP / FIPS 140-3 validation. "FIPS 203/204/205/206" means the algorithms follow those standards, not that the code is certified. Known issues for this crate are in
[SECURITY.md](https://github.com/0x307/aethel-runtime/blob/main/SECURITY.md). Version policy:
[STABILITY.md](https://github.com/0x307/aethel-runtime/blob/main/STABILITY.md).
