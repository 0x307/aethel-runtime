# Changelog — aethel-auth

All notable changes to this crate are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] - Unreleased

Breaking. The authorisation API now takes what the relying party knows,
instead of leaving it to documentation. Each change closes a finding from
the October internal audit of 0.1.0.

These changes skip the deprecation cycle, under the security exception in
STABILITY.md §3: a deprecated `check_approval` that still accepted a
hand-built approval, or an `authorise` that still ignored revocation, would
keep the defects working for another minor.

### Changed

- **`authorise` takes the principals the relying party recognises.** A
  delegation is signed by its own principal, so in 0.1.0 a delegation made by
  any key authorised its agent. It now takes `principals: &[Vec<u8>]` and
  refuses any other principal with `AuthError::NotAuthorised`. An empty set
  recognises nobody.
- **`authorise` takes the relying party's revocations.** A new `RevokedKeys`
  trait, implemented for a slice of keys, `HashSet` and `BTreeSet` of keys,
  and any `Fn(&[u8]) -> bool`. A delegation whose principal or delegate key is
  revoked is refused with the new `AuthError::Revoked`.
- **`amount: None` is refused under a delegation that sets any amount bound**
  (`max_per_invocation`, `max_total` or `approval_required_above`). In 0.1.0
  it skipped the ceiling and the approval check. An action with no quantity
  passes `Some(0)`. `None` is still accepted under a delegation with no amount
  bound.
- **`check_approval` verifies the approval itself.** It takes the principal's
  `StepUpProof`, the verifier's parameters, the relying party's digest of the
  request and the nonce store, and is `async`. The step-up must be signed by
  the delegation's principal over `approval_digest(delegation,
  request_digest)`, which folds in `Delegation::id`. In 0.1.0 it took an
  `AuthenticatedIdentity`, which has public fields and could be built by hand,
  and one approval passed for any delegation from the same principal.
- **`RemainingObligations` is `#[must_use]`**, and `is_clear()` no longer
  leaves revocation implied: both of its remaining duties are in the struct.

### Added

- `approval_digest` and `Holder::approve`, which builds the principal's
  approval of one request under one delegation.
- `RevokedKeys` and `AuthError::Revoked`.

### Migrating from 0.1

- `authorise(d, aud, delegate, action, amount, now)` becomes
  `authorise(d, aud, &principals, &revoked, delegate, action, amount, now)`.
  A relying party with no revocations yet passes `&[] as &[Vec<u8>]`.
- Pass `Some(0)`, not `None`, for a quantity-free action under a bounded
  delegation.
- Replace `verify_step_up` then `check_approval(d, &identity)` with
  `check_approval(d, &step_up, params, &request_digest, &nonces).await`, and
  have the principal sign with `Holder::approve` (or sign
  `approval_digest(d, &request_digest)` as the step-up's `action_digest`). A
  0.1.0-style step-up over the bare request digest is refused.

## [0.1.0] - 2026-10-26

First release. The authority layer for agents: an agent proves control of its
key on every request, and presents a delegation from its principal that bounds
what it may do.

### Added

- **`LoginProof` and `verify_login`.** A client-asserted proof bound to one
  relying party, one validity window and one nonce, signed under
  `aethel-auth/login/v1`. The verifier clamps the window with its own maximum
  age and claims the nonce atomically through a `NonceStore`.
- **Request binding for login proofs.** An optional
  `LoginProof::request_digest`, signed under the same purpose, binds a proof
  to one request. `Holder::login_for_request` makes one and
  `verify_login_for_request` checks it against the relying party's own digest
  of the request, in constant time. Plain `verify_login` refuses a proof that
  carries a digest (`AuthError::RequestDigestNotChecked`), and
  `verify_login_for_request` refuses one without (`AuthError::RequestMismatch`).
  A proof without a digest has the same signed bytes and JSON as before, so
  proofs made before the field existed still verify. The README recommends a
  canonical form: method, path and a SHA-256 of the body, length-prefixed.
- **`Delegation`, `Bounds`, `verify_delegation` and `authorise`.** A principal
  grants a delegate a list of actions, a ceiling per invocation, a total over a
  window, an approval threshold and a validity period, at one relying party.
  `authorise` returns `RemainingObligations` for what only the relying party
  can enforce: the running total and the human approval.
- **`StepUpProof` and `verify_step_up`.** The principal re-proves control for
  one action digest, which is how a request above the approval threshold is
  approved.
- **`Revocation`, `Succession`, `verify_revocation` and `verify_succession`.**
  A holder ends its own authority or names its successor; a recognised
  authority can revoke another key and never grant one.
- **`Holder`, behind the `holder` feature**, which builds every statement above
  for one audience, and `revoke_as_authority`.
- **JSON via the `serde` feature (default).** Byte fields are base64url text.
  The signature covers the length-prefixed canonical bytes, not the JSON.
- **Strict decoding: one spelling per value.** Base64url is read only in its
  canonical form, with no padding and no set trailing bits. A second spelling
  of a revoked key is refused at parse time. The older JSON number-array
  shape is behind `legacy-number-arrays`, off by default.
- **`Delegation::id()`**, a 32-byte identifier for a relying party's own
  bookkeeping: the running total, and refusing a delegation once a key is
  revoked. One id per distinct signed statement. Signing is deterministic, so
  identical terms from one principal give the same id and share one running
  total; a separate budget needs a changed term, such as `not_before`.
- **`check_approval`**, which refuses a step-up unless the delegation's
  principal signed it.
- **`aethel-auth-cli`** (not published): `new`, `show`, `login`, `step-up`,
  `delegate` (with `--max-total` and `--window-secs`), `revoke`, `succeed` and
  `recover`.

### Features

- Default: `std` and `serde`. `holder` and `legacy-number-arrays` are opt-in.
- `verify` enables nothing. Verification is always built, so there was
  nothing to gate. The feature is kept, and is no longer in `default`, so a
  manifest that names it (`features = ["std", "verify", "serde"]`) still
  resolves.

### Not in this release

- **Sessions, session request binding, enrolment and the directory**, the flow for a
  person at a browser that cannot sign. `LoginProof::session_commitment` is
  reserved for it and is always `None` from this release's holder, so adding
  that flow later does not change what an agent signs.
- **Sub-delegation.** Deliberately absent.

### Requires

- The `std` feature. It is on by default, and a build without it is a
  `compile_error!` that says why: `aethel-core` 0.7 also builds as a
  `cdylib`, which cannot link without std. `no_std` support can be added
  later without breaking a build that has `std`.
- `aethel-core` 0.7.5 or later. 0.7.2 is the first release that registers
  this crate's purposes. 0.7.5 moves aethel-core to pqc-sig 0.5 with
  byte-identical outputs, so an app that asks for 0.7.4 still builds.
- Rust 1.87 (MSRV). `ctutils` below 0.4.4 has RUSTSEC-2026-0385, a
  constant-time failure reached through pqc-sig's ML-DSA. Every fixed
  `ctutils` needs Rust 1.87. This crate names `ctutils >= 0.4.4` as a direct
  floor, as pqc-sig 0.5.1 and aethel-vault 0.3.3 do.

### Version policy

This crate never yanks. A security defect is fixed forward and reported as a
RustSec advisory. A legacy line gets 6 months of security patches from the
day its successor line ships. A security fix may raise the MSRV in a patch
release, and the changelog says so. See the README and the family's
STABILITY.md. Nothing was yanked; this is the first release.
