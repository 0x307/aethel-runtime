# Changelog — aethel-auth

All notable changes to this crate are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - Unreleased

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
