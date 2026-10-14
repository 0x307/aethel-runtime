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
- **`aethel-auth-cli`** (not published): `new`, `show`, `login`, `step-up`,
  `delegate` (with `--max-total` and `--window-secs`), `revoke`, `succeed` and
  `recover`.

### Not in this release

- **Sessions, request binding, enrolment and the directory**, the flow for a
  person at a browser that cannot sign. `LoginProof::session_commitment` is
  reserved for it and is always `None` from this release's holder, so adding
  that flow later does not change what an agent signs.
- **Sub-delegation.** Deliberately absent.

### Requires

- `aethel-core` 0.7.2 or later, the first release that registers this crate's purposes.
