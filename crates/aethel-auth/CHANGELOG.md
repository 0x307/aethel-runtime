# Changelog — aethel-auth

All notable changes to this crate are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

Driven by the first integration (Ledger's staff sign-in), which needed each of
these and found each missing. Every change is general; none carries a Ledger
type.

### Added

- **`Session::into_stored` / `Session::from_stored` and `StoredSession`.** A
  persistent `SessionStore` was impossible: `Session` kept its secret private
  with no accessor, so the in-memory store (documented as a test double) was
  the only one that could exist. `StoredSession`'s `Debug` redacts the secret.
- **`Session::establish`.** The one way to turn a verified login into a
  session. It refuses a secret the login did not commit to and a login that
  asked for no session. `AuthError::CommitmentMismatch` existed and nothing
  returned it; every consumer had to remember the check.
- **`Directory` trait, with `enrol()`, `revoke()` and `succeed()`**, and an
  `InMemoryDirectory` reference implementation. The crate still stores nothing;
  the trait says what a relying party's directory must do. `create_account`
  mints a new account and has no way to bind a key to an existing one; a
  revoked or succeeded-away key never resolves and is never bound again; only
  the outgoing key moves an account.
- **`AuthError::KeyAlreadyEnrolled`.** `enrol()` refuses an enrolled key before
  spending the invite.
- **`aethel-auth-cli revoke --subject <key>`**: revoke another key as an
  authority. The library had `revoke_as_authority`; the signer could not
  produce one.

### Changed

- **Breaking: `InviteStore` has an associated `Grant`,** and `redeem` returns
  `Option<Grant>` instead of `bool`, in the same atomic step that spends the
  invite. `verify_enrolment` returns `(EnrolledIdentity, Grant)`.
  `InMemoryInviteStore<()>` keeps `issue`; `issue_granting` takes a grant.
- **`Directory`, `enrol` and `InMemoryDirectory` live in `directory`**
  (re-exported at the crate root as before).
- **JSON: byte fields are base64url text** instead of arrays of numbers. A
  login proof from the signer went from ~19 KB to 7.3 KB. Decoding still
  accepts the old arrays. `signing_input` is unchanged, so signatures are
  unaffected.

### Documentation

- `Session<A>`: `A` is whatever the relying party needs a session to name,
  typically a composite (account and tenant), not just "the user".
- README status no longer says "scaffold".
