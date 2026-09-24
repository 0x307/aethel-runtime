# Stability and Cadence Policy

This project ships `0.x`. This document is the contract that comes with that: what counts as
a breaking change, how deprecations work, what release cadence you can expect, and what
support looks like. It's the same policy across every 0x307 repo in this family — the crypto
crates, the identity primitives, and the identity SDK.

---

## 1. Everything is 0.x

This project ships `0.x` until its own shape stops changing. `1.0.0` is tagged when the API
has stopped changing on contact with real use — a discovery, not a date on a roadmap. There's
no committed timeline to `1.0`.

Inside `0.x`, breaking changes are expected and allowed. What this policy fixes is how you'll
know one happened, and what you're owed when it does.

## 2. What counts as a breaking change

A change is breaking if code that compiled and ran correctly against the previous published
version might fail to compile, fail to run, or silently behave differently after the upgrade,
without you changing anything.

**Breaking, concretely:**

- Removing or renaming a public function, method, type, trait, or exported interface
- Changing a function's signature — parameter types, order, count, or return type
- Changing a type's public field set, or making a previously-public field private
- Changing the wire format or serialized shape of a type that crosses a process boundary
- Changing documented behavior of an existing call in a way that changes its output for the
  same input — including error-vs-success outcomes
- Tightening previously-permissive input validation such that previously-accepted input is
  now rejected
- Raising the Minimum Supported Rust Version (MSRV), or a package's minimum Node version
- Changing a default value that affects behavior (a default algorithm, a default feature
  flag's on/off state)

**Not breaking:**

- Adding a new public function, method, type, or optional field
- Widening an accepted input (accepting more than before, rejecting nothing that used to be
  accepted)
- Adding a new opt-in feature flag
- Performance improvements that don't change observable behavior
- Fixing a bug where the old behavior contradicted the documented behavior — the fix isn't
  breaking even though it changes output, because the old output was never the contract.
  These are called out in the changelog either way, since you may have been depending on the
  bug
- Internal refactors with no change to the public surface
- Documentation changes

**If it's ambiguous which side of this a change falls on, it's treated as breaking.** That's
the conservative default this policy exists to give you — the cost of an unnecessary minor
version bump is much lower than the cost of a silent break.

## 3. Deprecation before removal

Nothing is deleted without a deprecation cycle first:

1. The item is marked deprecated in a minor release, with the changelog entry stating what to
   migrate to.
2. It stays functional, with a working migration path documented, for **at least one full
   minor version** after the deprecation lands.
3. Removal happens in a later minor or major release, called out explicitly in that release's
   changelog as a completed removal.

One minor version is a floor, not a target — a deprecation with a non-obvious migration gets
more notice.

## 4. Every breaking change gets a changelog entry with a migration note

Not just "breaking: renamed `foo` to `bar`" — a migration note means you can read the entry
and know what to change in your own code without opening an issue to ask. Minimum bar: old
signature/name, new signature/name, and a one-line reason if it isn't obvious.

The `CHANGELOG.md` is the authoritative record of breaking changes — not commit messages, not
GitHub release notes alone.

## 5. Release cadence

**A release ships when there's something worth releasing — a fix, a feature, or a breaking
change that's been sitting long enough to be worth cutting a version for — and, independent of
that, at minimum once every 6 weeks.**

If nothing shipped in a given six-week window, the minimum release is a changelog-only release
stating that explicitly ("no functional changes this cycle") rather than silence. Silence is
what makes a 0.x project look abandoned; a shipped no-op doesn't.

This cadence is a floor, not a promise of frequency above it. Faster is normal, especially
early. The floor is what's meant to hold indefinitely, including through a slow stretch.

### Yanks

A version is yanked when it has a security defect, when it fails to build for a consumer,
or when it produces data the rest of the family no longer accepts. It is never yanked to push
people onto a newer feature set. A yanked version still resolves from an existing
`Cargo.lock`, so nothing already built breaks; new resolutions skip it. The release that
replaces it says why in `CHANGELOG.md`.

## 6. Support posture

**Best-effort, no SLA, single named maintainer** — see `README.md` for who that is right now.
There's no team and no on-call rotation behind this project. In practice:

- Issues and PRs are triaged (labeled, acknowledged, or closed with a reason) on a
  best-effort basis, with no committed response time for general issues.
- The one exception is the **security contact** in `SECURITY.md`: reports there are
  acknowledged within **5 business days**.
- "Best-effort" means exactly that, not a soft-pedaled response-time promise. If that changes,
  this document changes with it.

## 7. Where this applies

This policy is shared across every repo in this family, not restated per repo. Each repo's
`SECURITY.md` and `CHANGELOG.md` reference this document rather than duplicating it.

## 8. Active deprecations (this repo: `aethel-vault`)

Per §3, tracked here until each item's removal ships (and called out again in
`CHANGELOG.md` at that point):

| Item | Deprecated since | Migration | Earliest removal |
|---|---|---|---|
| `client::ContractPayload` | 0.2.0 | Type alias for `client::LedgerPayload`, renamed because it is the confidential internal ledger's payload, not an on-chain contract's. Use `LedgerPayload`; the fields are identical. | 0.4.0 |
