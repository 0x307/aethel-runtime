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

**Security exception.** A fix for a security defect can ship in a patch release even when it
falls under "Breaking" above, if the alternative is leaving the defect in the supported line.
That covers refusing input that is unsafe to accept (a low-order key, say) and raising the MSRV
because a dependency's security fix needs a newer compiler. The changelog entry names the rule
it breaks and why, and the change is never used for anything that isn't the fix.

**If it's ambiguous which side of this a change falls on, it's treated as breaking.** That's
the conservative default this policy exists to give you — the cost of an unnecessary minor
version bump is much lower than the cost of a silent break.

**Security exception for the MSRV.** A security fix may raise the MSRV in a patch release,
when the fixed dependency needs a newer Rust and no fixed version builds on the old one.
The changelog entry names the advisory and says which Rust versions are dropped.

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

**Security exception.** When an item cannot be kept working through a deprecation cycle without
keeping a security defect working, it may be changed or removed in the next minor release
with no cycle. The changelog entry names the defect and carries the migration note §4
requires, and the affected versions are reported like any security fix (§5, version policy).
This is for defects in the item's own contract, not a shortcut for ordinary cleanup.

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

### Version policy

- **Fix forward, and yank only with a recorded reason.** A fix ships as a new release. A
  security fix also gets a [RustSec](https://rustsec.org/) advisory that names the affected
  versions and the fixed one, so `cargo audit` and `cargo deny` flag the affected versions in
  your build and you learn about the problem and the fix together. A security bug alone is not
  a reason to yank.
- **A version is yanked only when it can't be installed or would mislead.** It can't be
  installed when it fails to build or resolve for a consumer. It would mislead when its
  published code or README describes behaviour it doesn't have, in a way a consumer would act
  on. Each yank gets one line in the crate's `CHANGELOG.md`, under "Yanked versions", giving
  the reason (for `aethel-auth`, [`crates/aethel-auth/CHANGELOG.md`](./crates/aethel-auth/CHANGELOG.md#yanked-versions)).
  A yanked version still resolves from an existing `Cargo.lock`, so nothing already built
  breaks; new resolutions skip it.
- **The gates that keep a release from needing a yank are in CI:** for `aethel-auth`, the wire
  tests (`tests/wire_json.rs`, `tests/wire_binary.rs`, `tests/compat_f43ef88.rs`, and the
  recorded 0.3 delegations in `tests/vectors/v0_3_delegations.json`) and a build of the
  packaged `.crate` itself.
- **More than one line may be live.** A line is a `0.x` minor series, such as `0.3`. When a
  dependency forces a breaking release, the old line can stay in use alongside the new one.
- **A legacy line gets 6 months of security patches.** The window starts on the day its
  successor line ships. During it, security fixes are released on the legacy line too.
- **After the window, the line is unsupported.** It is marked unsupported in `CHANGELOG.md`
  and gets no more fixes. Every version stays downloadable, and existing builds keep working.
- Each release that opens or closes a support window states the dates in `CHANGELOG.md`.

This policy took effect on 2026-10-22. It does not change versions yanked before then.

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

## 8. Active deprecations (this repo)

### `aethel-vault`

Per §3, tracked here until each item's removal ships (and called out again in
`CHANGELOG.md` at that point):

| Item | Deprecated since | Migration | Earliest removal |
|---|---|---|---|
| `client::ContractPayload` | 0.2.0 | Type alias for `client::LedgerPayload`, renamed because it is the confidential internal ledger's payload, not an on-chain contract's. Use `LedgerPayload`; the fields are identical. | 0.4.0 |

### `aethel-auth`

None active. Breaks taken without a deprecation cycle, each with its migration note in that
release's `CHANGELOG.md` entry:

- **0.2.0** changed `authorise` and `check_approval`, and **0.3.0** replaced the approval and
  `approval_digest`, under the §3 security exception.
- **0.4.0**:
  - `verify_login`, `verify_login_for_request` and `verify_step_up` gained a `revoked`
    argument, under the §3 security exception: before 0.4 a revoked key could still sign in
    and step up.
  - `authorise` and `check_approval` gained a `revoked_delegations` argument, and `Bounds`
    gained the public `approvers` field. These are §2 breaks (signature and field set) in a
    `0.x` minor (§1). Nothing is removed, so §3 does not apply.
  - `Approval.principal_key` was renamed to `approver_key`. This removal is a named exception
    to §3, and it is **not** the security exception. With named approvers the signer is no
    longer always the principal, so keeping the old name would misname it, and a Rust field
    cannot carry a deprecated alias. `#[serde(alias = "principal_key")]` keeps 0.3 JSON
    decoding; a 0.4 `Approval` serialises `approver_key`, which 0.3 readers reject.
