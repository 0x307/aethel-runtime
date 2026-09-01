# aethel-runtime Roadmap

This tracks what's sequenced ahead of what in this repo, and why, so the
tempting-to-build-first part doesn't get built first.

## 1. Account de-correlation comes before wider blind-state adoption

A downstream consumer of this crate keys accounts by DID and by public
EVM/Solana wallet addresses. Encrypting a balance into an `FheUint64` hides
transaction *amounts*. It does nothing for the transaction *graph*: a public
chain address is maximally correlatable by design, so every transfer between
two encrypted-balance accounts is still visible as an edge between two known
addresses.

**Blind state is only meaningful once the account is no longer keyed by a
correlatable public identifier.** Encrypting the balance is the demonstrable,
easy-to-build-first part of this arc; building it first would look like the
privacy property had shipped when only the amount-hiding half had. The
de-correlation work (replacing public-address account keys with something
that isn't trivially linkable, presumably PLP-projection-derived vault IDs
used consistently instead of addresses) is sequenced ahead of any broader
rollout of the blind-state balance path, not the other way around. This repo
does not attempt that work; it is called out here so the next person doesn't
reach for the encrypted-balance part first because it's the one with a demo.

## 2. Wiring an untrusted network caller's identity proof into the vault

`homomorphic_transfer_authenticated` (`src/vault.rs`) verifies a
`aethel_core::plp::ZkIdentityProof` against a vault's registered
`EphemeralProjection` via `aethel_core::plp::Verifier::verify`. That call is
real. What it does not yet support is a proof arriving as bytes over a
network from an untrusted caller, and that's a real gap, not a small one:

`aethel-core`'s `Poly` type (the field type inside `ZkIdentityProof`,
`EphemeralProjection.matrix_a`/`public_b`, and SAAP's `Polynomial`) has no
public constructor outside the crate. `coeffs` is `pub(crate)`; the only way
to get a `Poly` with attacker-influenced coefficients is to be code that
lives inside `aethel-core` itself, e.g. `component.rs`'s
`zk_proof_from_wit`. This looks deliberate — a type that can only be produced
by the crate's own proving/verifying algorithms cannot be handed a
fabricated proof at the type level, regardless of what a calling crate's own
validation logic does or doesn't check. `EphemeralProjection` is the
exception: it has `to_bytes`/`from_bytes` because publishing a projection
is exactly what it's for. `ZkIdentityProof` (and SAAP's `SaapPresentation`)
do not, because unlike a projection, a proof is meant to be *produced*, not
*asserted*.

Two ways to close this, neither attempted here:

- **Upstream `aethel-core` change.** Add a validated byte codec for
  `ZkIdentityProof` (and, if the SAAP path is wanted instead, for
  `SaapPresentation`/`saap::Polynomial`) analogous to
  `EphemeralProjection::to_bytes`/`from_bytes` — decode-then-validate, not a
  raw field copy, so an out-of-range coefficient is rejected the same way
  `EphemeralProjection::from_bytes` rejects a too-short buffer today.
- **Host-import delegation**, matching the pattern already used for FHE:
  this crate's WASM binary delegates `host_fhe_sub`/`_add`/`_ge`/`_select` to
  the wasmer.io host because those operations don't belong inside the
  contract's own sandboxed state machine. Identity verification could work
  the same way: the host (which, unlike this contract's wasm32 binary, *can*
  run `wasmtime` and load `aethel-core`'s compiled WIT component) verifies a
  submitted proof against a projection through the `aethel:core` component
  world and calls a `host_identity_verify(projection_bytes, proof_bytes) ->
  bool` import, mirroring `host_fhe_zero`'s shape. This avoids needing a new
  `aethel-core` release but adds a host-side dependency this contract
  doesn't otherwise have.

Until one of those lands, `homomorphic_transfer_authenticated` is reachable
only by a caller that links `aethel-vault` and `aethel-core` together in the
same Rust binary and produces the proof in-process (e.g. via
`aethel_core::plp::Prover::prove_identity`) — a native validator or gateway
service is the realistic shape of that caller, not a wallet submitting a
proof over the wire.

## 3. Doc debt beyond README.md and the crate-level doc comment — addressed

`README.md`, `src/lib.rs`'s crate doc comment, and `docs/OVERVIEW.md` now
describe only what `src/` actually implements: single-party FHE, PLP-derived
vault IDs, and the `homomorphic_transfer_authenticated` identity-proof path.
`docs/TFHE-VAULT-SPEC.md` and `docs/WASM-DEPLOYMENT.md` carry
implementation-status notes distinguishing the remaining design-target
material they describe (SRAM PUF, an "enclave binary" build) from what ships,
plus inline corrections at concrete claims that were simply wrong rather
than aspirational (e.g. `TFHE-VAULT-SPEC.md`'s error-code table listed
100/101/102/103, which were never the real values; `WASM-DEPLOYMENT.md`
§4.1 named a `tfhe` feature that doesn't exist and described the wasm32
contract as linking `tfhe` directly, which it never has).

Separately, since fixed: `build.rs` used to regenerate `dist/*`
unconditionally on every `cargo build`, which made those files show as
modified after any local build (line-ending churn under `core.autocrlf`) and
turned out to be a hard blocker, not just noise: `cargo publish --dry-run`
failed outright with "Source directory was modified by build.rs", since a
build script writing into the source tree is exactly what publish
verification rejects. Now env-gated behind `AETHEL_GENERATE_DIST=1`,
matching the identical fix `aethel-core` made in its own 0.1.5. `dist/` and
`docs/TFHE-VAULT-SPEC.md`/`docs/WASM-DEPLOYMENT.md` are also excluded from
what `cargo package` actually ships (`Cargo.toml`'s `exclude` list) — a
Rust consumer builds from `src/`, and both carry a stronger permanence bar
once published to crates.io than the mutable git repo.

## 4. Publishing this crate to crates.io — prepped, not done

The `aethel-vault` name is available on crates.io, and `cargo publish
--dry-run` succeeds as of the fixes above. Two things intentionally left
undone, per an explicit decision to hold off (2026-09-01):

- **GitHub repo visibility.** `Cargo.toml`'s `repository` field is correct
  now (`https://github.com/0x307/aethel-runtime` — it previously pointed at
  a nonexistent `0x307/aethel`), but the repo itself is still private.
  crates.io renders that field as a public link regardless of the
  destination's visibility, so publishing before the repo goes public leaves
  a dead link on the crate's public page. Sequence GitHub visibility before
  (or alongside) a real `cargo publish`, not after.
- **The actual publish.** Everything above is preparation; no version of
  this crate has been published. `cargo login` credentials are present in
  this environment, so a real publish needs only the go-ahead, not further
  setup.

## 5. Not attempted in this pass, and deliberately so

- Wiring identity checks into every vault operation (registration,
  withdrawal, etc.) rather than just transfer. One operation is enough to
  prove the pattern works; wiring all of them multiplies the surface area of
  a decision (PLP proof vs. full SAAP presentation vs. host-delegated
  verification) that isn't settled yet.
- Full SAAP presentation verification (`aethel_core::credential::verify`)
  instead of a bare PLP ownership proof. It hits the identical
  no-external-constructor wall described above for `saap::Polynomial`
  (`SaapPresentation`'s field type), for materially more implementation
  work: an `IssuerParams`, a `Credential`, and a `BlindedCredential`, plus
  four distinct freshness-critical randomness values, versus one proof and
  one projection for the PLP path. If a future consumer needs selective
  attribute disclosure, revisit; the ownership-only case does not.
