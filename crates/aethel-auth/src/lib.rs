//! Delegated authority for post-quantum identities.
//!
//! `aethel-core` proves *who*. This crate expresses **what an entity may do,
//! within what bounds, until when, and unless revoked** — the layer above
//! authentication that every consumer of `aethel-core` has so far had to
//! build for itself, differently.
//!
//! # What this crate is for
//!
//! Five separable jobs sit above "prove control of a key", and only the first
//! is `aethel-core`'s:
//!
//! 1. **Authenticate** — prove control of a key. `aethel-core` does this.
//! 2. **Establish** — mint a handle the client presents afterwards, with a
//!    lifetime.
//! 3. **Authorise each request** — cheaply.
//! 4. **Step up** — re-prove for a sensitive action, or after expiry.
//! 5. **End** — logout, expiry, revocation, succession.
//!
//! Jobs 2 through 5 live here.
//!
//! # Deployment posture, and why this is not in `aethel-vault`
//!
//! This crate is what a **relying party hosts**. Its sibling in this
//! repository, `aethel-vault`, is what an **agent holds**, and it makes
//! `hosted` a hard compile error because never being hosted is a property it
//! advertises. A verifier is hosted by definition, so the two cannot be one
//! crate without voiding that claim.
//!
//! They are still two halves of one idea. The vault holds the authority to
//! *spend*; this crate verifies the authority to *act*. A delegation issued
//! here is the generalisation of the vault's `SpendPolicy` beyond money, and
//! the two are meant to compose.
//!
//! # Verifier-first
//!
//! The default build verifies and holds no secret. It depends on
//! `aethel-core` alone: no WASM runtime, no wallet, no ECDSA. Producing
//! statements is the holder's side and lives behind the `holder` feature,
//! because a server should not link that machinery by accident.
//!
//! # Two constraints this crate is built under
//!
//! **No correlating identifier may travel between verifiers.** A per-verifier
//! handle is permitted and is how a service recognises a returning entity;
//! anything correlatable *across* verifiers is not, and no cost saving buys
//! it back. Within one verifier, recognition is opt-in and documented to the
//! consumer.
//!
//! **A session is a deviation, not a default.** The architecture's position is
//! a one-time context-bound nullifier per interaction, and per-request
//! verification was measured as viable. A session exists here for one reason:
//! a browser has no signer, so a human at a page cannot sign each request. It
//! is scoped to that case, and it ends when a browser signer exists.
//!
//! # Status
//!
//! Scaffold. The statement types are not implemented yet; see the tracker.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Re-exported so consumers verify under the same registry entries this crate
/// signs under, rather than defining their own bytes.
///
/// Purpose bytes are `<crate>/<thing>/v<n>` and are registered centrally in
/// `aethel-core`, never redefined downstream. This crate's entries are added
/// there, the way `aethel-vault`'s are.
pub use aethel_core::signing::purpose;

#[cfg(test)]
mod tests {
    /// The default build is what a service hosts, so it must not acquire a
    /// dependency that implies holding a secret or running a WASM engine.
    ///
    /// This mirrors `aethel-vault`'s `manifest_contains_no_ecdsa_crates`: the
    /// cheapest way to keep a stated property true is to let the build fail
    /// when it stops being true, rather than to rely on review catching it.
    #[test]
    fn default_build_stays_verifier_only() {
        let manifest = include_str!("../Cargo.toml");

        // Everything from `[dependencies]` to the end of the file. Feature
        // declarations above it may legitimately *name* these crates.
        let deps = manifest
            .split_once("\n[dependencies]")
            .expect("manifest has a [dependencies] section")
            .1;

        for forbidden in [
            "wasmtime",     // a verifier must not need a WASM engine
            "wasm-bindgen", // browser glue belongs on the holder side
            "tfhe",         // the vault's confidential ledger, not ours
            "k256",         // no ECDSA in this repository's own signatures
            "secp256k1",
            "alloy",
            "ethers",
        ] {
            assert!(
                !deps.contains(forbidden),
                "`{forbidden}` appears in [dependencies]. The default build is \
                 verification only and depends on aethel-core alone; a holder-side \
                 or wallet dependency belongs behind an opt-in feature, if anywhere."
            );
        }
    }

    /// The purpose registry is central. If this stops compiling, the
    /// re-export above has drifted from `aethel-core`.
    #[test]
    fn purpose_registry_is_reachable() {
        assert!(!super::purpose::PLP_PRESENT_V1.is_empty());
    }
}
