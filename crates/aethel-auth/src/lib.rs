//! Delegated authority for post-quantum identities.
//!
//! `aethel-core` proves *who*. This crate expresses **what an entity may do,
//! within what bounds, until when, and unless revoked** — the layer above
//! authentication that every consumer of `aethel-core` has so far had to
//! build for itself, differently.
//!
//! # What this crate is for
//!
//! Four jobs sit above "prove control of a key", and only the first is
//! `aethel-core`'s:
//!
//! 1. **Authenticate**: prove control of a key. `aethel-core` does this; the
//!    [`LoginProof`] here makes that proof bound to one relying party, one
//!    window and one nonce.
//! 2. **Authorise each request**: check that a [`Delegation`] from a
//!    principal covers what its delegate is attempting.
//! 3. **Step up**: re-prove for one sensitive action, which is how a
//!    principal approves a request above its own threshold.
//! 4. **End**: expiry, revocation, succession.
//!
//! Jobs 2 through 4 live here, for an agent that proves itself on every
//! request and keeps no session.
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
//! The default build verifies and holds no secret. Its runtime dependencies
//! are `aethel-core`, `sha3`, `subtle` and, by default, `serde`: no WASM
//! runtime, no wallet, no ECDSA. Producing
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
//! **Every request proves itself.** The architecture's position is a one-time
//! context-bound proof per interaction, and per-request verification was
//! measured as viable. This release has no sessions: an agent signs a fresh
//! [`LoginProof`] for each request. A session flow, for a person at a browser
//! that cannot sign, is not in this release; [`LoginProof`] reserves one
//! optional field for it so adding it later would not change what an agent
//! signs.
//!
//! # Status
//!
//! Built: the login proof, step-up, delegation, and succession and revocation
//! statements, with builders for all of them behind the `holder` feature.

#![cfg_attr(not(feature = "std"), no_std)]
// No unsafe code, tests included. Test executors use `Waker::noop()`.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "serde")]
mod b64;
pub mod delegation;
#[cfg(feature = "holder")]
pub mod holder;

pub mod error;
pub mod nonce;
pub mod proof;
pub mod statements;

pub use delegation::{
    authorise, check_approval, verify_delegation, Bounds, Delegation, RemainingObligations,
};
pub use error::{AuthError, StoreError};
#[cfg(feature = "holder")]
pub use holder::{revoke_as_authority, Holder};
pub use nonce::{InMemoryNonceStore, NonceStore};
pub use proof::{
    key_fingerprint, verify_login, verify_login_for_request, verify_step_up, AuthMethod,
    AuthStrength, AuthenticatedIdentity, LoginProof, StepUpProof, VerifyParams,
};
pub use statements::{verify_revocation, verify_succession, Revocation, RevokedBy, Succession};

/// Re-exported so consumers verify under the same registry entries this crate
/// signs under, rather than defining their own bytes.
///
/// Purpose bytes are `<crate>/<thing>/v<n>` and are registered centrally in
/// `aethel-core`, never redefined downstream. This crate's entries are added
/// there, the way `aethel-vault`'s are.
pub use aethel_core::signing::purpose;

/// This crate's own entries in that registry, named locally so a caller does
/// not have to know they live upstream.
///
/// Each statement type gets its own purpose and never borrows another's. That
/// is what makes a signature for one statement structurally unusable as
/// another, rather than a rule callers have to remember.
pub mod purposes {
    pub use aethel_core::signing::purpose::{
        AUTH_DELEGATION_V1, AUTH_LOGIN_V1, AUTH_REVOCATION_V1, AUTH_STEP_UP_V1, AUTH_SUCCESSION_V1,
    };
}

#[cfg(test)]
mod tests {
    /// The default build is what a service hosts, so it must not acquire a
    /// dependency that implies holding a secret or running a WASM engine.
    ///
    /// This mirrors `aethel-vault`'s `manifest_contains_no_ecdsa_crates`: the
    /// cheapest way to keep a stated property true is to let the build fail
    /// when it stops being true, rather than to rely on review catching it.
    ///
    /// # What this does not cover, which is most of it
    ///
    /// It reads **this crate's manifest text**. It would catch someone adding
    /// `k256` here. It would not notice the same crate arriving through
    /// `aethel-core` or `pqc-sig`, because a manifest is not a dependency
    /// graph, and a test that searches one while claiming the other is worse
    /// than no test.
    ///
    /// The real assertion is `aethel-ws/scripts/no-classical-crypto.sh`,
    /// which walks the resolved graph for every crate in the family and runs
    /// as part of the workspace gate. This one stays because it is free and
    /// fails earlier, not because it is sufficient.
    ///
    /// Note that this is a *deny* list, not "aethel-core and nothing else".
    /// The crate also pulls `sha3` and `subtle`, both of which are small,
    /// `no_std`, and already implied by what it does: SHAKE-256 is the hash
    /// `aethel-core` itself uses, and constant-time comparison is not
    /// something to hand-roll next to a MAC. What the list forbids is anything
    /// that would make a verifier carry holder-side or wallet machinery.
    /// Crates a default (verifier) build must never depend on.
    const FORBIDDEN_IN_DEFAULT_BUILD: [&str; 7] = [
        "wasmtime",     // a verifier must not need a WASM engine
        "wasm-bindgen", // browser glue belongs on the holder side
        "tfhe",         // the vault's confidential ledger, not ours
        "k256",         // no ECDSA in this repository's own signatures
        "secp256k1",
        "alloy",
        "ethers",
    ];

    /// The runtime-dependency tables of a manifest, in either shape Cargo
    /// writes.
    ///
    /// The repository's manifest has one `[dependencies]` table. The manifest
    /// inside a published `.crate` is rewritten by `cargo package` into one
    /// `[dependencies.<name>]` table per crate. An earlier version of this
    /// test only understood the first shape, so it passed in the repository
    /// and panicked in the published crate. Both shapes are read here, and
    /// target-specific dependency tables count as runtime dependencies too.
    /// `[dev-dependencies]`, `[build-dependencies]` and feature lists do not.
    fn runtime_dependency_tables(manifest: &str) -> String {
        let mut out = String::new();
        let mut inside = false;
        for line in manifest.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('[') {
                let header = trimmed.trim_start_matches('[').trim_end_matches(']');
                inside = header == "dependencies"
                    || header.starts_with("dependencies.")
                    || (header.starts_with("target.")
                        && (header.ends_with(".dependencies")
                            || header.contains(".dependencies.")));
            }
            if inside {
                out.push_str(line);
                out.push('\n');
            }
        }
        out
    }

    #[test]
    fn default_build_stays_verifier_only() {
        let deps = runtime_dependency_tables(include_str!("../Cargo.toml"));

        // Not vacuous: the tables were found, in whichever shape this
        // manifest is in.
        assert!(
            deps.contains("aethel-core"),
            "no runtime dependency tables found; the parser no longer matches this manifest"
        );

        for forbidden in FORBIDDEN_IN_DEFAULT_BUILD {
            assert!(
                !deps.contains(forbidden),
                "`{forbidden}` appears in the runtime dependencies. The default build is \
                 verification only: no WASM runtime, wallet or classical asymmetric \
                 crypto. A holder-side or wallet dependency belongs behind an opt-in \
                 feature, if anywhere."
            );
        }
    }

    /// Positive control for the test above: a forbidden crate is caught in
    /// both manifest shapes, and a dev-dependency or a feature list that
    /// merely names one is not.
    #[test]
    fn the_dependency_guard_reads_both_manifest_shapes() {
        let repository_shape = "[features]
holder = [\"k256\"]

[dependencies]
aethel-core = \"0.7\"
k256 = \"0.13\"

[dev-dependencies]
criterion = \"0.5\"
";
        let packaged_shape = "[features]
holder = []

[dependencies.aethel-core]
version = \"0.7\"

[dependencies.k256]
version = \"0.13\"

[dev-dependencies.criterion]
version = \"0.5\"
";
        let target_shape = "[dependencies]
aethel-core = \"0.7\"

[target.'cfg(unix)'.dependencies]
k256 = \"0.13\"
";
        let clean_packaged = "[features]
holder = [\"k256\"]

[dependencies.aethel-core]
version = \"0.7\"

[dev-dependencies.k256]
version = \"0.13\"
";

        for (label, manifest) in [
            ("repository", repository_shape),
            ("packaged", packaged_shape),
            ("target-specific", target_shape),
        ] {
            assert!(
                runtime_dependency_tables(manifest).contains("k256"),
                "the {label} shape hid a forbidden runtime dependency"
            );
        }

        let deps = runtime_dependency_tables(clean_packaged);
        assert!(deps.contains("aethel-core"));
        assert!(
            !deps.contains("k256"),
            "a dev-dependency or a feature list must not count as a runtime dependency"
        );
    }

    /// The purpose registry is central. If this stops compiling, the
    /// re-export above has drifted from `aethel-core`.
    #[test]
    fn purpose_registry_is_reachable() {
        assert!(!super::purpose::PLP_PRESENT_V1.is_empty());
    }

    /// The point of a purpose is not that the constant exists, it is that a
    /// signature made under one is structurally unusable under another. Prove
    /// that on this crate's own entries rather than trusting the registry.
    ///
    /// A login response replayed as a step-up is the concrete attack: both are
    /// signed by the same key, over similar-looking bytes, moments apart.
    #[test]
    fn a_login_signature_is_not_a_step_up_signature() {
        use aethel_core::signing::{verify_with_purpose, Identity};

        let identity = Identity::generate(&[7u8; 32]).expect("32 bytes is enough entropy");
        let public = identity.public_key();
        let message = b"challenge-id|nonce|audience|expiry";

        // Note the argument order: `purpose` comes before `message` in both
        // calls. Both are `&[u8]`, so transposing them compiles and produces a
        // signature over the wrong thing. Worth naming, since a caller who gets
        // it backwards gets no help from the type system.
        let signature = identity
            .sign_with_purpose(super::purposes::AUTH_LOGIN_V1, message)
            .expect("signing under a registered purpose");

        assert!(
            verify_with_purpose(&public, super::purposes::AUTH_LOGIN_V1, message, &signature)
                .expect("well-formed inputs"),
            "a login signature must verify under the login purpose"
        );

        assert!(
            !verify_with_purpose(
                &public,
                super::purposes::AUTH_STEP_UP_V1,
                message,
                &signature
            )
            .expect("well-formed inputs"),
            "a login signature must NOT verify as a step-up: same key, same bytes, \
             different purpose"
        );
    }

    /// Every statement type this crate will produce needs its own purpose. A
    /// collision would silently make two statement types interchangeable.
    #[test]
    fn this_crates_purposes_are_distinct_and_namespaced() {
        use super::purposes::*;

        let all = [
            AUTH_LOGIN_V1,
            AUTH_STEP_UP_V1,
            AUTH_SUCCESSION_V1,
            AUTH_REVOCATION_V1,
            AUTH_DELEGATION_V1,
        ];

        for (i, a) in all.iter().enumerate() {
            assert!(
                a.starts_with(b"aethel-auth/"),
                "purpose {i} is not namespaced to this crate"
            );
            for b in all.iter().skip(i + 1) {
                assert_ne!(a, b, "two of this crate's purposes collide");
            }
        }
    }
}
