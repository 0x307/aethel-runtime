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
//! Built: the login proof, sessions, step-up, delegation, and succession and
//! revocation statements, and enrolment, with builders for all of them behind
//! the `holder` feature. The authority layer is complete on both sides.
//!
//! The browser half of the session flow is the TypeScript client in
//! `clients/browser-session/`, which mirrors [`binding`] — the one format
//! both ends must compute identically, and the only place in this protocol
//! where two languages have to agree byte for byte.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

pub mod binding;
#[cfg(feature = "serde")]
mod b64;
pub mod delegation;
pub mod directory;
pub mod enrolment;
#[cfg(feature = "holder")]
pub mod holder;

pub mod error;
pub mod nonce;
pub mod proof;
pub mod session;
pub mod statements;

pub use binding::{sha256_32, verify_request, RequestBinding, SESSION_BINDING_V1};
pub use delegation::{authorise, verify_delegation, Bounds, Delegation, RemainingObligations};
pub use directory::{enrol, revoke, succeed, Directory, InMemoryDirectory};
pub use enrolment::{
    verify_enrolment, EnrolledIdentity, EnrolmentProof, InMemoryInviteStore, InviteStore,
};
pub use error::{AuthError, StoreError};
#[cfg(feature = "holder")]
pub use holder::{revoke_as_authority, Holder};
pub use nonce::{InMemoryNonceStore, NonceStore};
pub use proof::{
    key_fingerprint, verify_login, verify_step_up, AuthMethod, AuthStrength, AuthenticatedIdentity, LoginProof,
    StepUpProof, VerifyParams,
};
pub use statements::{
    verify_revocation, verify_succession, RevokedBy, Revocation, Succession,
};
pub use session::{
    verify_session, InMemorySessionStore, Session, SessionSecret, SessionStore, SessionToken, StoredSession,
};

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
        AUTH_DELEGATION_V1, AUTH_ENROL_V1, AUTH_LOGIN_V1, AUTH_REVOCATION_V1,
        AUTH_STEP_UP_V1, AUTH_SUCCESSION_V1,
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
            !verify_with_purpose(&public, super::purposes::AUTH_STEP_UP_V1, message, &signature)
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
            AUTH_ENROL_V1,
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
