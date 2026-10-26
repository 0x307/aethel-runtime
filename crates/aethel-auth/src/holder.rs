//! Producing statements. The other half of this crate.
//!
//! Everything else here verifies. Nothing verified it until this module
//! existed, which meant a complete verifier that no client could talk to.
//!
//! # One holder, one relying party
//!
//! [`Holder`] binds an identity to an audience, and every statement it
//! produces is for that audience. That is not a convenience wrapper: it is how
//! the per-relying-party rule becomes the path of least resistance rather than
//! a paragraph someone is supposed to remember.
//!
//! ```ignore
//! let console = Holder::new(&console_identity, "https://console.example.com");
//! let gateway = Holder::new(&gateway_identity, "https://gateway.example.com");
//! ```
//!
//! Two identities, because no key should reach two relying parties. Reusing
//! one `Identity` for both `Holder`s compiles, and is the thing not to do: two
//! services that both see that key can join a holder's activity across them.
//! The type cannot prevent it, but it can make the correct shape the obvious
//! one.
//!
//! # No randomness, no clock
//!
//! Every builder takes its nonce and its timestamps. This crate has no RNG and
//! no clock, deliberately: a library that silently supplies either becomes the
//! weakest link in somebody else's entropy or the reason a test cannot run
//! twice. The caller passes both, and the caller is the one who knows whether
//! it has a real CSPRNG.
//!
//! # Where this runs
//!
//! Wherever the key actually lives: a CLI, a daemon, an agent process. A
//! browser has no ML-DSA signer until the TypeScript SDK exists, so there is
//! no browser builder here.

use aethel_core::signing::Identity;

use crate::delegation::{Bounds, Delegation};
use crate::proof::{LoginProof, StepUpProof};
use crate::purposes::{
    AUTH_DELEGATION_V1, AUTH_LOGIN_V1, AUTH_REVOCATION_V1, AUTH_STEP_UP_V1, AUTH_SUCCESSION_V1,
};
use crate::statements::{Revocation, RevokedBy, Succession};

/// An identity, and the one relying party it acts at.
pub struct Holder<'a> {
    identity: &'a Identity,
    audience: Vec<u8>,
}

impl<'a> Holder<'a> {
    /// Bind `identity` to `audience`.
    ///
    /// Use a **different identity per audience**. Nothing here enforces it,
    /// and everything here is shaped to make it the easy choice.
    pub fn new(identity: &'a Identity, audience: impl Into<Vec<u8>>) -> Self {
        Holder {
            identity,
            audience: audience.into(),
        }
    }

    /// The public key a relying party will know this holder by.
    pub fn public_key(&self) -> Vec<u8> {
        self.identity.public_key()
    }

    fn sign(&self, purpose: &[u8], message: &[u8]) -> Vec<u8> {
        // Note the argument order: purpose first, then message. Both are
        // `&[u8]`, so transposing them compiles and signs over the wrong
        // thing. Centralised here so every builder gets it right once.
        self.identity
            .sign_with_purpose(purpose, message)
            .expect("registry purposes are within MAX_CONTEXT_LEN")
    }

    /// A login proof, for an agent that re-proves on every request and keeps
    /// no session.
    ///
    /// The proof's `session_commitment` is always `None` here. The field is
    /// part of the wire format so a session flow can be added later without
    /// changing what an agent signs; this release has no session flow.
    pub fn login(&self, nonce: [u8; 32], issued_at: u64, valid_for_secs: u64) -> LoginProof {
        self.build_login(nonce, issued_at, valid_for_secs, None)
    }

    /// A login proof that is good for one request only.
    ///
    /// `request_digest` is a digest of the request, in the form the relying
    /// party defines (the README recommends one). The relying party computes
    /// the same digest from the request it receives and checks the proof with
    /// [`verify_login_for_request`](crate::verify_login_for_request), so a
    /// proof seen on the way cannot be attached to a different request.
    pub fn login_for_request(
        &self,
        nonce: [u8; 32],
        issued_at: u64,
        valid_for_secs: u64,
        request_digest: [u8; 32],
    ) -> LoginProof {
        self.build_login(nonce, issued_at, valid_for_secs, Some(request_digest))
    }

    /// One builder for both kinds of login proof, so each is signed once,
    /// over its final fields.
    fn build_login(
        &self,
        nonce: [u8; 32],
        issued_at: u64,
        valid_for_secs: u64,
        request_digest: Option<[u8; 32]>,
    ) -> LoginProof {
        let mut proof = LoginProof {
            public_key: self.public_key(),
            audience: self.audience.clone(),
            nonce,
            issued_at,
            expires_at: issued_at.saturating_add(valid_for_secs),
            session_commitment: None,
            request_digest,
            signature: Vec::new(),
        };
        proof.signature = self.sign(AUTH_LOGIN_V1, &proof.signing_input());
        proof
    }

    /// Re-prove control for one specific action.
    ///
    /// `action_digest` is the relying party's own digest of what is about to
    /// happen. The holder should be shown what it means before signing;
    /// consenting to an opaque 32 bytes is consenting to nothing.
    pub fn step_up(
        &self,
        nonce: [u8; 32],
        issued_at: u64,
        valid_for_secs: u64,
        action_digest: [u8; 32],
    ) -> StepUpProof {
        let mut proof = StepUpProof {
            public_key: self.public_key(),
            audience: self.audience.clone(),
            nonce,
            issued_at,
            expires_at: issued_at.saturating_add(valid_for_secs),
            action_digest,
            signature: Vec::new(),
        };
        proof.signature = self.sign(AUTH_STEP_UP_V1, &proof.signing_input());
        proof
    }

    /// Grant `delegate_key` bounded authority to act at this audience.
    ///
    /// The delegate needs its own per-relying-party identity too. If an agent
    /// reuses one key across services, the delegations held at each of them
    /// share it, and anyone seeing two can join the agent across services.
    pub fn delegate_to(
        &self,
        delegate_key: Vec<u8>,
        bounds: Bounds,
        not_before: u64,
        expires_at: u64,
    ) -> Delegation {
        let mut delegation = Delegation {
            principal_key: self.public_key(),
            delegate_key,
            audience: self.audience.clone(),
            bounds,
            not_before,
            expires_at,
            signature: Vec::new(),
        };
        delegation.signature = self.sign(AUTH_DELEGATION_V1, &delegation.signing_input());
        delegation
    }

    /// End this identity's own authority at this relying party.
    ///
    /// A holder can always do this. It needs nobody's permission, which is the
    /// point.
    pub fn revoke_self(&self, issued_at: u64) -> Revocation {
        let mut revocation = Revocation {
            subject_key: self.public_key(),
            signer_key: self.public_key(),
            by: RevokedBy::Holder,
            audience: self.audience.clone(),
            issued_at,
            signature: Vec::new(),
        };
        revocation.signature = self.sign(AUTH_REVOCATION_V1, &revocation.signing_input());
        revocation
    }

    /// Name the key that continues this identity's authority here.
    ///
    /// Only the outgoing key can do this, which is why no operator can rotate
    /// a lost key, and why losing one without HTSS shares costs the
    /// relationship.
    pub fn name_successor(&self, to_key: Vec<u8>, issued_at: u64) -> Succession {
        let mut succession = Succession {
            from_key: self.public_key(),
            to_key,
            audience: self.audience.clone(),
            issued_at,
            signature: Vec::new(),
        };
        succession.signature = self.sign(AUTH_SUCCESSION_V1, &succession.signing_input());
        succession
    }
}

/// Revoke another identity's authority, as a recognised authority.
///
/// Separate from [`Holder`] on purpose. Revoking someone else is not something
/// a holder does, and putting it on the same type would put it one dot away
/// from `revoke_self` for anyone exploring the API.
///
/// This only ever **removes** authority, which is why an operator may hold it.
/// There is deliberately no counterpart that grants any.
pub fn revoke_as_authority(
    authority: &Identity,
    subject_key: Vec<u8>,
    audience: impl Into<Vec<u8>>,
    issued_at: u64,
) -> Revocation {
    let mut revocation = Revocation {
        subject_key,
        signer_key: authority.public_key(),
        by: RevokedBy::Authority,
        audience: audience.into(),
        issued_at,
        signature: Vec::new(),
    };
    revocation.signature = authority
        .sign_with_purpose(AUTH_REVOCATION_V1, &revocation.signing_input())
        .expect("registry purposes are within MAX_CONTEXT_LEN");
    revocation
}
