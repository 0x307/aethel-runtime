//! Succession and revocation: how an identity ends, and how it continues.
//!
//! Both are **statements**, not enforcement. This crate checks that a
//! statement is genuine and says what it says. Acting on it is the relying
//! party's job, because only the relying party holds the directory that maps
//! keys to accounts. The same split as delegation's cumulative bounds.
//!
//! # The asymmetry that makes the model work
//!
//! Revocation only ever *removes* authority. Succession only ever *transfers*
//! it, and only the outgoing key can sign one.
//!
//! That is why an operator can safely hold revocation and epoch powers: the
//! dangerous direction is granting, and nothing here grants. An operator who
//! could name a successor could take over any account, so no such path exists
//! and none may be added later as a convenience.
//!
//! **The consequence, stated plainly: no operator can rotate a lost key.**
//! Recovery is HTSS social recovery, holder-controlled, or the relationship
//! ends. See [`crate::statements::Succession`] and the enrolment module.
//!
//! # Succession is a link, and under D4 a contained one
//!
//! A succession record names two identities, so anyone holding it can connect
//! them. The product spec calls this "not acceptable for a person", written
//! when a holder had one identity presented everywhere. Under the
//! per-relying-party model that is too strong: a succession record links two
//! per-RP identities **at a verifier that already knows both of them**, so a
//! person rotating their key at one service is the ordinary case.
//!
//! What remains true, and is the sharper warning:
//!
//! - A succession record must never be published anywhere the issuing relying
//!   party is not. It is not a broadcast.
//! - A holder who reuses one identity across services and *then* rotates it
//!   produces a single record that joins everything it touched.

use aethel_core::signing::verify_with_purpose;

use crate::error::AuthError;
use crate::proof::push_len_prefixed;
use crate::purposes::{AUTH_REVOCATION_V1, AUTH_SUCCESSION_V1};

/// Who ended an identity's authority.
///
/// Kept distinct because they answer different questions after the fact. A
/// holder revoking their own key is key hygiene; an authority revoking it is
/// an administrative act with someone accountable for it. Collapsing them
/// loses that, and an audit log that cannot tell them apart is not much of an
/// audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokedBy {
    /// The identity revoked itself. Signed by the key being revoked.
    Holder,
    /// An authority revoked it. Signed by the authority's own key.
    ///
    /// Safe for an operator to hold: this removes authority and cannot grant
    /// any.
    Authority,
}

/// A signed statement that an identity's authority has ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    /// The key whose authority is ending.
    pub subject_key: Vec<u8>,
    /// The key that signed this statement. Equal to `subject_key` for
    /// [`RevokedBy::Holder`], the authority's key otherwise.
    pub signer_key: Vec<u8>,
    /// Who did it.
    pub by: RevokedBy,
    /// The relying party this applies at. A revocation is not a broadcast.
    pub audience: Vec<u8>,
    /// Unix seconds the statement was made.
    pub issued_at: u64,
    /// ML-DSA-65 signature under `AUTH_REVOCATION_V1`.
    pub signature: Vec<u8>,
}

impl Revocation {
    /// The exact bytes the signature covers.
    ///
    /// `by` is inside the signed input. Without it, a holder's
    /// self-revocation could be re-presented as an authority action, or the
    /// reverse, and the audit trail would be forgeable by whoever relays it.
    pub fn signing_input(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128 + self.audience.len());
        push_len_prefixed(&mut out, &self.subject_key);
        push_len_prefixed(&mut out, &self.audience);
        out.push(match self.by {
            RevokedBy::Holder => 0,
            RevokedBy::Authority => 1,
        });
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out
    }
}

/// A signed statement naming the key that continues an identity's authority.
///
/// Only the **outgoing** key can sign one. That is the whole security
/// property: it makes rotation something a holder does and an operator
/// cannot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Succession {
    /// The key standing down. Signs this statement.
    pub from_key: Vec<u8>,
    /// The key taking over.
    pub to_key: Vec<u8>,
    /// The relying party this applies at, and only there.
    pub audience: Vec<u8>,
    /// Unix seconds.
    pub issued_at: u64,
    /// ML-DSA-65 signature by `from_key`, under `AUTH_SUCCESSION_V1`.
    pub signature: Vec<u8>,
}

impl Succession {
    /// The exact bytes the signature covers.
    ///
    /// Both keys are inside it. The outgoing key is the one verified against,
    /// so it is bound implicitly, but including it explicitly costs little and
    /// makes a transcript self-describing. The incoming key must be bound or
    /// anyone relaying the statement could substitute themselves as successor.
    pub fn signing_input(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128 + self.audience.len());
        push_len_prefixed(&mut out, &self.from_key);
        push_len_prefixed(&mut out, &self.to_key);
        push_len_prefixed(&mut out, &self.audience);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out
    }
}

/// Check that a revocation is genuine and for this relying party.
///
/// For [`RevokedBy::Holder`] the signer must *be* the subject: a holder can
/// only revoke themselves. For [`RevokedBy::Authority`] the caller supplies
/// the authority keys it recognises, and the signer must be one of them.
///
/// An empty `authority_keys` means this relying party recognises no authority,
/// so every authority revocation is refused. That is the safe reading of
/// silence, consistent with delegation: absence grants nothing.
pub fn verify_revocation(
    revocation: &Revocation,
    expected_audience: &[u8],
    authority_keys: &[Vec<u8>],
) -> Result<(), AuthError> {
    if revocation.subject_key.is_empty()
        || revocation.signer_key.is_empty()
        || revocation.signature.is_empty()
        || revocation.audience.is_empty()
    {
        return Err(AuthError::Malformed);
    }

    if revocation.audience != expected_audience {
        return Err(AuthError::AudienceMismatch);
    }

    match revocation.by {
        RevokedBy::Holder => {
            if revocation.signer_key != revocation.subject_key {
                return Err(AuthError::NotAuthorised);
            }
        }
        RevokedBy::Authority => {
            if !authority_keys.iter().any(|k| *k == revocation.signer_key) {
                return Err(AuthError::NotAuthorised);
            }
        }
    }

    let verified = verify_with_purpose(
        &revocation.signer_key,
        AUTH_REVOCATION_V1,
        &revocation.signing_input(),
        &revocation.signature,
    )
    .map_err(|_| AuthError::Malformed)?;

    if !verified {
        return Err(AuthError::BadSignature);
    }

    Ok(())
}

/// Check that a succession is genuine and signed by the key standing down.
///
/// There is deliberately no parameter by which an operator could authorise
/// this. If the outgoing key cannot sign, there is no succession.
pub fn verify_succession(
    succession: &Succession,
    expected_audience: &[u8],
) -> Result<(), AuthError> {
    if succession.from_key.is_empty()
        || succession.to_key.is_empty()
        || succession.signature.is_empty()
        || succession.audience.is_empty()
    {
        return Err(AuthError::Malformed);
    }

    if succession.audience != expected_audience {
        return Err(AuthError::AudienceMismatch);
    }

    // A key succeeding itself is not a rotation, and accepting it would let a
    // replayed record look like a fresh one forever.
    if succession.from_key == succession.to_key {
        return Err(AuthError::Malformed);
    }

    let verified = verify_with_purpose(
        &succession.from_key,
        AUTH_SUCCESSION_V1,
        &succession.signing_input(),
        &succession.signature,
    )
    .map_err(|_| AuthError::Malformed)?;

    if !verified {
        return Err(AuthError::BadSignature);
    }

    Ok(())
}
