//! The principal's approval of one request under one delegation.
//!
//! A delegation can say that requests above an amount need the principal's
//! approval ([`crate::Bounds::approval_required_above`]). This module is that
//! approval: a statement of its own, signed under its own purpose
//! ([`crate::purposes::AUTH_APPROVAL_V1`]), naming in the clear what is being
//! approved.
//!
//! # Its own statement, not a step-up
//!
//! An approval used to be a step-up whose 32-byte action digest happened to
//! be computed from the delegation and the request. A step-up is also the
//! general "confirm it's you" signature, so any software that got the owner to
//! sign *a* step-up over bytes it chose had an approval, and the owner's
//! signer could not tell which it was making. Here the purpose is different,
//! so a step-up signature never verifies as an approval, and the fields are
//! plain, so an owner's software can show "approve 9,000 for `pay` under this
//! delegation at this seller" and check each value before signing.
//!
//! # What it binds
//!
//! The audience, the delegation (by [`crate::Delegation::id`]), the relying
//! party's digest of the request, the action and the amount, plus a nonce and
//! a validity window. [`check_approval`] refuses it if any of those differs
//! from what the relying party is about to do.

use aethel_core::signing::verify_with_purpose;
use subtle::ConstantTimeEq;

use crate::delegation::{verify_delegation, Delegation, RevokedKeys};
use crate::error::AuthError;
use crate::nonce::NonceStore;
use crate::proof::{check_envelope, claim_nonce, push_len_prefixed, VerifyParams};
use crate::purposes::AUTH_APPROVAL_V1;

/// A principal's signed approval of one request under one delegation.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    /// ML-DSA-65 public key of the approver: the delegation's principal.
    #[cfg_attr(feature = "serde", serde(with = "crate::b64::bytes"))]
    pub principal_key: Vec<u8>,
    /// The relying party the approval is for.
    #[cfg_attr(feature = "serde", serde(with = "crate::b64::bytes"))]
    pub audience: Vec<u8>,
    /// [`Delegation::id`] of the delegation the request is made under.
    #[cfg_attr(feature = "serde", serde(with = "crate::b64::array32"))]
    pub delegation_id: [u8; 32],
    /// The relying party's own digest of the request being approved. The
    /// crate does not interpret it; see the README for a recommended form.
    #[cfg_attr(feature = "serde", serde(with = "crate::b64::array32"))]
    pub request_digest: [u8; 32],
    /// The action tag being approved, one of the delegation's actions.
    #[cfg_attr(feature = "serde", serde(with = "crate::b64::bytes"))]
    pub action: Vec<u8>,
    /// The exact amount being approved. An approval at one amount does not
    /// approve another, larger or smaller.
    pub amount: u128,
    /// 256 bits, fresh, never reused.
    #[cfg_attr(feature = "serde", serde(with = "crate::b64::array32"))]
    pub nonce: [u8; 32],
    /// Unix seconds, per the approver's clock.
    pub issued_at: u64,
    /// Unix seconds, per the approver's clock.
    pub expires_at: u64,
    /// ML-DSA-65 signature over [`Approval::signing_input`], under
    /// [`AUTH_APPROVAL_V1`].
    #[cfg_attr(feature = "serde", serde(with = "crate::b64::bytes"))]
    pub signature: Vec<u8>,
}

impl Approval {
    /// The exact bytes the signature covers.
    ///
    /// Every field but the signer's key (bound by verification) and the
    /// signature, fixed-width or length-prefixed in a fixed order, so no two
    /// approvals share signed bytes.
    pub fn signing_input(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(192 + self.audience.len() + self.action.len());
        push_len_prefixed(&mut out, &self.audience);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        push_len_prefixed(&mut out, &self.nonce);
        push_len_prefixed(&mut out, &self.delegation_id);
        push_len_prefixed(&mut out, &self.request_digest);
        push_len_prefixed(&mut out, &self.action);
        out.extend_from_slice(&self.amount.to_be_bytes());
        out
    }
}

/// Verify the principal's approval of the request the relying party is about
/// to perform, and spend its nonce.
///
/// Checks the delegation itself first, the same way [`crate::authorise`]
/// does: genuine, live now, at this audience, from a principal in
/// `principals`, with neither key in `revoked`. An approval that arrives after
/// the delegation expired or a key was revoked is refused, even if
/// `authorise` passed earlier.
///
/// Then the approval: signed by the delegation's principal under
/// [`AUTH_APPROVAL_V1`], at this audience, inside its window, naming this
/// delegation, `request_digest`, `action` and `amount` exactly, with an unspent
/// nonce. The relying party computes all three request values from the request
/// it received, never from the client.
#[allow(clippy::too_many_arguments)]
pub async fn check_approval<R: RevokedKeys + ?Sized, N: NonceStore>(
    delegation: &Delegation,
    approval: &Approval,
    params: VerifyParams<'_>,
    principals: &[Vec<u8>],
    revoked: &R,
    request_digest: &[u8; 32],
    action: &[u8],
    amount: u128,
    nonces: &N,
) -> Result<(), AuthError> {
    if !principals.contains(&delegation.principal_key) {
        return Err(AuthError::NotAuthorised);
    }
    if revoked.is_revoked(&delegation.principal_key) || revoked.is_revoked(&delegation.delegate_key)
    {
        return Err(AuthError::Revoked);
    }
    verify_delegation(delegation, params.expected_audience, params.now)?;

    if approval.principal_key.is_empty() || approval.signature.is_empty() {
        return Err(AuthError::Malformed);
    }
    if approval.principal_key != delegation.principal_key {
        return Err(AuthError::NotAuthorised);
    }
    check_envelope(
        &approval.audience,
        approval.issued_at,
        approval.expires_at,
        &params,
    )?;

    // Before the signature: is this an approval of what is about to happen?
    let same_request = approval.delegation_id.ct_eq(&delegation.id())
        & approval.request_digest.ct_eq(request_digest);
    if !bool::from(same_request) || approval.action != action || approval.amount != amount {
        return Err(AuthError::ActionMismatch);
    }

    let verified = verify_with_purpose(
        &approval.principal_key,
        AUTH_APPROVAL_V1,
        &approval.signing_input(),
        &approval.signature,
    )
    .map_err(|_| AuthError::Malformed)?;
    if !verified {
        return Err(AuthError::BadSignature);
    }

    claim_nonce(
        nonces,
        AUTH_APPROVAL_V1,
        &approval.principal_key,
        &approval.nonce,
        approval.issued_at,
        approval.expires_at,
    )
    .await
}
