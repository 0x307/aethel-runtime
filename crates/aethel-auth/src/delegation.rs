//! Delegation: a principal grants a delegate bounded authority to act.
//!
//! This is the generalisation of `aethel-vault`'s `SpendPolicy` beyond money.
//! The vault's shapes map across directly, which is deliberate rather than
//! coincidental, so an agent can hold a standing spend policy *inside* a
//! delegation and the two compose instead of colliding:
//!
//! | Vault | Here |
//! |---|---|
//! | `allow_rails` | [`Bounds::actions`] |
//! | `max_per_call` | [`Bounds::max_per_invocation`] |
//! | `daily_cap` | [`Bounds::max_total`] with [`Bounds::window_secs`] |
//! | `hitl_above` | [`Bounds::approval_required_above`] |
//!
//! # Statement here, enforcement there
//!
//! The same split as revocation. This crate checks that a delegation is
//! genuine, live, for this relying party, and that a proposed action falls
//! inside its *declared* scope. It cannot check a cumulative bound, because
//! "how much has been spent today" is state only the relying party holds.
//!
//! [`authorise`] therefore returns what the caller still has to enforce,
//! rather than silently returning `Ok` and letting a cap go unchecked.
//!
//! # Every party needs a per-relying-party identity
//!
//! A delegation names **both** a principal and a delegate. If an agent used
//! one identity everywhere, the delegations held at each relying party would
//! share that delegate key, and anyone seeing two of them could join the agent
//! across services. That is the correlating identifier the whole design
//! forbids, arriving through a side door.
//!
//! So D4 is a rule about every party to a statement, not only about people.
//! The `audience` field is what enforces it here: a delegation is valid at one
//! relying party and nowhere else, so there is deliberately no way to express
//! "this one delegation, everywhere". That object would be a cross-verifier
//! correlator by construction.
//!
//! # Ending a delegation
//!
//! A delegation ends at `expires_at`, or when the relying party stops
//! honouring one of its two keys. This release has no statement that revokes
//! one delegation and leaves the principal's others standing. A principal
//! ends its delegates' authority at a relying party by revoking **its own**
//! key there (`Holder::revoke_self`, behind the `holder` feature), which ends
//! every delegation it issued at that relying party.
//!
//! So a relying party must refuse a delegation whose `principal_key` or
//! `delegate_key` it has seen a verified revocation for. [`authorise`] cannot
//! check that, because the set of revoked keys is the relying party's state.
//! [`Delegation::id`] gives it a stable key to track a delegation by, for that
//! and for the running total.
//!
//! # No sub-delegation
//!
//! A delegate cannot re-delegate. Not an oversight: each hop multiplies the
//! correlation surface and makes revocation a graph problem rather than a
//! lookup. If a chain is ever wanted, it should be designed on purpose.

use aethel_core::signing::verify_with_purpose;

use crate::error::AuthError;
use crate::proof::{push_len_prefixed, shake256_32, AuthMethod, AuthenticatedIdentity};
use crate::purposes::AUTH_DELEGATION_V1;

/// What a delegate is permitted to do.
///
/// Every field is a *ceiling*. An empty or `None` field grants nothing rather
/// than everything: a delegation that failed to say what it allowed should
/// authorise nothing, not all of it.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Bounds {
    /// Allow-list of action tags. Empty means no action is permitted.
    ///
    /// The crate does not interpret a tag; only the relying party knows what
    /// `b"transfer"` means. It only checks membership.
    #[cfg_attr(feature = "serde", serde(with = "crate::b64::vec_bytes"))]
    pub actions: Vec<Vec<u8>>,
    /// Ceiling on any single invocation. `None` means no single-invocation
    /// ceiling was set, which a caller passing an amount must treat as a
    /// refusal rather than as permission.
    pub max_per_invocation: Option<u128>,
    /// Ceiling on the sum over [`Bounds::window_secs`]. **Enforced by the
    /// relying party**, which is the only party holding the running total.
    pub max_total: Option<u128>,
    /// The window `max_total` applies over.
    pub window_secs: Option<u64>,
    /// Above this, the relying party must obtain a human approval before
    /// proceeding. The vault's `hitl_above`, generalised.
    pub approval_required_above: Option<u128>,
}

/// A signed grant of bounded authority.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    /// The granting identity's ML-DSA-65 public key, at this relying party.
    #[cfg_attr(feature = "serde", serde(with = "crate::b64::bytes"))]
    pub principal_key: Vec<u8>,
    /// The receiving identity's ML-DSA-65 public key, at this relying party.
    #[cfg_attr(feature = "serde", serde(with = "crate::b64::bytes"))]
    pub delegate_key: Vec<u8>,
    /// The relying party this delegation is valid at, and only there.
    #[cfg_attr(feature = "serde", serde(with = "crate::b64::bytes"))]
    pub audience: Vec<u8>,
    /// What the delegate may do.
    pub bounds: Bounds,
    /// Unix seconds. Not valid before this.
    pub not_before: u64,
    /// Unix seconds. Not valid at or after this.
    pub expires_at: u64,
    /// ML-DSA-65 signature by the **principal**, under `AUTH_DELEGATION_V1`.
    #[cfg_attr(feature = "serde", serde(with = "crate::b64::bytes"))]
    pub signature: Vec<u8>,
}

impl Delegation {
    /// The exact bytes the principal's signature covers.
    ///
    /// The delegate key *is* included, unlike the signer's own key in a login
    /// proof: it is not the key being verified against, so nothing else binds
    /// it, and an unbound delegate field would let anyone substitute
    /// themselves as the recipient.
    pub fn signing_input(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256 + self.audience.len());
        push_len_prefixed(&mut out, &self.delegate_key);
        push_len_prefixed(&mut out, &self.audience);
        out.extend_from_slice(&self.not_before.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());

        // Count-prefixed, then each entry length-prefixed, so an action list
        // cannot be re-split into a different list with the same bytes.
        out.extend_from_slice(&(self.bounds.actions.len() as u32).to_be_bytes());
        for action in &self.bounds.actions {
            push_len_prefixed(&mut out, action);
        }

        // `None` and `Some(0)` must not encode alike: one grants nothing, the
        // other sets a ceiling of zero, and a holder should be able to tell a
        // verifier which they meant.
        for field in [
            self.bounds.max_per_invocation,
            self.bounds.max_total,
            self.bounds.approval_required_above,
        ] {
            match field {
                Some(v) => {
                    out.push(1);
                    out.extend_from_slice(&v.to_be_bytes());
                }
                None => out.push(0),
            }
        }
        match self.bounds.window_secs {
            Some(v) => {
                out.push(1);
                out.extend_from_slice(&v.to_be_bytes());
            }
            None => out.push(0),
        }

        out
    }

    /// A stable 32-byte identifier for this delegation, for a relying party's
    /// own bookkeeping: the running total over `window_secs`, and refusing a
    /// delegation once either of its keys is revoked.
    ///
    /// `SHAKE-256` over a domain label, the principal key, the signed bytes and
    /// the signature, each length-prefixed. So it is one id per distinct
    /// signed statement.
    ///
    /// # What it is stable over, and what changes it
    ///
    /// The id depends on the principal key, every signed field (delegate key,
    /// audience, every bound, `not_before`, `expires_at`) and the signature
    /// bytes. It does not depend on the JSON spelling, and it does not change
    /// when the same delegation is read, stored or sent again.
    ///
    /// Signing is deterministic: `aethel-core` signs ML-DSA-65 without
    /// randomness, and so does `Holder::delegate_to`. So the
    /// same principal signing **identical terms twice gets the same signature
    /// and the same id**, and the two grants share one running total. That
    /// fails safe: it gives less budget, never more. A principal who wants a
    /// separate budget must change a signed term, for example `not_before`.
    ///
    /// A delegation signed elsewhere with a randomised ML-DSA signer has a
    /// different signature for the same terms, and so a different id. Do not
    /// rely on equal terms meaning an equal id unless you know how it was
    /// signed.
    ///
    /// Not a cross-relying-party identifier: a delegation is valid at one
    /// audience, and so is its id. Do not publish it anywhere that audience
    /// is not.
    pub fn id(&self) -> [u8; 32] {
        let mut input = Vec::with_capacity(5_600 + self.audience.len());
        push_len_prefixed(&mut input, b"aethel-auth/delegation-id/v1");
        push_len_prefixed(&mut input, &self.principal_key);
        push_len_prefixed(&mut input, &self.signing_input());
        push_len_prefixed(&mut input, &self.signature);
        shake256_32(&input)
    }
}

/// What the relying party must still enforce after [`authorise`] succeeds.
///
/// Three things only the relying party can do, because only it holds the
/// state: keep the running total, obtain the principal's approval, and refuse
/// a delegation whose keys it has seen revoked (see "Ending a delegation" in
/// this module's docs).
///
/// Returned rather than checked, because this crate holds no running totals
/// and cannot ask a human. Returning it makes the remaining obligation
/// explicit at the call site instead of leaving a cap silently unchecked.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemainingObligations {
    /// Keep a running total for this delegate and refuse once it would exceed
    /// this over `window_secs`.
    pub cumulative_ceiling: Option<u128>,
    /// The window the ceiling applies over.
    pub window_secs: Option<u64>,
    /// This invocation is above the principal's approval threshold. Do not
    /// proceed until the **principal** has signed a step-up for this action.
    ///
    /// Verify that step-up with [`crate::verify_step_up`], then pass the
    /// result to [`check_approval`]. The step-up must come from the
    /// delegation's `principal_key`: a step-up from the delegate is the agent
    /// approving itself, and `verify_step_up` alone does not know which key
    /// it should be.
    pub human_approval_required: bool,
}

impl RemainingObligations {
    /// Whether the caller can proceed with no further checks of its own.
    pub fn is_clear(&self) -> bool {
        self.cumulative_ceiling.is_none() && !self.human_approval_required
    }
}

/// Check that a delegation is genuine, live, and for this relying party.
///
/// Verifies the principal's signature over the whole statement, including the
/// delegate key and every bound, so nothing in it can be altered after signing.
pub fn verify_delegation(
    delegation: &Delegation,
    expected_audience: &[u8],
    now: u64,
) -> Result<(), AuthError> {
    if delegation.principal_key.is_empty()
        || delegation.delegate_key.is_empty()
        || delegation.signature.is_empty()
        || delegation.audience.is_empty()
    {
        return Err(AuthError::Malformed);
    }

    if delegation.audience != expected_audience {
        return Err(AuthError::AudienceMismatch);
    }

    if now < delegation.not_before || now >= delegation.expires_at {
        return Err(AuthError::Expired);
    }

    let verified = verify_with_purpose(
        &delegation.principal_key,
        AUTH_DELEGATION_V1,
        &delegation.signing_input(),
        &delegation.signature,
    )
    .map_err(|_| AuthError::Malformed)?;

    if !verified {
        return Err(AuthError::BadSignature);
    }

    Ok(())
}

/// Decide whether a delegation authorises a specific attempt.
///
/// `delegate_key` is the identity that actually presented a proof, which the
/// caller has already authenticated. Checking it against the delegation is
/// what stops a valid delegation being used by someone it was not issued to.
///
/// `amount` is `None` for an action carrying no quantity.
pub fn authorise(
    delegation: &Delegation,
    expected_audience: &[u8],
    delegate_key: &[u8],
    action: &[u8],
    amount: Option<u128>,
    now: u64,
) -> Result<RemainingObligations, AuthError> {
    verify_delegation(delegation, expected_audience, now)?;

    if delegation.delegate_key != delegate_key {
        return Err(AuthError::NotDelegated);
    }

    if !delegation.bounds.actions.iter().any(|a| a == action) {
        return Err(AuthError::NotDelegated);
    }

    if let Some(amount) = amount {
        // An amount against a delegation that set no per-invocation ceiling is
        // refused. The alternative reading, that an absent ceiling means
        // unlimited, turns a forgetful principal into an unbounded one.
        match delegation.bounds.max_per_invocation {
            Some(ceiling) if amount <= ceiling => {}
            _ => return Err(AuthError::NotDelegated),
        }
    }

    let human_approval_required = match (amount, delegation.bounds.approval_required_above) {
        (Some(amount), Some(threshold)) => amount > threshold,
        _ => false,
    };

    Ok(RemainingObligations {
        cumulative_ceiling: delegation.bounds.max_total,
        window_secs: delegation.bounds.window_secs,
        human_approval_required,
    })
}

/// Check that a verified step-up approves a request under this delegation.
///
/// `approval` is what [`crate::verify_step_up`] returned for the step-up the
/// relying party asked for, with the action digest of the request being
/// approved. This adds the check that call cannot make: the step-up was
/// signed by the delegation's **principal**, at the delegation's audience.
///
/// Refuses a step-up from the delegate (the agent approving its own request),
/// from any other key, and anything established by a mechanism other than a
/// step-up, such as a login proof.
pub fn check_approval(
    delegation: &Delegation,
    approval: &AuthenticatedIdentity,
) -> Result<(), AuthError> {
    if approval.method != AuthMethod::StepUp {
        return Err(AuthError::NotAuthorised);
    }
    if approval.audience != delegation.audience {
        return Err(AuthError::AudienceMismatch);
    }
    if approval.public_key != delegation.principal_key {
        return Err(AuthError::NotAuthorised);
    }
    Ok(())
}
