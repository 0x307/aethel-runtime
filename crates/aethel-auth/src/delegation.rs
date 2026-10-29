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
//! `delegate_key` it has seen a verified revocation for. The set of revoked
//! keys is the relying party's state, so [`authorise`] takes it as an input
//! ([`RevokedKeys`]) and refuses either key in it. A caller cannot reach
//! "authorised" without saying what it knows about revocation.
//! [`Delegation::id`] gives it a stable key to track a delegation by, for the
//! running total.
//!
//! # Whose delegation it is
//!
//! A delegation is signed by its own `principal_key`, so the signature proves
//! only that *some* key granted it. Anyone can make a key and delegate to an
//! agent. Which principals count at this relying party (the accounts it has
//! enrolled) is the relying party's state too, so [`authorise`] takes the set
//! it recognises and refuses any other, the way [`crate::verify_revocation`]
//! takes the authority keys it recognises.
//!
//! # No sub-delegation
//!
//! A delegate cannot re-delegate. Not an oversight: each hop multiplies the
//! correlation surface and makes revocation a graph problem rather than a
//! lookup. If a chain is ever wanted, it should be designed on purpose.

use aethel_core::signing::verify_with_purpose;

use crate::error::AuthError;
use crate::nonce::NonceStore;
use crate::proof::{push_len_prefixed, shake256_32, verify_step_up, StepUpProof, VerifyParams};
use crate::purposes::AUTH_DELEGATION_V1;

/// The keys this relying party has seen a verified revocation for.
///
/// [`authorise`] asks it about both keys of a delegation. Implemented for a
/// slice of keys, for `std`'s `HashSet` and `BTreeSet` of keys, and for any
/// `Fn(&[u8]) -> bool`, so a relying party can answer from its own store.
///
/// Keys are compared as decoded bytes. Never answer this by comparing keys as
/// text: a store keyed on one text spelling of a key misses the same key
/// spelled another way, which is how a revoked key came back on 2026-10-14.
///
/// A relying party that has never received a revocation passes an empty
/// slice, `&[] as &[Vec<u8>]`. That is a statement about its state, made at
/// the call, rather than a default nobody chose.
pub trait RevokedKeys {
    /// Whether `public_key` has been revoked at this relying party.
    fn is_revoked(&self, public_key: &[u8]) -> bool;
}

impl RevokedKeys for [Vec<u8>] {
    fn is_revoked(&self, public_key: &[u8]) -> bool {
        self.iter().any(|k| k == public_key)
    }
}

impl<F: Fn(&[u8]) -> bool> RevokedKeys for F {
    fn is_revoked(&self, public_key: &[u8]) -> bool {
        self(public_key)
    }
}

impl<S: core::hash::BuildHasher> RevokedKeys for std::collections::HashSet<Vec<u8>, S> {
    fn is_revoked(&self, public_key: &[u8]) -> bool {
        self.contains(public_key)
    }
}

impl RevokedKeys for std::collections::BTreeSet<Vec<u8>> {
    fn is_revoked(&self, public_key: &[u8]) -> bool {
        self.contains(public_key)
    }
}

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
/// Two things only the relying party can do: keep the running total, and
/// obtain the principal's approval. Revocation and the principal are not
/// here, because [`authorise`] has already checked both against what the
/// caller passed it.
///
/// Returned rather than checked, because this crate holds no running totals
/// and cannot ask a human. Returning it makes the remaining obligation
/// explicit at the call site instead of leaving a cap silently unchecked, and
/// `#[must_use]` makes ignoring it a warning.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "a delegation can leave a running total or an approval to the caller"]
pub struct RemainingObligations {
    /// Keep a running total for this delegate and refuse once it would exceed
    /// this over `window_secs`.
    pub cumulative_ceiling: Option<u128>,
    /// The window the ceiling applies over.
    pub window_secs: Option<u64>,
    /// This invocation is above the principal's approval threshold. Do not
    /// proceed until the **principal** has signed a step-up approving this
    /// request under this delegation, and [`check_approval`] has accepted it.
    pub human_approval_required: bool,
}

impl RemainingObligations {
    /// Whether the caller can proceed with no further checks of its own:
    /// there is no running total to keep and no approval to obtain.
    ///
    /// The principal and revocation checks are not the caller's here; they
    /// were inputs to [`authorise`], which refused on either.
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
/// - `principals` is the set of principal keys this relying party recognises:
///   the accounts it has enrolled, or the one account this request is for. A
///   delegation from any other key is refused with
///   [`AuthError::NotAuthorised`], however well it is signed. An empty set
///   recognises nobody.
/// - `revoked` is what this relying party knows about revocation. A
///   delegation whose principal or delegate key is in it is refused with
///   [`AuthError::Revoked`].
/// - `delegate_key` is the identity that actually presented a proof, which the
///   caller has already authenticated. Checking it against the delegation is
///   what stops a valid delegation being used by someone it was not issued to.
/// - `amount` is the quantity this attempt carries. `None` is accepted only
///   under a delegation that sets no amount bound at all (no
///   `max_per_invocation`, `max_total` or `approval_required_above`). Under a
///   delegation that sets one, `None` is refused, because "the caller did not
///   say" and "there is nothing to count" look the same here and only one of
///   them is safe. An action that carries no quantity under a bounded
///   delegation passes `Some(0)`, which says so.
#[allow(clippy::too_many_arguments)]
pub fn authorise<R: RevokedKeys + ?Sized>(
    delegation: &Delegation,
    expected_audience: &[u8],
    principals: &[Vec<u8>],
    revoked: &R,
    delegate_key: &[u8],
    action: &[u8],
    amount: Option<u128>,
    now: u64,
) -> Result<RemainingObligations, AuthError> {
    // Set membership before the signature: both are cheap, and the public
    // error is the same for every refusal, so the order tells a prober
    // nothing.
    if !principals.contains(&delegation.principal_key) {
        return Err(AuthError::NotAuthorised);
    }
    if revoked.is_revoked(&delegation.principal_key) || revoked.is_revoked(&delegation.delegate_key)
    {
        return Err(AuthError::Revoked);
    }

    verify_delegation(delegation, expected_audience, now)?;

    if delegation.delegate_key != delegate_key {
        return Err(AuthError::NotDelegated);
    }

    if !delegation.bounds.actions.iter().any(|a| a == action) {
        return Err(AuthError::NotDelegated);
    }

    let bounds = &delegation.bounds;
    let sets_an_amount_bound = bounds.max_per_invocation.is_some()
        || bounds.max_total.is_some()
        || bounds.approval_required_above.is_some();
    if amount.is_none() && sets_an_amount_bound {
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

/// The digest a principal signs, as a step-up's `action_digest`, to approve
/// one request under one delegation.
///
/// `SHAKE-256` over a domain label, [`Delegation::id`] and `request_digest`,
/// each length-prefixed. `request_digest` is the relying party's own digest
/// of the request being approved (its action, its amount and anything else it
/// relies on), computed from the request it received, never taken from the
/// client. Folding the delegation id in means an approval for a request under
/// one delegation does not approve a request under another.
///
/// The holder builds the step-up with `Holder::approve`, which calls this.
pub fn approval_digest(delegation: &Delegation, request_digest: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(96);
    push_len_prefixed(&mut input, b"aethel-auth/approval/v1");
    push_len_prefixed(&mut input, &delegation.id());
    push_len_prefixed(&mut input, request_digest);
    shake256_32(&input)
}

/// Verify the principal's approval of one request under this delegation, and
/// spend its nonce.
///
/// Verifies `step_up` itself rather than accepting the result of an earlier
/// verification. The step-up must be signed by the delegation's
/// **principal**, at the delegation's audience, over
/// [`approval_digest`]`(delegation, request_digest)`. So the approval names
/// this delegation and this request, and nothing short of the principal's
/// signature passes.
///
/// `request_digest` is computed by the relying party from the request it is
/// about to perform, the same way the holder computed it before signing.
///
/// Refuses a step-up from the delegate (the agent approving its own request)
/// or any other key, one for another request or another delegation, one for
/// another audience, and a replay. `params.expected_audience` must be the
/// delegation's audience.
pub async fn check_approval<N: NonceStore>(
    delegation: &Delegation,
    step_up: &StepUpProof,
    params: VerifyParams<'_>,
    request_digest: &[u8; 32],
    nonces: &N,
) -> Result<(), AuthError> {
    if params.expected_audience != delegation.audience.as_slice() {
        return Err(AuthError::AudienceMismatch);
    }
    if step_up.public_key != delegation.principal_key {
        return Err(AuthError::NotAuthorised);
    }
    let expected = approval_digest(delegation, request_digest);
    verify_step_up(step_up, params, &expected, nonces).await?;
    Ok(())
}
