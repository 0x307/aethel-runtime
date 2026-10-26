//! The login proof: one round trip, asserted by the client.
//!
//! The holder builds the whole thing itself — its own nonce, its own validity
//! window, the audience it intends — signs it under
//! [`AUTH_LOGIN_V1`], and sends it once. There
//! is no server-issued challenge to fetch first.
//!
//! # One proof per request
//!
//! An agent presents this on each request and keeps no session.
//!
//! The format reserves one optional field, [`LoginProof::session_commitment`],
//! for a later flow in which a person proves once and a session carries them
//! afterwards. This release has no session flow: the holder never sets the
//! field, and the verifier passes whatever a proof carries through to
//! [`AuthenticatedIdentity`] without acting on it. Reserving it now means the
//! session flow, if it ships, does not change what an agent signs.
//!
//! # Binding a proof to one request
//!
//! A proof without a request digest says "this key, at this audience, in this
//! window". Anyone who sees it before the nonce is claimed (a proxy that
//! terminates TLS, a gateway, a log) can attach it to a different request at
//! the same audience. [`LoginProof::request_digest`] closes that: the holder
//! signs a digest of the request, and [`verify_login_for_request`] refuses the
//! proof unless the relying party's own digest of the request it received
//! matches. The relying party defines what the digest covers, the way it does
//! for a step-up's `action_digest`; the README gives a recommended form.
//!
//! A proof that carries a digest is refused by plain [`verify_login`], with
//! [`AuthError::RequestDigestNotChecked`]. The holder asked for the binding,
//! and a verifier that ignored it would be accepting the proof for any
//! request.
//!
//! # What the client controls, and what that costs
//!
//! Because the client picks the nonce and the window, two things follow, and
//! both are enforced here rather than left to the caller:
//!
//! - **The client's clock is an input to validate, never a fact to trust.** A
//!   skewed or hostile clock would otherwise mint proofs valid arbitrarily far
//!   into the future. The verifier clamps with its own `max_age_secs`.
//! - **Replay protection lives entirely in the nonce store.** See
//!   [`crate::nonce`], which says what that demands of a deployment.

use aethel_core::signing::verify_with_purpose;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

use crate::error::AuthError;
use crate::nonce::NonceStore;
use crate::purposes::{AUTH_LOGIN_V1, AUTH_STEP_UP_V1};
use subtle::ConstantTimeEq;

/// How firmly an identity was established.
///
/// Deliberately the same two values SAGP already uses, so it can adopt this
/// crate without migrating its call sites or its policy checks.
///
/// Note what this does *not* encode: how recently. A proof verified three
/// hours ago and one verified a second ago are both `Proven`. "Recently enough
/// for this particular action" is a step-up question, answered by a separate
/// proof, because collapsing the two would make them indistinguishable
/// exactly where the difference matters.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthStrength {
    /// Cryptographically proven.
    Proven,
    /// Asserted but not proven. Must not be permitted to spend.
    Claimed,
}

/// Which mechanism established the identity.
///
/// Non-exhaustive: further mechanisms may be added without a major release.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthMethod {
    /// An ML-DSA-65 login proof verified by this crate.
    LoginProof,
    /// A step-up: control re-proven for one specific action.
    StepUp,
}

/// The outcome of a successful verification.
///
/// Carries the public key rather than an account identifier: mapping a key to
/// an account is the relying party's job and needs its own directory, which
/// this crate deliberately does not own.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedIdentity {
    /// The ML-DSA-65 public key that signed the proof.
    #[cfg_attr(feature = "serde", serde(with = "crate::b64::bytes"))]
    pub public_key: Vec<u8>,
    /// The audience the proof was made for, as verified.
    #[cfg_attr(feature = "serde", serde(with = "crate::b64::bytes"))]
    pub audience: Vec<u8>,
    /// How firmly the identity was established.
    pub strength: AuthStrength,
    /// Which mechanism established it.
    pub method: AuthMethod,
    /// Copied from the proof. Reserved for a session flow this release does
    /// not have; `None` for every proof this crate's holder builds.
    #[cfg_attr(feature = "serde", serde(with = "crate::b64::opt_array32"))]
    pub session_commitment: Option<[u8; 32]>,
}

/// A client-asserted login proof.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginProof {
    /// ML-DSA-65 public key, 1,952 bytes.
    #[cfg_attr(feature = "serde", serde(with = "crate::b64::bytes"))]
    pub public_key: Vec<u8>,
    /// The relying party this proof is for. Its stable origin, and the thing
    /// that stops a proof made for one service authenticating at another.
    #[cfg_attr(feature = "serde", serde(with = "crate::b64::bytes"))]
    pub audience: Vec<u8>,
    /// 256 bits, from the holder's own CSPRNG. Never reused.
    #[cfg_attr(feature = "serde", serde(with = "crate::b64::array32"))]
    pub nonce: [u8; 32],
    /// Unix seconds, per the holder's clock.
    pub issued_at: u64,
    /// Unix seconds, per the holder's clock.
    pub expires_at: u64,
    /// Reserved: `SHAKE-256` of a session secret, for a session flow this
    /// release does not have. `None` for an agent that re-proves per request,
    /// which is every proof this crate's holder builds.
    ///
    /// It is signed when present, so a commitment rather than a secret: the
    /// signed bytes may be logged.
    #[cfg_attr(feature = "serde", serde(with = "crate::b64::opt_array32"))]
    pub session_commitment: Option<[u8; 32]>,
    /// Optional: a digest of the one request this proof is for.
    ///
    /// The crate does not interpret it. The relying party defines what it
    /// covers (the README recommends method, path and a hash of the body) and
    /// computes it from the request it actually received, never from a value
    /// the client sent. Check it with [`verify_login_for_request`]; plain
    /// [`verify_login`] refuses a proof that carries one.
    ///
    /// Signed only when present. A `None` digest adds nothing to
    /// [`LoginProof::signing_input`] and nothing to the JSON, so a proof made
    /// before this field existed has the same bytes and still verifies.
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "crate::b64::opt_array32"
        )
    )]
    pub request_digest: Option<[u8; 32]>,
    /// ML-DSA-65 signature over [`LoginProof::signing_input`], made under
    /// `AUTH_LOGIN_V1`.
    #[cfg_attr(feature = "serde", serde(with = "crate::b64::bytes"))]
    pub signature: Vec<u8>,
}

/// Append `bytes` prefixed with its length.
///
/// Every variable-length field is framed this way. Concatenating with a
/// delimiter instead would mean a field *containing* that delimiter could make
/// two different proofs encode to identical bytes, so one signature would
/// verify for both. With `audience` holding a URL, that is not hypothetical.
pub(crate) fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

impl LoginProof {
    /// The exact bytes the signature covers.
    ///
    /// The public key is not included: ML-DSA verification already binds the
    /// key, since the signature is checked *against* it. Adding 1,952 bytes to
    /// every signed message would buy nothing.
    pub fn signing_input(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96 + self.audience.len());
        push_len_prefixed(&mut out, &self.audience);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        push_len_prefixed(&mut out, &self.nonce);
        // An absent commitment encodes as length 0 and a present one as
        // length 32, so the two are distinguishable rather than merely
        // different-looking.
        match &self.session_commitment {
            Some(c) => push_len_prefixed(&mut out, c),
            None => push_len_prefixed(&mut out, &[]),
        }
        // Appended only when present, unlike the commitment above, so that a
        // proof without one keeps the exact bytes it had before the field
        // existed. Still unambiguous: every earlier field is fixed-size or
        // length-prefixed, so the total length says whether a digest follows.
        if let Some(d) = &self.request_digest {
            push_len_prefixed(&mut out, d);
        }
        out
    }
}

/// `SHAKE-256(input)`, 32 bytes. The commitment and hashing scheme used
/// throughout this crate, and the same hash `aethel-core` uses.
pub(crate) fn shake256_32(input: &[u8]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut xof = hasher.finalize_xof();
    let mut out = [0u8; 32];
    xof.read(&mut out);
    out
}

/// The checks every client-asserted proof shares: right audience, sane clock,
/// not expired.
///
/// Shared between login and step-up so the two cannot drift. A step-up that
/// enforced the window differently from a login would be a gap nobody meant to
/// leave, and the only reliable way to avoid that is for there to be one
/// implementation.
pub(crate) fn check_envelope(
    audience: &[u8],
    issued_at: u64,
    expires_at: u64,
    params: &VerifyParams<'_>,
) -> Result<(), AuthError> {
    if audience.is_empty() {
        return Err(AuthError::Malformed);
    }
    if audience != params.expected_audience {
        return Err(AuthError::AudienceMismatch);
    }

    // Both directions. A proof from the future is as much a reason to refuse
    // as a stale one, and treating only staleness as suspicious would let a
    // fast-running clock buy unbounded validity.
    if issued_at > params.now {
        return Err(AuthError::StaleOrFutureProof);
    }
    if params.now.saturating_sub(issued_at) > params.max_age_secs {
        return Err(AuthError::StaleOrFutureProof);
    }
    if expires_at <= params.now {
        return Err(AuthError::Expired);
    }
    Ok(())
}

/// How long a nonce store must remember a claimed nonce.
///
/// A proof is accepted only while it is unexpired **and** no older than
/// `max_age_secs`, so the nonce has to be remembered until the earlier of the
/// two, and no longer. Using `expires_at` alone would let a holder that picked
/// a far-future expiry keep a store entry alive indefinitely. The `+ 1` covers
/// the last second at which [`check_envelope`] still accepts the proof.
pub(crate) fn nonce_retention(issued_at: u64, expires_at: u64, params: &VerifyParams<'_>) -> u64 {
    expires_at.min(
        issued_at
            .saturating_add(params.max_age_secs)
            .saturating_add(1),
    )
}

/// A short, human-comparable name for a public key.
///
/// An ML-DSA-65 public key is 1,952 bytes, which is 3,904 hex characters. A
/// person cannot read that off a screen, compare two of them, or dictate one
/// over a phone, and a tool that prints it in full has told them nothing they
/// can act on.
///
/// This is `SHAKE-256(key)` truncated to 8 bytes and grouped, so it fits on a
/// line and a mismatch is visible at a glance. 64 bits is ample for comparing
/// two values someone already holds; it is **not** an identifier to look a key
/// up by, and a caller must never treat a matching fingerprint as proof that
/// two keys are equal. Compare the keys for that.
pub fn key_fingerprint(public_key: &[u8]) -> String {
    let d = shake256_32(public_key);
    d[..8]
        .chunks(2)
        .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
        .collect::<Vec<_>>()
        .join("-")
}

/// What the verifier brings to the check.
///
/// `Copy`, because the first consumer to integrate hit this immediately: a
/// caller that passes `params` to `verify_login` and then wants `params.now`
/// for its own bookkeeping had to clone or re-read it. Three small fields,
/// nothing owned, so there is no reason to make that awkward.
#[derive(Debug, Clone, Copy)]
pub struct VerifyParams<'a> {
    /// The relying party's own stable origin. Compared against the proof's.
    pub expected_audience: &'a [u8],
    /// The verifier's clock, unix seconds. Injected rather than read here, so
    /// expiry is testable and the crate holds no hidden dependency on the
    /// system clock.
    pub now: u64,
    /// How far back the verifier will accept an `issued_at`. This is the
    /// clamp on a client-chosen window: without it a holder could mint a proof
    /// valid for a year.
    pub max_age_secs: u64,
}

/// Verify a login proof and spend its nonce.
///
/// # Order of checks, and why
///
/// Audience and clock first: they are free, they need no I/O, and they reject
/// the overwhelming majority of bad input.
///
/// The signature next. It costs real CPU, so it sits behind the free checks.
///
/// The nonce claim **last**, after the signature has verified. That ordering
/// is deliberate and is the opposite of what a server-issued challenge wants.
/// Claiming first would let an unauthenticated party write into the nonce
/// store at will, which is a denial-of-service surface with no upside: a
/// replayed proof still fails, just at the claim instead of before it.
///
/// # A proof bound to a request is refused here
///
/// If the proof carries a [`LoginProof::request_digest`], this returns
/// [`AuthError::RequestDigestNotChecked`] without checking the signature or
/// claiming the nonce. Use [`verify_login_for_request`] for those.
pub async fn verify_login<N: NonceStore>(
    proof: &LoginProof,
    params: VerifyParams<'_>,
    nonces: &N,
) -> Result<AuthenticatedIdentity, AuthError> {
    verify_login_inner(proof, params, None, nonces).await
}

/// Verify a login proof that is bound to one request, and spend its nonce.
///
/// `expected_request_digest` is the relying party's own digest of the request
/// it received, computed the same way the holder computed it. It must never
/// be a value the client supplied: comparing the proof's digest with a digest
/// the client also chose checks nothing.
///
/// The proof must carry a digest, and it must match. A proof with no digest
/// is refused with [`AuthError::RequestMismatch`], the same as a wrong one,
/// because an unbound proof is exactly what this check exists to rule out.
/// Otherwise the checks and their order are those of [`verify_login`], with
/// the digest compared, in constant time, before the signature.
pub async fn verify_login_for_request<N: NonceStore>(
    proof: &LoginProof,
    params: VerifyParams<'_>,
    expected_request_digest: &[u8; 32],
    nonces: &N,
) -> Result<AuthenticatedIdentity, AuthError> {
    verify_login_inner(proof, params, Some(expected_request_digest), nonces).await
}

/// One implementation for both entry points, so the bound and unbound checks
/// cannot drift apart.
async fn verify_login_inner<N: NonceStore>(
    proof: &LoginProof,
    params: VerifyParams<'_>,
    expected_request_digest: Option<&[u8; 32]>,
    nonces: &N,
) -> Result<AuthenticatedIdentity, AuthError> {
    if proof.public_key.is_empty() || proof.signature.is_empty() {
        return Err(AuthError::Malformed);
    }
    check_envelope(&proof.audience, proof.issued_at, proof.expires_at, &params)?;

    // Free checks, so before the signature. Constant-time for the same reason
    // as the step-up's action digest: not secret, but on a path an attacker
    // drives, and there is no reason to leak a prefix match.
    match (expected_request_digest, &proof.request_digest) {
        (None, None) => {}
        (None, Some(_)) => return Err(AuthError::RequestDigestNotChecked),
        (Some(_), None) => return Err(AuthError::RequestMismatch),
        (Some(expected), Some(signed)) => {
            if !bool::from(signed.ct_eq(expected)) {
                return Err(AuthError::RequestMismatch);
            }
        }
    }

    let verified = verify_with_purpose(
        &proof.public_key,
        AUTH_LOGIN_V1,
        &proof.signing_input(),
        &proof.signature,
    )
    .map_err(|_| AuthError::Malformed)?;

    if !verified {
        return Err(AuthError::BadSignature);
    }

    if !nonces
        .claim(
            &proof.nonce,
            nonce_retention(proof.issued_at, proof.expires_at, &params),
        )
        .await?
    {
        return Err(AuthError::NonceAlreadyUsed);
    }

    Ok(AuthenticatedIdentity {
        public_key: proof.public_key.clone(),
        audience: proof.audience.clone(),
        strength: AuthStrength::Proven,
        method: AuthMethod::LoginProof,
        session_commitment: proof.session_commitment,
    })
}

// ── Step-up ──────────────────────────────────────────────────────────────────

/// A re-proof of control, bound to one specific action.
///
/// A session says "this is the same browser as before". A step-up says "the
/// holder is present *right now*, and consents to *this*". They are different
/// claims, and the cheap one must never be allowed to stand in for the other.
///
/// The shape is deliberately the same as [`LoginProof`] with one field added,
/// so both go through the same envelope checks and cannot drift apart.
///
/// # Forward compatibility with predicates
///
/// When the predicate subsystem exists, the natural thing to want here is
/// "prove you are under your cap" instead of disclosing the cap. That is
/// additive: the encoding is length-prefixed, so a later `AUTH_STEP_UP_V2`
/// can carry a predicate proof alongside `action_digest` without disturbing
/// anything. Nothing is reserved for it now, because a field nobody fills is
/// a field nobody maintains.
///
/// It is **not** buildable today for a reason worth recording: the range-proof
/// spike commits the value slot itself, so `v_0` is whatever the prover put
/// there. A predicate over a self-chosen bound proves that the holder chose a
/// number, which is not a claim worth checking. Binding the value to an
/// issuer-attested attribute is the prerequisite.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepUpProof {
    /// ML-DSA-65 public key of whoever is consenting. For approving a
    /// delegated request above its threshold, that is the delegation's
    /// **principal**, not the agent that logged in; see
    /// [`crate::check_approval`].
    #[cfg_attr(feature = "serde", serde(with = "crate::b64::bytes"))]
    pub public_key: Vec<u8>,
    /// The relying party this step-up is for.
    #[cfg_attr(feature = "serde", serde(with = "crate::b64::bytes"))]
    pub audience: Vec<u8>,
    /// 256 bits, fresh, never reused.
    #[cfg_attr(feature = "serde", serde(with = "crate::b64::array32"))]
    pub nonce: [u8; 32],
    /// Unix seconds, per the holder's clock.
    pub issued_at: u64,
    /// Unix seconds, per the holder's clock.
    pub expires_at: u64,
    /// A digest of the action being consented to.
    ///
    /// The crate does not interpret this: only the relying party knows what
    /// "transfer 500 to X" serialises to. What matters is that it is **bound
    /// into the signature**, so a step-up granted for one action cannot be
    /// presented for another.
    #[cfg_attr(feature = "serde", serde(with = "crate::b64::array32"))]
    pub action_digest: [u8; 32],
    /// ML-DSA-65 signature over [`StepUpProof::signing_input`], under
    /// `AUTH_STEP_UP_V1`.
    #[cfg_attr(feature = "serde", serde(with = "crate::b64::bytes"))]
    pub signature: Vec<u8>,
}

impl StepUpProof {
    /// The exact bytes the signature covers.
    pub fn signing_input(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128 + self.audience.len());
        push_len_prefixed(&mut out, &self.audience);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        push_len_prefixed(&mut out, &self.nonce);
        push_len_prefixed(&mut out, &self.action_digest);
        out
    }
}

/// Verify a step-up against the action it claims to authorise.
///
/// `expected_action_digest` is what the *server* believes is about to happen,
/// computed from its own view of the request. Comparing it against the signed
/// one is the whole point: a holder who signed for a different action, or a
/// caller who swapped the action after the signature, is refused.
pub async fn verify_step_up<N: NonceStore>(
    proof: &StepUpProof,
    params: VerifyParams<'_>,
    expected_action_digest: &[u8; 32],
    nonces: &N,
) -> Result<AuthenticatedIdentity, AuthError> {
    if proof.public_key.is_empty() || proof.signature.is_empty() {
        return Err(AuthError::Malformed);
    }
    check_envelope(&proof.audience, proof.issued_at, proof.expires_at, &params)?;

    // Before spending CPU on a signature: is this even about the right action?
    // Constant-time because the digest is not secret but the comparison sits
    // on a path an attacker can drive, and there is no reason to leak a prefix
    // match for free.
    if !bool::from(proof.action_digest.ct_eq(expected_action_digest)) {
        return Err(AuthError::ActionMismatch);
    }

    let verified = verify_with_purpose(
        &proof.public_key,
        AUTH_STEP_UP_V1,
        &proof.signing_input(),
        &proof.signature,
    )
    .map_err(|_| AuthError::Malformed)?;

    if !verified {
        return Err(AuthError::BadSignature);
    }

    if !nonces
        .claim(
            &proof.nonce,
            nonce_retention(proof.issued_at, proof.expires_at, &params),
        )
        .await?
    {
        return Err(AuthError::NonceAlreadyUsed);
    }

    Ok(AuthenticatedIdentity {
        public_key: proof.public_key.clone(),
        audience: proof.audience.clone(),
        strength: AuthStrength::Proven,
        method: AuthMethod::StepUp,
        session_commitment: None,
    })
}
