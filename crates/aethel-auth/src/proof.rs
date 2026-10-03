//! The login proof: one round trip, asserted by the client.
//!
//! The holder builds the whole thing itself — its own nonce, its own validity
//! window, the audience it intends — signs it under
//! [`AUTH_LOGIN_V1`](crate::purposes::AUTH_LOGIN_V1), and sends it once. There
//! is no server-issued challenge to fetch first.
//!
//! # One proof, for agents and for people
//!
//! An agent presents this on each request and keeps no session. A person
//! presents it once, additionally committing to a session secret, and the
//! session carries them afterwards. Same wire format, same verification path;
//! the only difference is whether [`LoginProof::session_commitment`] is
//! present. A person is a slow agent, not a different protocol.
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
/// for this particular action" is a step-up question, tracked separately on
/// the session, because collapsing the two would make them indistinguishable
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    /// An ML-DSA-65 login proof verified by this crate.
    LoginProof,
    /// A session token presented after such a proof.
    Session,
    /// A step-up: control re-proven for one specific action.
    StepUp,
    /// An enrolment: first proof of possession against an invite.
    Enrolment,
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
    /// Present when the holder committed to a session secret, which is how
    /// the human flow asks for a session. Absent for an agent.
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
    /// `SHAKE-256` of the session secret the holder intends to use, when it
    /// wants a session. `None` for an agent that will re-prove per request.
    ///
    /// A commitment rather than the secret itself: the signed bytes may be
    /// logged, and the secret must not be recoverable from them.
    #[cfg_attr(feature = "serde", serde(with = "crate::b64::opt_array32"))]
    pub session_commitment: Option<[u8; 32]>,
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
/// for the session it opens had to clone or re-read it. Three small fields,
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
pub async fn verify_login<N: NonceStore>(
    proof: &LoginProof,
    params: VerifyParams<'_>,
    nonces: &N,
) -> Result<AuthenticatedIdentity, AuthError> {
    if proof.public_key.is_empty() || proof.signature.is_empty() {
        return Err(AuthError::Malformed);
    }
    check_envelope(&proof.audience, proof.issued_at, proof.expires_at, &params)?;

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

    if !nonces.claim(&proof.nonce, proof.expires_at).await? {
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
    /// ML-DSA-65 public key. The same per-relying-party identity that logged in.
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

    if !nonces.claim(&proof.nonce, proof.expires_at).await? {
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
