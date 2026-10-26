//! Failures, and the rule about what a caller may say out loud.

use core::fmt;

/// Why an authority check failed.
///
/// # Uniform outward, specific inward
///
/// These variants exist so a *server* can log precisely what went wrong. They
/// are not safe to return to the party that failed the check.
///
/// An endpoint that reports "unknown key" for one input and "bad signature"
/// for another is an oracle: a prober learns which public keys are enrolled
/// without holding any of them, and learns which of its guesses are
/// well-formed. [`AuthError::public_message`] exists so the outward path is
/// the easy one to write.
///
/// # Non-exhaustive
///
/// More variants will arrive with more statement types, so a downstream
/// `match` needs a wildcard arm. That arm should map to
/// [`AuthError::public_message`] like every other rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthError {
    /// The proof named a different relying party.
    AudienceMismatch,
    /// `issued_at` is in the future, or older than the verifier's max age.
    /// Covers both directions deliberately: a clock skewed either way is a
    /// reason to refuse, not to guess.
    StaleOrFutureProof,
    /// The proof's own expiry has passed.
    Expired,
    /// The signature did not verify under the expected purpose.
    BadSignature,
    /// The nonce had already been claimed. A replay, or an honest client that
    /// reused a value it should not have.
    NonceAlreadyUsed,
    /// A step-up was signed for a different action than the one being
    /// attempted, or the action was swapped after the holder consented.
    ActionMismatch,
    /// A login proof checked with `verify_login_for_request` had no request
    /// digest, or a digest of a different request.
    RequestMismatch,
    /// A login proof carried a request digest but was checked with plain
    /// `verify_login`, which cannot check it. Refused rather than accepted,
    /// because the holder asked for the proof to be good for one request only.
    RequestDigestNotChecked,
    /// A delegation did not authorise what the delegate attempted: wrong
    /// action, over a bound, outside its window, or not for this audience.
    NotDelegated,
    /// The signer was not entitled to make this statement: a holder revoking
    /// a key that is not theirs, or an unrecognised authority.
    NotAuthorised,
    /// The input could not be parsed at all.
    Malformed,
    /// The nonce store failed. Distinct from a rejection: the
    /// check did not complete, so nothing was decided.
    Store(StoreError),
}

impl AuthError {
    /// The only string that may cross back to the party that failed.
    ///
    /// Deliberately identical for every rejection. The one exception is
    /// [`AuthError::Store`], which is not a rejection at all: the check never
    /// reached a verdict, and a caller that reports it as a failed login is
    /// telling the user something untrue.
    pub fn public_message(&self) -> &'static str {
        match self {
            AuthError::Store(_) => "the request could not be processed",
            _ => "authentication failed",
        }
    }

    /// Whether this is a verdict about the request, or a failure to reach one.
    pub fn is_rejection(&self) -> bool {
        !matches!(self, AuthError::Store(_))
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::AudienceMismatch => write!(f, "proof is for a different audience"),
            AuthError::StaleOrFutureProof => write!(f, "proof issued outside the accepted window"),
            AuthError::Expired => write!(f, "proof has expired"),
            AuthError::BadSignature => {
                write!(f, "signature did not verify under the expected purpose")
            }
            AuthError::NonceAlreadyUsed => write!(f, "nonce has already been claimed"),
            AuthError::ActionMismatch => write!(f, "step-up was signed for a different action"),
            AuthError::RequestMismatch => {
                write!(f, "login proof is not bound to this request")
            }
            AuthError::RequestDigestNotChecked => {
                write!(
                    f,
                    "login proof is bound to a request, and was not checked as one"
                )
            }
            AuthError::NotDelegated => write!(f, "delegation does not authorise this"),
            AuthError::NotAuthorised => write!(f, "signer is not entitled to make this statement"),
            AuthError::Malformed => write!(f, "input could not be parsed"),
            AuthError::Store(e) => write!(f, "store failure: {e}"),
        }
    }
}

impl std::error::Error for AuthError {}

/// A store did not answer. The caller's own failure, not the client's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(pub String);

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for StoreError {}

impl From<StoreError> for AuthError {
    fn from(e: StoreError) -> Self {
        AuthError::Store(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every rejection must look the same from outside. If a new variant is
    /// added with its own outward text, a prober can tell it apart from the
    /// others, which is the whole thing this guards against.
    #[test]
    fn every_rejection_has_the_same_public_message() {
        let rejections = [
            AuthError::AudienceMismatch,
            AuthError::StaleOrFutureProof,
            AuthError::Expired,
            AuthError::BadSignature,
            AuthError::NonceAlreadyUsed,
            AuthError::ActionMismatch,
            AuthError::RequestMismatch,
            AuthError::RequestDigestNotChecked,
            AuthError::NotDelegated,
            AuthError::NotAuthorised,
            AuthError::Malformed,
        ];

        for e in &rejections {
            assert!(
                e.is_rejection(),
                "{e:?} should be a verdict about the request"
            );
            assert_eq!(
                e.public_message(),
                "authentication failed",
                "{e:?} leaks which check failed"
            );
        }
    }

    /// A store outage is not a failed login, and must not be reported as one.
    #[test]
    fn a_store_failure_is_not_a_rejection() {
        let e = AuthError::Store(StoreError("connection refused".into()));
        assert!(!e.is_rejection());
        assert_ne!(e.public_message(), "authentication failed");
    }
}
