//! The canonical request binding: what a session MAC actually covers.
//!
//! [`SessionSecret::mac`](crate::session::SessionSecret::mac) MACs whatever
//! bytes it is handed, because a crate cannot know what a request is. That
//! leaves the most dangerous decision in the protocol to each caller, and the
//! two most likely ways to get it wrong both fail silently:
//!
//! - **Omit a varying element** and every request MACs identically, so anyone
//!   who observes one can replay it for the life of the session.
//! - **Disagree between client and server by one byte** and nothing verifies,
//!   which at least fails closed, but fails closed *everywhere* and is
//!   miserable to diagnose across two languages.
//!
//! So the format is defined once, here, and the browser client mirrors it.
//! This module is the specification; `clients/browser-session/` is the other
//! implementation of it, and `tests/binding_cross_language.rs` proves they
//! agree by running the TypeScript and checking the result with this crate's
//! verifier rather than by two implementations agreeing with themselves.
//!
//! # The v1 layout
//!
//! `LP(x)` is `x` prefixed with its length as four big-endian bytes, the same
//! framing every signed structure in this crate uses. Integers are
//! big-endian and unprefixed because their width is fixed.
//!
//! ```text
//! LP("aethel-auth/session-binding/v1")   domain separation
//! LP(audience)                           the relying party
//! LP(method)                             uppercase ASCII, normalised
//! LP(path)                               exactly as sent, not normalised
//! LP(query)                              exactly as sent, without '?', may be empty
//! LP(sha256(body))                       32 bytes, of zero bytes when there is no body
//! u64 timestamp                          unix seconds, 8 bytes
//! LP(nonce)                              32 bytes from the client's CSPRNG
//! ```
//!
//! # Why each field is here
//!
//! **The domain separator** keeps these bytes from ever colliding with
//! another structure MACed under the same key. Nothing else uses this key
//! today; the separator costs 34 bytes and removes the question permanently.
//!
//! **The audience** stops a MAC made for one relying party verifying at
//! another. Under D4 a holder has a different identity per service, so this
//! is belt and braces, but the session secret is the one piece of key
//! material two services could conceivably be induced to share, and the cost
//! is nothing.
//!
//! **Method, path and query** are the request. Omitting any of them would let
//! an attacker who captured a `GET /profile` turn it into a
//! `DELETE /account`.
//!
//! **The body hash**, rather than the body, so the binding is a fixed size
//! regardless of payload. SHA-256 rather than SHAKE-256 for the same reason
//! the MAC is HMAC-SHA-256, per D8 and
//! [`SessionSecret::mac`](crate::session::SessionSecret::mac). A request with
//! no body hashes the empty string, which is a specific 32-byte value and not
//! 32 zero bytes.
//!
//! **The timestamp** bounds how long a captured request stays interesting,
//! and bounds how long the nonce store must remember anything.
//!
//! **The nonce** is what makes each request unique. This is the field whose
//! absence the replay attack depends on.
//!
//! # What is deliberately absent
//!
//! **The session token.** Binding it would add nothing: the MAC key *is* the
//! session secret, so a MAC made under one session cannot verify under
//! another. It would also force the browser to hash the token, and the stored
//! hash is SHAKE-256, which WebCrypto cannot compute.
//!
//! **Headers.** Nothing outside the list above is authenticated, and that is
//! a real limit rather than an oversight: an intermediary can alter a
//! `Content-Type` or an `Accept` and the MAC still verifies. A relying party
//! whose authorisation depends on a header must either put that decision
//! behind a step-up or extend this format to v2 on both sides at once.
//!
//! # Normalisation, and where it stops
//!
//! The method is uppercased by both implementations, so a client sending
//! `get` and a server seeing `GET` still agree. Nothing else is normalised.
//!
//! Path and query are bound **exactly as transmitted**. This is the one place
//! a deployment can surprise itself: a proxy that rewrites `//a` to `/a`, or
//! decodes `%2F`, changes the bytes the server sees and every MAC fails. That
//! is the correct direction to fail, and it is worth knowing to look for
//! before spending an afternoon on the crypto.

use sha2::{Digest, Sha256};

use crate::error::AuthError;
use crate::nonce::NonceStore;
use crate::proof::push_len_prefixed;
use crate::session::{Session, SessionStore, SessionToken};

/// The domain separator. Follows the crate-scoped convention settled in D2,
/// the same shape as the signing purposes, though this is a MAC input rather
/// than a FIPS 204 context.
pub const SESSION_BINDING_V1: &[u8] = b"aethel-auth/session-binding/v1";

/// `SHA-256(input)`, 32 bytes.
///
/// The browser half of this protocol runs on WebCrypto, which offers SHA-2
/// and has no SHA-3 or SHAKE. Everything computed on both sides therefore
/// uses SHA-256; everything computed only server-side stays on SHAKE-256 to
/// match `aethel-core`. See D8.
pub fn sha256_32(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// One request, in the form the session MAC covers.
///
/// Borrowed throughout: this is built per request on a hot path, and none of
/// it outlives the request it describes.
#[derive(Debug, Clone, Copy)]
pub struct RequestBinding<'a> {
    /// The relying party, byte-identical to the audience the session was
    /// opened for.
    pub audience: &'a [u8],
    /// The HTTP method. Case is normalised, so `get` and `GET` agree.
    pub method: &'a str,
    /// The path, exactly as transmitted. Not normalised, not decoded.
    pub path: &'a str,
    /// The query string without its leading `?`, exactly as transmitted.
    /// Empty when there is none.
    pub query: &'a str,
    /// `SHA-256` of the request body, or of the empty string when there is no
    /// body. Use [`sha256_32`] so both halves compute it the same way.
    pub body_sha256: [u8; 32],
    /// Unix seconds, per the client's clock, validated against the
    /// verifier's own.
    pub timestamp: u64,
    /// 256 bits from the client's CSPRNG, never reused within the store's
    /// retention window.
    pub nonce: [u8; 32],
}

impl RequestBinding<'_> {
    /// The exact bytes the MAC covers. See the module documentation for the
    /// layout and for why each field is present.
    pub fn encode(&self) -> Vec<u8> {
        // The method is the only normalised field. Uppercasing on both sides
        // is safer than requiring two codebases to agree by convention: a
        // deterministic transform cannot drift, a convention can.
        let method = self.method.to_ascii_uppercase();

        let mut out = Vec::with_capacity(
            SESSION_BINDING_V1.len()
                + self.audience.len()
                + method.len()
                + self.path.len()
                + self.query.len()
                + 96,
        );
        push_len_prefixed(&mut out, SESSION_BINDING_V1);
        push_len_prefixed(&mut out, self.audience);
        push_len_prefixed(&mut out, method.as_bytes());
        push_len_prefixed(&mut out, self.path.as_bytes());
        push_len_prefixed(&mut out, self.query.as_bytes());
        push_len_prefixed(&mut out, &self.body_sha256);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        push_len_prefixed(&mut out, &self.nonce);
        out
    }
}

/// Verify a request presented against a live session.
///
/// This is the per-request entry point a relying party calls, and it is the
/// only one that closes the replay hole:
/// [`verify_session`](crate::session::verify_session) alone checks that a MAC
/// is correct, which a replayed request's MAC also is.
///
/// The order of checks is deliberate. The MAC is verified **before** the
/// nonce is claimed, so an unauthenticated caller cannot fill the nonce store
/// with entries; by the time anything is written, the request is known to
/// have come from the session holder.
///
/// # Errors
///
/// Returns [`AuthError::NoSuchSession`] for an unknown, expired or
/// superseded session, [`AuthError::StaleOrFutureProof`] for a timestamp
/// outside `max_age_secs` in either direction,
/// [`AuthError::AudienceMismatch`] when the binding names a different relying
/// party than the session was opened for, [`AuthError::BadMac`] when the MAC
/// does not verify, and [`AuthError::NonceAlreadyUsed`] for a replay.
pub async fn verify_request<A, S, N>(
    sessions: &S,
    nonces: &N,
    token: &SessionToken,
    binding: &RequestBinding<'_>,
    presented_mac: &[u8],
    now: u64,
    max_age_secs: u64,
    current_epoch: u64,
) -> Result<Session<A>, AuthError>
where
    A: Clone,
    S: SessionStore<A>,
    N: NonceStore,
{
    let session = sessions
        .get(&token.hash())
        .await?
        .ok_or(AuthError::NoSuchSession)?;

    if session.is_expired(now) || session.epoch < current_epoch {
        return Err(AuthError::NoSuchSession);
    }

    // The client's clock is an input, never a fact. Both directions are
    // refused: a timestamp from the future is as much a reason to stop as a
    // stale one, and guessing which way a clock is wrong is not this crate's
    // business.
    if binding.timestamp > now.saturating_add(max_age_secs)
        || now.saturating_sub(binding.timestamp) > max_age_secs
    {
        return Err(AuthError::StaleOrFutureProof);
    }

    if binding.audience != session.audience.as_slice() {
        return Err(AuthError::AudienceMismatch);
    }

    if !session.verify_mac(&binding.encode(), presented_mac) {
        return Err(AuthError::BadMac);
    }

    // Only now, with the request attributable to the session holder, is
    // anything written. The nonce need outlive the window in which the
    // timestamp check would still pass; past that, a replay is refused by the
    // clock and the store need not remember it.
    if !nonces
        .claim(&binding.nonce, binding.timestamp.saturating_add(max_age_secs))
        .await?
    {
        return Err(AuthError::NonceAlreadyUsed);
    }

    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUDIENCE: &[u8] = b"https://console.example.com";
    const NOW: u64 = 1_758_000_000;

    fn binding<'a>(method: &'a str, path: &'a str, nonce: [u8; 32]) -> RequestBinding<'a> {
        RequestBinding {
            audience: AUDIENCE,
            method,
            path,
            query: "",
            body_sha256: sha256_32(b""),
            timestamp: NOW,
            nonce,
        }
    }

    #[test]
    fn every_field_changes_the_bytes() {
        // If a field can be altered without moving the encoding, it is not
        // actually bound, and an attacker can change it freely.
        let base = binding("GET", "/a", [1u8; 32]).encode();

        assert_ne!(base, binding("POST", "/a", [1u8; 32]).encode(), "method is bound");
        assert_ne!(base, binding("GET", "/b", [1u8; 32]).encode(), "path is bound");
        assert_ne!(base, binding("GET", "/a", [2u8; 32]).encode(), "nonce is bound");

        let mut b = binding("GET", "/a", [1u8; 32]);
        b.query = "x=1";
        assert_ne!(base, b.encode(), "query is bound");

        b = binding("GET", "/a", [1u8; 32]);
        b.body_sha256 = sha256_32(b"payload");
        assert_ne!(base, b.encode(), "body is bound");

        b = binding("GET", "/a", [1u8; 32]);
        b.timestamp = NOW + 1;
        assert_ne!(base, b.encode(), "timestamp is bound");

        b = binding("GET", "/a", [1u8; 32]);
        b.audience = b"https://elsewhere.example.com";
        assert_ne!(base, b.encode(), "audience is bound");
    }

    #[test]
    fn the_method_is_normalised_and_nothing_else_is() {
        assert_eq!(
            binding("get", "/a", [1u8; 32]).encode(),
            binding("GET", "/a", [1u8; 32]).encode(),
            "a client sending a lowercase method must still verify"
        );
        assert_ne!(
            binding("GET", "/A", [1u8; 32]).encode(),
            binding("GET", "/a", [1u8; 32]).encode(),
            "paths are case-sensitive and must not be folded"
        );
    }

    #[test]
    fn length_prefixing_stops_fields_running_together() {
        // Without length prefixes these two differ only in where one field
        // ends and the next begins, so both would encode identically and one
        // MAC would authorise the other.
        let a = RequestBinding {
            audience: b"https://a.example.com/x",
            method: "GET",
            path: "/",
            query: "",
            body_sha256: sha256_32(b""),
            timestamp: NOW,
            nonce: [1u8; 32],
        };
        let b = RequestBinding {
            audience: b"https://a.example.com",
            method: "GET",
            path: "/x/",
            query: "",
            body_sha256: sha256_32(b""),
            timestamp: NOW,
            nonce: [1u8; 32],
        };
        assert_ne!(a.encode(), b.encode());
    }

    #[test]
    fn an_empty_body_is_the_hash_of_nothing() {
        // Not 32 zero bytes. A reader reaching for `[0u8; 32]` produces a
        // binding that disagrees with every real client.
        assert_ne!(sha256_32(b""), [0u8; 32]);
        let hex: String = sha256_32(b"").iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "the SHA-256 of the empty string, pinned so the TypeScript has a \
             fixed target"
        );
    }

}
