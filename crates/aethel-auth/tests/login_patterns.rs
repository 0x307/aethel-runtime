//! The two login patterns the README documents, as running code.
//!
//! "A server challenge" and "Login proofs and revocation" are advice to a
//! relying party. Each test here is that advice written against the public
//! API only, with a control for every refusal.

use aethel_auth::{
    verify_login, verify_login_for_request, AuthError, Holder, InMemoryNonceStore, RevokedKeys,
    VerifyParams,
};
use aethel_core::signing::Identity;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

const AUDIENCE: &[u8] = b"https://console.example.com";
const NOW: u64 = 1_700_000_000;
const MAX_AGE: u64 = 300;

/// Minimal executor. The crate pulls in no async runtime, and none of these
/// futures actually yield, so polling once is enough.
fn block_on<F: core::future::Future>(f: F) -> F::Output {
    use core::task::{Context, Poll, Waker};
    let mut cx = Context::from_waker(Waker::noop());
    let mut f = Box::pin(f);
    match f.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("future parked; these stores do not yield"),
    }
}

fn identity(seed: u8) -> Identity {
    Identity::generate(&[seed; 32]).expect("32 bytes of entropy")
}

fn params() -> VerifyParams<'static> {
    VerifyParams {
        expected_audience: AUDIENCE,
        now: NOW,
        max_age_secs: MAX_AGE,
    }
}

/// The README's `lp(x)`: the 4-byte big-endian length of `x`, then `x`.
fn lp(out: &mut Vec<u8>, x: &[u8]) {
    out.extend_from_slice(&(x.len() as u32).to_be_bytes());
    out.extend_from_slice(x);
}

/// A 32-byte hash. The README recommends SHA-256; this test uses SHAKE-256
/// (already a dependency of the crate) so it adds none. The crate only ever
/// sees the 32 bytes, so the choice does not change what is being tested.
fn hash32(input: &[u8]) -> [u8; 32] {
    let mut h = Shake256::default();
    h.update(input);
    let mut out = [0u8; 32];
    h.finalize_xof().read(&mut out);
    out
}

/// The README's recommended digest, with the server challenge as one more
/// `lp(..)` field.
fn request_digest(method: &str, path: &str, body: &[u8], challenge: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::new();
    lp(&mut buf, method.as_bytes());
    lp(&mut buf, path.as_bytes());
    lp(&mut buf, &hash32(body));
    lp(&mut buf, challenge);
    hash32(&buf)
}

#[test]
fn server_challenge_binds_the_login() {
    let agent = identity(1);
    let holder = Holder::new(&agent, AUDIENCE);

    // The server issues challenge A (and would store it). B is some other
    // value, such as a challenge issued to a different client.
    let challenge_a = [0xAA; 32];
    let challenge_b = [0xBB; 32];

    // The client logs in with a digest over method, path, body hash and A.
    let body = br#"{"invoice":7}"#;
    let client_digest = request_digest("POST", "/v1/pay?invoice=7", body, &challenge_a);
    let proof = holder.login_for_request([7u8; 32], NOW - 5, 60, client_digest);

    // Refused: the server builds its digest from B, not the challenge it
    // issued to this client. Checked on its own store so the refusal is the
    // digest's and not a spent nonce's.
    let server_digest_b = request_digest("POST", "/v1/pay?invoice=7", body, &challenge_b);
    let refused = block_on(verify_login_for_request(
        &proof,
        params(),
        &server_digest_b,
        &InMemoryNonceStore::new(),
    ));
    assert_eq!(
        refused.unwrap_err(),
        AuthError::RequestMismatch,
        "a digest built from a different challenge must be refused"
    );

    // Control: the server builds its digest from the challenge it issued, A.
    let server_digest_a = request_digest("POST", "/v1/pay?invoice=7", body, &challenge_a);
    let accepted = block_on(verify_login_for_request(
        &proof,
        params(),
        &server_digest_a,
        &InMemoryNonceStore::new(),
    ))
    .expect("the proof bound to challenge A verifies against challenge A");
    assert_eq!(accepted.public_key, agent.public_key());
}

#[test]
fn plain_login_does_not_check_revocation() {
    let revoked_agent = identity(2);
    let other_agent = identity(3);

    // The relying party's own revoked set, holding the first agent's key.
    let revoked: Vec<Vec<u8>> = vec![revoked_agent.public_key()];

    let proof = Holder::new(&revoked_agent, AUDIENCE).login([1u8; 32], NOW - 5, 60);

    // The gap: verify_login takes no revoked set, so it accepts the proof of
    // a revoked key.
    let who = block_on(verify_login(&proof, params(), &InMemoryNonceStore::new()))
        .expect("verify_login does not check revocation");
    assert_eq!(who.public_key, revoked_agent.public_key());

    // The README's check, as the README shows it. It refuses that key.
    let check = |who: aethel_auth::AuthenticatedIdentity| -> Result<(), AuthError> {
        if revoked.is_revoked(&who.public_key) {
            return Err(AuthError::Revoked);
        }
        Ok(())
    };
    assert_eq!(check(who), Err(AuthError::Revoked));

    // Control: a key that is not in the set passes the same check.
    let proof = Holder::new(&other_agent, AUDIENCE).login([2u8; 32], NOW - 5, 60);
    let who = block_on(verify_login(&proof, params(), &InMemoryNonceStore::new()))
        .expect("a valid proof");
    assert_eq!(check(who), Ok(()));
}
