//! Per-request verification against a live session.
//!
//! `verify_session` answers "is this MAC correct for this session", which a
//! replayed request also satisfies. `verify_request` is the entry point that
//! closes that hole, and these are the claims it makes.

use aethel_auth::{
    sha256_32, verify_request, AuthError, AuthStrength, InMemoryNonceStore, InMemorySessionStore,
    RequestBinding, Session, SessionSecret, SessionStore, SessionToken,
};

const AUDIENCE: &[u8] = b"https://console.example.com";
const NOW: u64 = 1_758_000_000;
const MAX_AGE: u64 = 300;

/// Minimal executor. The crate pulls in no async runtime, and none of these
/// futures actually yield, so polling once is enough.
fn block_on<F: core::future::Future>(f: F) -> F::Output {
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn noop(_: *const ()) {}
    fn clone(p: *const ()) -> RawWaker {
        RawWaker::new(p, &VTABLE)
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut f = Box::pin(f);
    match f.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("future parked; these stores do not yield"),
    }
}

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

/// A session already open, plus the pieces a request needs to use it.
fn live_session() -> (
    InMemorySessionStore<u32>,
    InMemoryNonceStore,
    SessionToken,
    SessionSecret,
) {
    let sessions = InMemorySessionStore::new();
    let nonces = InMemoryNonceStore::new();
    let token = SessionToken::from_bytes([7u8; 32]);
    let secret = SessionSecret::from_bytes([9u8; 32]);
    block_on(sessions.create(Session::new(
        &token,
        secret.clone(),
        1u32,
        AUDIENCE.to_vec(),
        AuthStrength::Proven,
        0,
        NOW,
        NOW + 3600,
    )))
    .expect("create");
    (sessions, nonces, token, secret)
}

#[test]
fn a_well_formed_request_verifies() {
    let (sessions, nonces, token, secret) = live_session();
    let b = binding("GET", "/profile", [11u8; 32]);
    let mac = secret.mac(&b.encode());

    let out = block_on(verify_request(
        &sessions, &nonces, &token, &b, &mac, NOW, MAX_AGE, 0,
    ))
    .expect("a request from the session holder is accepted");
    assert_eq!(out.actor, 1u32);
}

#[test]
fn replaying_a_captured_request_fails() {
    // The acceptance criterion for 0X3-192, and the thing a binding without a
    // varying element cannot deliver.
    let (sessions, nonces, token, secret) = live_session();
    let b = binding("GET", "/profile", [11u8; 32]);
    let mac = secret.mac(&b.encode());

    block_on(verify_request(
        &sessions, &nonces, &token, &b, &mac, NOW, MAX_AGE, 0,
    ))
    .expect("first use");

    let replay = block_on(verify_request(
        &sessions, &nonces, &token, &b, &mac, NOW, MAX_AGE, 0,
    ));
    assert!(
        matches!(replay, Err(AuthError::NonceAlreadyUsed)),
        "the identical request must not be accepted twice, got {replay:?}"
    );
}

#[test]
fn a_mac_cannot_be_moved_onto_another_request() {
    let (sessions, nonces, token, secret) = live_session();
    let signed = binding("GET", "/profile", [11u8; 32]);
    let mac = secret.mac(&signed.encode());

    let attacked = binding("DELETE", "/account", [11u8; 32]);
    let out = block_on(verify_request(
        &sessions, &nonces, &token, &attacked, &mac, NOW, MAX_AGE, 0,
    ));
    assert!(matches!(out, Err(AuthError::BadMac)), "got {out:?}");
}

#[test]
fn a_swapped_body_fails() {
    let (sessions, nonces, token, secret) = live_session();
    let mut signed = binding("POST", "/transfer", [11u8; 32]);
    signed.body_sha256 = sha256_32(br#"{"amount":1}"#);
    let mac = secret.mac(&signed.encode());

    let mut attacked = signed;
    attacked.body_sha256 = sha256_32(br#"{"amount":1000000}"#);
    let out = block_on(verify_request(
        &sessions, &nonces, &token, &attacked, &mac, NOW, MAX_AGE, 0,
    ));
    assert!(matches!(out, Err(AuthError::BadMac)), "got {out:?}");
}

#[test]
fn a_failed_mac_does_not_burn_the_nonce() {
    // Claiming before verifying would let an unauthenticated caller fill the
    // store, and would let anyone who observed a nonce deny it to the real
    // request.
    let (sessions, nonces, token, secret) = live_session();
    let b = binding("GET", "/profile", [11u8; 32]);

    let bad = block_on(verify_request(
        &sessions,
        &nonces,
        &token,
        &b,
        &[0u8; 32],
        NOW,
        MAX_AGE,
        0,
    ));
    assert!(matches!(bad, Err(AuthError::BadMac)));

    let mac = secret.mac(&b.encode());
    block_on(verify_request(
        &sessions, &nonces, &token, &b, &mac, NOW, MAX_AGE, 0,
    ))
    .expect("the real request still works after a forged one was refused");
}

#[test]
fn a_stale_or_future_timestamp_fails() {
    let (sessions, nonces, token, secret) = live_session();

    let mut old = binding("GET", "/profile", [11u8; 32]);
    old.timestamp = NOW - MAX_AGE - 1;
    let mac = secret.mac(&old.encode());
    let out = block_on(verify_request(
        &sessions, &nonces, &token, &old, &mac, NOW, MAX_AGE, 0,
    ));
    assert!(
        matches!(out, Err(AuthError::StaleOrFutureProof)),
        "got {out:?}"
    );

    let mut ahead = binding("GET", "/profile", [12u8; 32]);
    ahead.timestamp = NOW + MAX_AGE + 1;
    let mac = secret.mac(&ahead.encode());
    let out = block_on(verify_request(
        &sessions, &nonces, &token, &ahead, &mac, NOW, MAX_AGE, 0,
    ));
    assert!(
        matches!(out, Err(AuthError::StaleOrFutureProof)),
        "a clock ahead of ours is as much a reason to stop as one behind, got {out:?}"
    );
}

#[test]
fn a_binding_for_another_audience_fails() {
    let (sessions, nonces, token, secret) = live_session();
    let mut b = binding("GET", "/profile", [11u8; 32]);
    b.audience = b"https://elsewhere.example.com";
    let mac = secret.mac(&b.encode());

    let out = block_on(verify_request(
        &sessions, &nonces, &token, &b, &mac, NOW, MAX_AGE, 0,
    ));
    assert!(matches!(out, Err(AuthError::AudienceMismatch)), "got {out:?}");
}

#[test]
fn an_expired_session_fails_and_says_nothing_about_why() {
    let (sessions, nonces, token, secret) = live_session();
    let mut b = binding("GET", "/profile", [11u8; 32]);
    b.timestamp = NOW + 7200;
    let mac = secret.mac(&b.encode());

    let out = block_on(verify_request(
        &sessions,
        &nonces,
        &token,
        &b,
        &mac,
        NOW + 7200,
        MAX_AGE,
        0,
    ));
    assert!(
        matches!(out, Err(AuthError::NoSuchSession)),
        "an expired session is indistinguishable from one that never existed, got {out:?}"
    );
}

#[test]
fn bumping_the_epoch_invalidates_a_live_session() {
    // Bulk revocation without enumerating sessions: the session is otherwise
    // perfectly valid and its MAC is correct.
    let (sessions, nonces, token, secret) = live_session();
    let b = binding("GET", "/profile", [11u8; 32]);
    let mac = secret.mac(&b.encode());

    let out = block_on(verify_request(
        &sessions, &nonces, &token, &b, &mac, NOW, MAX_AGE, 1,
    ));
    assert!(matches!(out, Err(AuthError::NoSuchSession)), "got {out:?}");
}

#[test]
fn an_unknown_token_fails() {
    let (sessions, nonces, _token, secret) = live_session();
    let stranger = SessionToken::from_bytes([42u8; 32]);
    let b = binding("GET", "/profile", [11u8; 32]);
    let mac = secret.mac(&b.encode());

    let out = block_on(verify_request(
        &sessions, &nonces, &stranger, &b, &mac, NOW, MAX_AGE, 0,
    ));
    assert!(matches!(out, Err(AuthError::NoSuchSession)), "got {out:?}");
}
