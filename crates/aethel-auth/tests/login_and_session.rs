//! End-to-end tests for the login proof and the session it opens.
//!
//! Every test here is a claim the crate makes in its documentation. If a claim
//! is not worth a test, it should not be in the docs.

use aethel_auth::{
    purposes, verify_login, verify_session, AuthError, AuthStrength, InMemoryNonceStore,
    InMemorySessionStore, LoginProof, Session, SessionSecret, SessionStore, SessionToken,
    VerifyParams,
};
use aethel_core::signing::Identity;

const AUDIENCE: &[u8] = b"https://console.example.com";
const NOW: u64 = 1_700_000_000;
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

/// Build a signed proof. `commitment` present means "I want a session".
fn make_proof(
    identity: &Identity,
    audience: &[u8],
    nonce: [u8; 32],
    issued_at: u64,
    expires_at: u64,
    commitment: Option<[u8; 32]>,
) -> LoginProof {
    let mut proof = LoginProof {
        public_key: identity.public_key(),
        audience: audience.to_vec(),
        nonce,
        issued_at,
        expires_at,
        session_commitment: commitment,
        signature: Vec::new(),
    };
    proof.signature = identity
        .sign_with_purpose(purposes::AUTH_LOGIN_V1, &proof.signing_input())
        .expect("signing");
    proof
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

// ── The proof ────────────────────────────────────────────────────────────────

#[test]
fn an_agent_proof_verifies_in_one_round_trip() {
    let id = identity(1);
    let nonces = InMemoryNonceStore::new();
    let proof = make_proof(&id, AUDIENCE, [1u8; 32], NOW - 5, NOW + 60, None);

    let identity_out = block_on(verify_login(&proof, params(), &nonces)).expect("valid proof");

    assert_eq!(identity_out.public_key, id.public_key());
    assert_eq!(identity_out.strength, AuthStrength::Proven);
    assert!(
        identity_out.session_commitment.is_none(),
        "an agent asks for no session"
    );
}

#[test]
fn a_replayed_proof_is_refused() {
    let id = identity(2);
    let nonces = InMemoryNonceStore::new();
    let proof = make_proof(&id, AUDIENCE, [2u8; 32], NOW - 5, NOW + 60, None);

    block_on(verify_login(&proof, params(), &nonces)).expect("first use");
    let err = block_on(verify_login(&proof, params(), &nonces)).unwrap_err();

    assert_eq!(err, AuthError::NonceAlreadyUsed);
}

#[test]
fn a_proof_for_another_audience_is_refused() {
    let id = identity(3);
    let nonces = InMemoryNonceStore::new();
    let proof = make_proof(&id, b"https://evil.example", [3u8; 32], NOW - 5, NOW + 60, None);

    assert_eq!(
        block_on(verify_login(&proof, params(), &nonces)).unwrap_err(),
        AuthError::AudienceMismatch,
        "a proof minted for one relying party must not authenticate at another"
    );
}

#[test]
fn a_proof_from_the_future_is_refused() {
    let id = identity(4);
    let nonces = InMemoryNonceStore::new();
    let proof = make_proof(&id, AUDIENCE, [4u8; 32], NOW + 60, NOW + 600, None);

    assert_eq!(
        block_on(verify_login(&proof, params(), &nonces)).unwrap_err(),
        AuthError::StaleOrFutureProof,
        "a fast clock must not buy validity"
    );
}

#[test]
fn a_proof_older_than_the_verifiers_max_age_is_refused() {
    let id = identity(5);
    let nonces = InMemoryNonceStore::new();
    // The client claims a year of validity. The verifier's own clamp is what
    // decides, not the client's optimism.
    let proof = make_proof(&id, AUDIENCE, [5u8; 32], NOW - 10_000, NOW + 31_536_000, None);

    assert_eq!(
        block_on(verify_login(&proof, params(), &nonces)).unwrap_err(),
        AuthError::StaleOrFutureProof,
        "the client's expiry is an input to validate, not a fact to trust"
    );
}

#[test]
fn an_expired_proof_is_refused() {
    let id = identity(6);
    let nonces = InMemoryNonceStore::new();
    let proof = make_proof(&id, AUDIENCE, [6u8; 32], NOW - 100, NOW - 1, None);

    assert_eq!(
        block_on(verify_login(&proof, params(), &nonces)).unwrap_err(),
        AuthError::Expired
    );
}

#[test]
fn a_signature_made_under_another_purpose_is_refused() {
    let id = identity(7);
    let nonces = InMemoryNonceStore::new();
    let mut proof = make_proof(&id, AUDIENCE, [7u8; 32], NOW - 5, NOW + 60, None);

    // Same key, same bytes, wrong purpose. This is the cross-protocol replay
    // that purpose separation exists to make structurally impossible.
    proof.signature = id
        .sign_with_purpose(purposes::AUTH_STEP_UP_V1, &proof.signing_input())
        .expect("signing");

    assert_eq!(
        block_on(verify_login(&proof, params(), &nonces)).unwrap_err(),
        AuthError::BadSignature
    );
}

#[test]
fn tampering_with_any_signed_field_is_refused() {
    let id = identity(8);

    for (label, mutate) in [
        ("expiry", (|p: &mut LoginProof| p.expires_at += 1) as fn(&mut LoginProof)),
        ("issued_at", |p: &mut LoginProof| p.issued_at -= 1),
        ("nonce", |p: &mut LoginProof| p.nonce[0] ^= 1),
    ] {
        let nonces = InMemoryNonceStore::new();
        let mut proof = make_proof(&id, AUDIENCE, [8u8; 32], NOW - 5, NOW + 60, None);
        mutate(&mut proof);

        assert_eq!(
            block_on(verify_login(&proof, params(), &nonces)).unwrap_err(),
            AuthError::BadSignature,
            "tampering with {label} must invalidate the signature"
        );
    }
}

#[test]
fn a_nonce_is_only_spent_when_the_signature_verified() {
    let id = identity(9);
    let nonces = InMemoryNonceStore::new();
    let mut proof = make_proof(&id, AUDIENCE, [9u8; 32], NOW - 5, NOW + 60, None);
    proof.signature[0] ^= 0xff;

    let _ = block_on(verify_login(&proof, params(), &nonces));

    assert!(
        nonces.is_empty(),
        "an unauthenticated caller must not be able to write into the nonce \
         store, or it becomes a denial-of-service surface"
    );
}

#[test]
fn length_prefixing_stops_a_field_boundary_from_being_ambiguous() {
    let id = identity(10);

    // Under a delimiter-joined encoding these two are the kind of pair that
    // can collide: the delimiter appears inside the audience itself.
    let a = make_proof(&id, b"https://a.example|x", [1u8; 32], NOW, NOW + 60, None);
    let b = make_proof(&id, b"https://a.example", [1u8; 32], NOW, NOW + 60, None);

    assert_ne!(
        a.signing_input(),
        b.signing_input(),
        "two different audiences must never encode to the same signed bytes"
    );
}

#[test]
fn asking_for_a_session_changes_the_signed_bytes() {
    let id = identity(11);
    let secret = SessionSecret::from_bytes([42u8; 32]);

    let agent = make_proof(&id, AUDIENCE, [1u8; 32], NOW, NOW + 60, None);
    let human = make_proof(&id, AUDIENCE, [1u8; 32], NOW, NOW + 60, Some(secret.commitment()));

    assert_ne!(
        agent.signing_input(),
        human.signing_input(),
        "an absent commitment and a present one must be distinguishable, or a \
         proof could be stripped of its session request in transit"
    );
}

// ── The session ──────────────────────────────────────────────────────────────

fn open_session(
    secret: SessionSecret,
    token: &SessionToken,
    expires_at: u64,
    epoch: u64,
) -> Session<&'static str> {
    Session::new(
        token,
        secret,
        "staff-42",
        AUDIENCE.to_vec(),
        AuthStrength::Proven,
        epoch,
        NOW,
        expires_at,
    )
}

#[test]
fn a_session_needs_both_the_token_and_the_mac() {
    let store: InMemorySessionStore<&'static str> = InMemorySessionStore::new();
    let secret = SessionSecret::from_bytes([7u8; 32]);
    let token = SessionToken::from_bytes([3u8; 32]);
    block_on(store.create(open_session(secret.clone(), &token, NOW + 3600, 1))).unwrap();

    let binding = b"GET /reports?id=9|req-0001";
    let mac = secret.mac(binding);

    block_on(verify_session(&store, &token, binding, &mac, NOW, 1)).expect("token and MAC agree");

    // The cookie alone, without the secret, is inert.
    let forged = [0u8; 32];
    assert_eq!(
        block_on(verify_session(&store, &token, binding, &forged, NOW, 1)).unwrap_err(),
        AuthError::BadMac,
        "a stolen token without the session secret must not open the session"
    );
}

#[test]
fn the_store_holds_a_hash_not_the_token() {
    let store: InMemorySessionStore<&'static str> = InMemorySessionStore::new();
    let secret = SessionSecret::from_bytes([8u8; 32]);
    let token = SessionToken::from_bytes([4u8; 32]);
    let session = open_session(secret, &token, NOW + 3600, 1);

    assert_ne!(
        session.token_hash.as_slice(),
        token.as_bytes(),
        "the raw token must never be what is persisted"
    );

    block_on(store.create(session)).unwrap();
    assert!(
        block_on(store.get(&token.hash())).unwrap().is_some(),
        "lookup is by hash"
    );
}

#[test]
fn an_expired_or_revoked_session_is_indistinguishable_from_an_unknown_one() {
    let store: InMemorySessionStore<&'static str> = InMemorySessionStore::new();
    let secret = SessionSecret::from_bytes([9u8; 32]);
    let token = SessionToken::from_bytes([5u8; 32]);
    let binding = b"GET /|req-1";
    let mac = secret.mac(binding);

    // Unknown.
    assert_eq!(
        block_on(verify_session(&store, &token, binding, &mac, NOW, 1)).unwrap_err(),
        AuthError::NoSuchSession
    );

    // Expired.
    block_on(store.create(open_session(secret.clone(), &token, NOW - 1, 1))).unwrap();
    assert_eq!(
        block_on(verify_session(&store, &token, binding, &mac, NOW, 1)).unwrap_err(),
        AuthError::NoSuchSession
    );

    // Revoked.
    block_on(store.create(open_session(secret.clone(), &token, NOW + 3600, 1))).unwrap();
    block_on(store.revoke(&token.hash())).unwrap();
    assert_eq!(
        block_on(verify_session(&store, &token, binding, &mac, NOW, 1)).unwrap_err(),
        AuthError::NoSuchSession,
        "all three must look identical, or a prober learns whether a token \
         ever existed"
    );
}

#[test]
fn bumping_the_epoch_invalidates_sessions_in_bulk() {
    let store: InMemorySessionStore<&'static str> = InMemorySessionStore::new();
    let secret = SessionSecret::from_bytes([10u8; 32]);
    let token = SessionToken::from_bytes([6u8; 32]);
    let binding = b"GET /|req-2";
    let mac = secret.mac(binding);

    block_on(store.create(open_session(secret, &token, NOW + 3600, 1))).unwrap();

    block_on(verify_session(&store, &token, binding, &mac, NOW, 1)).expect("epoch 1 is current");
    assert_eq!(
        block_on(verify_session(&store, &token, binding, &mac, NOW, 2)).unwrap_err(),
        AuthError::NoSuchSession,
        "raising the current epoch must invalidate sessions issued under the old one"
    );
}

#[test]
fn the_commitment_ties_the_secret_to_the_login_signature() {
    let secret = SessionSecret::from_bytes([11u8; 32]);
    let other = SessionSecret::from_bytes([12u8; 32]);

    assert_eq!(secret.commitment(), SessionSecret::from_bytes([11u8; 32]).commitment());
    assert_ne!(
        secret.commitment(),
        other.commitment(),
        "a different secret must not satisfy a commitment the holder signed"
    );
}

#[test]
fn a_binding_without_a_varying_element_replays() {
    // Not a bug in the MAC: a demonstration of why the binding is the
    // caller's responsibility, and what goes wrong when it is chosen badly.
    let secret = SessionSecret::from_bytes([13u8; 32]);

    let careless = b"GET /reports";
    assert_eq!(
        secret.mac(careless),
        secret.mac(careless),
        "a binding with nothing per-request in it produces one MAC forever, so \
         an observer can replay any request they saw"
    );

    let careful_first = b"GET /reports|req-0001";
    let careful_second = b"GET /reports|req-0002";
    assert_ne!(
        secret.mac(careful_first),
        secret.mac(careful_second),
        "a per-request element is what makes the MAC single-use"
    );
}

#[test]
fn the_secret_is_never_printed() {
    let secret = SessionSecret::from_bytes([0xAB; 32]);
    let rendered = format!("{secret:?}");

    assert!(!rendered.contains("171") && !rendered.to_lowercase().contains("ab"));
    assert!(rendered.contains("redacted"));
}
