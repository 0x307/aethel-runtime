//! End-to-end tests for the login proof.
//!
//! Every test here is a claim the crate makes in its documentation. If a claim
//! is not worth a test, it should not be in the docs.

use aethel_auth::{
    purposes, verify_login, AuthError, AuthStrength, InMemoryNonceStore, LoginProof, NonceStore,
    StoreError, VerifyParams,
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

/// Build a signed proof. `commitment` is the reserved session field.
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
    let proof = make_proof(
        &id,
        b"https://evil.example",
        [3u8; 32],
        NOW - 5,
        NOW + 60,
        None,
    );

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
    let proof = make_proof(
        &id,
        AUDIENCE,
        [5u8; 32],
        NOW - 10_000,
        NOW + 31_536_000,
        None,
    );

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
        (
            "expiry",
            (|p: &mut LoginProof| p.expires_at += 1) as fn(&mut LoginProof),
        ),
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
fn the_reserved_session_field_is_signed_when_present() {
    // No session flow ships in this release, but the field is part of the
    // format, so its presence must still change what is signed.
    let id = identity(11);

    let agent = make_proof(&id, AUDIENCE, [1u8; 32], NOW, NOW + 60, None);
    let human = make_proof(&id, AUDIENCE, [1u8; 32], NOW, NOW + 60, Some([42u8; 32]));

    assert_ne!(
        agent.signing_input(),
        human.signing_input(),
        "an absent commitment and a present one must be distinguishable, or a \
         proof could be stripped of its session request in transit"
    );
}

/// Records the retention each claim asks for.
struct RecordingStore(std::sync::Mutex<Vec<u64>>);

impl NonceStore for RecordingStore {
    fn claim(
        &self,
        _nonce: &[u8; 32],
        expires_at: u64,
    ) -> impl core::future::Future<Output = Result<bool, StoreError>> + Send {
        self.0.lock().unwrap().push(expires_at);
        async { Ok(true) }
    }
}

/// A holder that picks a far-future expiry must not make the verifier's
/// store remember its nonce for that long: the proof stops being accepted
/// after `max_age_secs`, so that is the most the store needs. A proof with an
/// ordinary expiry keeps it, which is the control.
#[test]
fn nonce_retention_is_bounded_by_the_verifiers_max_age() {
    let id = identity(70);

    let store = RecordingStore(std::sync::Mutex::new(Vec::new()));
    let far = make_proof(&id, AUDIENCE, [70u8; 32], NOW, u64::MAX, None);
    block_on(verify_login(&far, params(), &store)).expect("valid proof");

    let short = make_proof(&id, AUDIENCE, [71u8; 32], NOW, NOW + 30, None);
    block_on(verify_login(&short, params(), &store)).expect("valid proof");

    let recorded = store.0.lock().unwrap().clone();
    assert_eq!(
        recorded,
        vec![NOW + MAX_AGE + 1, NOW + 30],
        "retention is the earlier of expiry and the max-age clamp"
    );
}
