//! Login and step-up check revocation (AUTH4-04).
//!
//! `verify_login`, `verify_login_for_request` and `verify_step_up` each take the
//! relying party's revoked-key set. The check sits after the signature and
//! before the nonce claim, so a revoked key's proof never spends a nonce and an
//! unauthenticated caller cannot learn which keys are revoked.

use aethel_auth::{
    purposes, verify_login, verify_login_for_request, verify_step_up, AuthError,
    InMemoryNonceStore, LoginProof, StepUpProof, VerifyParams,
};
use aethel_core::signing::Identity;

const AUDIENCE: &[u8] = b"https://console.example.com";
const NOW: u64 = 1_700_000_000;
const MAX_AGE: u64 = 300;
const DIGEST: [u8; 32] = [0xD1; 32];
const ACTION: [u8; 32] = [0xAC; 32];

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

fn login(id: &Identity, digest: Option<[u8; 32]>, nonce: u8) -> LoginProof {
    let mut p = LoginProof {
        public_key: id.public_key(),
        audience: AUDIENCE.to_vec(),
        nonce: [nonce; 32],
        issued_at: NOW - 5,
        expires_at: NOW + 60,
        session_commitment: None,
        request_digest: digest,
        signature: Vec::new(),
    };
    p.signature = id
        .sign_with_purpose(purposes::AUTH_LOGIN_V1, &p.signing_input())
        .expect("signing");
    p
}

fn step_up(id: &Identity, nonce: u8) -> StepUpProof {
    let mut p = StepUpProof {
        public_key: id.public_key(),
        audience: AUDIENCE.to_vec(),
        nonce: [nonce; 32],
        issued_at: NOW - 5,
        expires_at: NOW + 60,
        action_digest: ACTION,
        signature: Vec::new(),
    };
    p.signature = id
        .sign_with_purpose(purposes::AUTH_STEP_UP_V1, &p.signing_input())
        .expect("signing");
    p
}

/// The same proof, with its signature broken. Same key, so a revoked key.
fn spoil(mut sig: Vec<u8>) -> Vec<u8> {
    sig[0] ^= 0x01;
    sig
}

fn none() -> &'static [Vec<u8>] {
    &[]
}

#[test]
fn verify_login_refuses_a_revoked_key() {
    let id = identity(1);
    let revoked = [id.public_key()];
    let proof = login(&id, None, 1);

    let nonces = InMemoryNonceStore::new();
    let err = block_on(verify_login(&proof, params(), &revoked[..], &nonces)).unwrap_err();
    assert_eq!(err, AuthError::Revoked);

    // Control: the same proof with an empty set passes.
    let out = block_on(verify_login(&proof, params(), none(), &nonces)).expect("control");
    assert_eq!(out.public_key, id.public_key());
}

#[test]
fn verify_login_for_request_refuses_a_revoked_key() {
    let id = identity(2);
    let revoked = [id.public_key()];
    let proof = login(&id, Some(DIGEST), 2);

    let nonces = InMemoryNonceStore::new();
    let err = block_on(verify_login_for_request(
        &proof,
        params(),
        &DIGEST,
        &revoked[..],
        &nonces,
    ))
    .unwrap_err();
    assert_eq!(err, AuthError::Revoked);

    block_on(verify_login_for_request(
        &proof,
        params(),
        &DIGEST,
        none(),
        &nonces,
    ))
    .expect("control");
}

#[test]
fn verify_step_up_refuses_a_revoked_key() {
    let id = identity(3);
    let revoked = [id.public_key()];
    let proof = step_up(&id, 3);

    let nonces = InMemoryNonceStore::new();
    let err = block_on(verify_step_up(
        &proof,
        params(),
        &ACTION,
        &revoked[..],
        &nonces,
    ))
    .unwrap_err();
    assert_eq!(err, AuthError::Revoked);

    block_on(verify_step_up(&proof, params(), &ACTION, none(), &nonces)).expect("control");
}

#[test]
fn a_revoked_key_never_spends_a_nonce() {
    let id = identity(4);
    let revoked = [id.public_key()];

    // login
    let nonces = InMemoryNonceStore::new();
    let proof = login(&id, None, 10);
    assert_eq!(
        block_on(verify_login(&proof, params(), &revoked[..], &nonces)).unwrap_err(),
        AuthError::Revoked
    );
    assert_eq!(
        nonces.len(),
        0,
        "a Revoked refusal must not claim the nonce"
    );
    block_on(verify_login(&proof, params(), none(), &nonces)).expect("control");
    assert_eq!(nonces.len(), 1, "control: a pass claims exactly one nonce");

    // login for request
    let nonces = InMemoryNonceStore::new();
    let proof = login(&id, Some(DIGEST), 11);
    assert_eq!(
        block_on(verify_login_for_request(
            &proof,
            params(),
            &DIGEST,
            &revoked[..],
            &nonces
        ))
        .unwrap_err(),
        AuthError::Revoked
    );
    assert_eq!(nonces.len(), 0);
    block_on(verify_login_for_request(
        &proof,
        params(),
        &DIGEST,
        none(),
        &nonces,
    ))
    .expect("control");
    assert_eq!(nonces.len(), 1);

    // step-up
    let nonces = InMemoryNonceStore::new();
    let proof = step_up(&id, 12);
    assert_eq!(
        block_on(verify_step_up(
            &proof,
            params(),
            &ACTION,
            &revoked[..],
            &nonces
        ))
        .unwrap_err(),
        AuthError::Revoked
    );
    assert_eq!(nonces.len(), 0);
    block_on(verify_step_up(&proof, params(), &ACTION, none(), &nonces)).expect("control");
    assert_eq!(nonces.len(), 1);
}

/// The signature is checked before revocation, so a caller who cannot sign as
/// a key cannot find out whether it is revoked.
#[test]
fn a_bad_signature_from_a_revoked_key_is_a_bad_signature() {
    let id = identity(5);
    let revoked = [id.public_key()];
    let nonces = InMemoryNonceStore::new();

    let mut proof = login(&id, None, 20);
    proof.signature = spoil(proof.signature);
    assert_eq!(
        block_on(verify_login(&proof, params(), &revoked[..], &nonces)).unwrap_err(),
        AuthError::BadSignature
    );

    let mut proof = login(&id, Some(DIGEST), 21);
    proof.signature = spoil(proof.signature);
    assert_eq!(
        block_on(verify_login_for_request(
            &proof,
            params(),
            &DIGEST,
            &revoked[..],
            &nonces
        ))
        .unwrap_err(),
        AuthError::BadSignature
    );

    let mut proof = step_up(&id, 22);
    proof.signature = spoil(proof.signature);
    assert_eq!(
        block_on(verify_step_up(
            &proof,
            params(),
            &ACTION,
            &revoked[..],
            &nonces
        ))
        .unwrap_err(),
        AuthError::BadSignature
    );
    assert_eq!(nonces.len(), 0);

    // Control: the same bad signature with an empty set is also BadSignature,
    // so the revoked set made no difference to what the caller sees.
    let mut proof = login(&id, None, 23);
    proof.signature = spoil(proof.signature);
    assert_eq!(
        block_on(verify_login(&proof, params(), none(), &nonces)).unwrap_err(),
        AuthError::BadSignature
    );
}
