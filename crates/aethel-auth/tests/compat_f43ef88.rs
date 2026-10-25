//! Proofs made before the request digest existed still verify.
//!
//! The fixture was written by the crate at `f43ef88`, the last commit before
//! `LoginProof::request_digest`, with a fixed identity. So it is a real old
//! proof, not one this version made and then read back. If these fail, adding
//! the field changed what an existing proof signs or how it reads, and every
//! proof already issued (and Aethel Verify's vectors) would stop verifying.

use aethel_auth::{
    verify_login, verify_login_for_request, AuthError, InMemoryNonceStore, LoginProof, VerifyParams,
};

const FIXTURE: &str = include_str!("fixtures/login_proofs_f43ef88.json");
const AUDIENCE: &[u8] = b"https://verify.example.com";

/// Minimal executor. None of these futures yield, so polling once is enough.
fn block_on<F: core::future::Future>(f: F) -> F::Output {
    use core::task::{Context, Poll, Waker};
    let mut cx = Context::from_waker(Waker::noop());
    let mut f = Box::pin(f);
    match f.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("future parked; this store does not yield"),
    }
}

fn params() -> VerifyParams<'static> {
    VerifyParams {
        expected_audience: AUDIENCE,
        now: 1_700_000_010,
        max_age_secs: 300,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn proofs_made_at_f43ef88_have_the_same_bytes_and_still_verify() {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    assert_eq!(fixture["made_at"], "f43ef88");

    for name in ["plain", "with_commitment"] {
        let old = &fixture[name];
        let proof: LoginProof = serde_json::from_value(old.clone()).unwrap();
        assert_eq!(proof.request_digest, None, "{name}: no digest in old JSON");

        assert_eq!(
            hex(&proof.signing_input()),
            fixture[format!("{name}_signing_input_hex")]
                .as_str()
                .unwrap(),
            "{name}: the signed bytes changed"
        );
        assert_eq!(
            serde_json::to_value(&proof).unwrap(),
            *old,
            "{name}: the JSON changed"
        );

        block_on(verify_login(&proof, params(), &InMemoryNonceStore::new()))
            .unwrap_or_else(|e| panic!("{name}: an old proof no longer verifies: {e:?}"));
    }
}

/// Control for the test above: the fixture does not verify whatever it
/// carries. Give the old proof a digest and its signature no longer covers
/// the signed bytes.
#[test]
fn an_old_proof_given_a_digest_does_not_verify() {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    let mut proof: LoginProof = serde_json::from_value(fixture["plain"].clone()).unwrap();
    proof.request_digest = Some([0xa1; 32]);

    assert_eq!(
        block_on(verify_login_for_request(
            &proof,
            params(),
            &[0xa1; 32],
            &InMemoryNonceStore::new()
        ))
        .unwrap_err(),
        AuthError::BadSignature
    );
}
