//! The JSON shape of the statement types: bytes as base64url text, and the
//! old number-array shape still accepted on the way in.

use aethel_auth::{Holder, LoginProof, Revocation};
use aethel_core::signing::Identity;

const AUDIENCE: &[u8] = b"https://console.example.com/t/1";

fn proof() -> LoginProof {
    let id = Identity::generate(&[3u8; 32]).unwrap();
    let mut proof = Holder::new(&id, AUDIENCE).login([4u8; 32], 1_700_000_000, 60);
    // The reserved session field, set so its `Some` encoding is exercised too.
    // Not re-signed: these tests check the JSON shape, not the signature.
    proof.session_commitment = Some([5u8; 32]);
    proof
}

#[test]
fn a_login_proof_is_compact_text_and_round_trips() {
    let proof = proof();
    let json = serde_json::to_string(&proof).unwrap();
    assert!(
        json.len() < 8_000,
        "{} bytes; number arrays made this ~19 KB",
        json.len()
    );
    assert!(!json.contains("[33,"), "no byte arrays in the output");
    assert_eq!(serde_json::from_str::<LoginProof>(&json).unwrap(), proof);
}

#[test]
fn a_proof_in_the_old_number_array_shape_still_reads() {
    let proof = proof();
    let old = serde_json::json!({
        "public_key": proof.public_key,
        "audience": proof.audience,
        "nonce": proof.nonce,
        "issued_at": proof.issued_at,
        "expires_at": proof.expires_at,
        "session_commitment": proof.session_commitment,
        "signature": proof.signature,
    });
    assert!(
        old.to_string().contains("\"nonce\":[4,4,"),
        "really the old shape"
    );
    assert_eq!(serde_json::from_value::<LoginProof>(old).unwrap(), proof);
}

#[test]
fn absent_options_and_wrong_lengths_behave() {
    let id = Identity::generate(&[6u8; 32]).unwrap();
    let agent = Holder::new(&id, AUDIENCE).login([7u8; 32], 1_700_000_000, 60);
    let json = serde_json::to_string(&agent).unwrap();
    assert!(json.contains("\"session_commitment\":null"));
    assert_eq!(serde_json::from_str::<LoginProof>(&json).unwrap(), agent);

    let short_nonce = json.replace(
        &format!(
            "\"nonce\":{}",
            serde_json::to_string(&serde_json::to_value(&agent).unwrap()["nonce"]).unwrap()
        ),
        "\"nonce\":\"AAAA\"",
    );
    assert!(
        serde_json::from_str::<LoginProof>(&short_nonce).is_err(),
        "a nonce must be 32 bytes"
    );

    let revocation = Holder::new(&id, AUDIENCE).revoke_self(1_700_000_000);
    let back: Revocation =
        serde_json::from_str(&serde_json::to_string(&revocation).unwrap()).unwrap();
    assert_eq!(back, revocation);
}
