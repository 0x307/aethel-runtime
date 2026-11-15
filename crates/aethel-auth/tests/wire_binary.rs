//! The canonical binary encoding, and the 0.3 fixtures it must not disturb.
//!
//! Every refusal has its control beside it (the unmodified encoding decodes),
//! and every vector comparison has a control that flips one byte.

mod common;

use aethel_auth::{
    verify_delegation, Approval, AuthError, Bounds, Delegation, DelegationRevocation, LoginProof,
};
use common::{hex, unhex, values, values_v2, Value, AUDIENCE};

const V0_3: &str = include_str!("vectors/v0_3_delegations.json");
const WIRE_V1: &str = include_str!("vectors/wire_v1.json");
const WIRE_V2: &str = include_str!("vectors/wire_v2.json");

// ---- AC1: 0.3 delegations still decode, hash and verify -------------------

/// Whether one recorded fixture is read back exactly by this version.
fn v0_3_entry_holds(entry: &serde_json::Value, recorded_id: &str, verify_at: u64) -> bool {
    let d: Delegation = serde_json::from_value(entry["json"].clone()).unwrap();
    hex(&d.id()) == recorded_id
        && hex(&d.signing_input()) == entry["signing_input_hex"].as_str().unwrap()
        && hex(&d.signature) == entry["signature_hex"].as_str().unwrap()
        && verify_delegation(&d, AUDIENCE, verify_at).is_ok()
}

#[test]
fn v0_3_delegations_keep_their_id_bytes_and_signature() {
    let doc: serde_json::Value = serde_json::from_str(V0_3).unwrap();
    let verify_at = doc["verify_at"].as_u64().unwrap();
    let entries = doc["delegations"].as_array().unwrap();
    assert_eq!(entries.len(), 4);
    for e in entries {
        let id = e["id_hex"].as_str().unwrap();
        assert!(v0_3_entry_holds(e, id, verify_at), "{}", e["name"]);
    }
}

/// Control: one flipped byte of the recorded id makes the same check fail.
#[test]
fn a_flipped_byte_in_a_recorded_id_fails_the_fixture_check() {
    let doc: serde_json::Value = serde_json::from_str(V0_3).unwrap();
    let verify_at = doc["verify_at"].as_u64().unwrap();
    for e in doc["delegations"].as_array().unwrap() {
        let mut id = unhex(e["id_hex"].as_str().unwrap());
        id[7] ^= 0x01;
        assert!(!v0_3_entry_holds(e, &hex(&id), verify_at), "{}", e["name"]);
    }
}

#[test]
fn v0_3_delegations_round_trip_through_the_binary_form() {
    let doc: serde_json::Value = serde_json::from_str(V0_3).unwrap();
    for e in doc["delegations"].as_array().unwrap() {
        let d: Delegation = serde_json::from_value(e["json"].clone()).unwrap();
        let bytes = d.to_bytes();
        assert_eq!(Delegation::from_bytes(&bytes).unwrap(), d);
        // AC4: the encoding holds the recorded signed bytes exactly, right
        // after the tag, version and the principal key's length-prefixed block.
        let at = 2 + 4 + d.principal_key.len() + 4;
        let signed = unhex(e["signing_input_hex"].as_str().unwrap());
        assert_eq!(&bytes[at..at + signed.len()], &signed[..], "{}", e["name"]);
        // ...and the length prefix in front of it says how long that block is.
        assert_eq!(
            &bytes[at - 4..at],
            &(signed.len() as u32).to_be_bytes(),
            "{}",
            e["name"]
        );
    }
}

// ---- AC2: committed vectors ------------------------------------------------

fn vector_matches(value: &Value, hex_in_file: &str) -> bool {
    let bytes = unhex(hex_in_file);
    value.to_bytes() == bytes && value.decodes_from(&bytes)
}

#[test]
fn wire_v1_vectors_encode_and_decode() {
    let doc: serde_json::Value = serde_json::from_str(WIRE_V1).unwrap();
    let entries = doc["vectors"].as_array().unwrap();
    let built = values();
    assert_eq!(entries.len(), built.len());
    assert!(built.len() >= 6, "two per type");
    for (entry, (name, kind, value)) in entries.iter().zip(built.iter()) {
        assert_eq!(entry["name"], *name);
        assert_eq!(entry["type"], *kind);
        let h = entry["hex"].as_str().unwrap();
        assert!(vector_matches(value, h), "{name}");
    }
}

/// Control: one byte changed in the file's value, and the check fails.
#[test]
fn a_changed_byte_in_a_wire_vector_fails() {
    let doc: serde_json::Value = serde_json::from_str(WIRE_V1).unwrap();
    let built = values();
    for (entry, (name, _, value)) in doc["vectors"].as_array().unwrap().iter().zip(built.iter()) {
        let mut bytes = unhex(entry["hex"].as_str().unwrap());
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;
        assert!(!vector_matches(value, &hex(&bytes)), "{name}");
    }
}

// ---- AC3: strict decoding ---------------------------------------------------

/// A hand-built envelope, so a test can put a defect inside the signed block.
fn envelope(tag: u8, version: u8, signer: &[u8], signed: &[u8], sig: &[u8]) -> Vec<u8> {
    let mut out = vec![tag, version];
    for part in [signer, signed, sig] {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

fn lp(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

/// A login's signed block with a commitment of `commitment_len` bytes.
fn login_with_commitment_len(commitment_len: usize) -> Vec<u8> {
    let mut signed = Vec::new();
    lp(&mut signed, b"aud");
    signed.extend_from_slice(&1u64.to_be_bytes());
    signed.extend_from_slice(&2u64.to_be_bytes());
    lp(&mut signed, &[7u8; 32]);
    lp(&mut signed, &vec![9u8; commitment_len]);
    envelope(0x02, 1, b"key", &signed, b"sig")
}

fn sample(name: &str) -> Vec<u8> {
    values()
        .into_iter()
        .find(|(n, _, _)| *n == name)
        .unwrap()
        .2
        .to_bytes()
}

fn offset_of_signed(bytes: &[u8]) -> usize {
    let signer_len = u32::from_be_bytes(bytes[2..6].try_into().unwrap()) as usize;
    2 + 4 + signer_len + 4
}

#[test]
fn control_the_unmodified_encodings_decode() {
    assert!(Delegation::from_bytes(&sample("delegation_minimal")).is_ok());
    assert!(Delegation::from_bytes(&sample("delegation_full")).is_ok());
    assert!(LoginProof::from_bytes(&sample("login_minimal")).is_ok());
    assert!(LoginProof::from_bytes(&sample("login_full")).is_ok());
    assert!(Approval::from_bytes(&sample("approval_minimal")).is_ok());
    assert!(Approval::from_bytes(&sample("approval_full")).is_ok());
    assert!(LoginProof::from_bytes(&login_with_commitment_len(32)).is_ok());
    assert!(LoginProof::from_bytes(&login_with_commitment_len(0)).is_ok());
}

#[test]
fn one_trailing_byte_is_refused() {
    let mut b = sample("delegation_full");
    b.push(0);
    assert_eq!(Delegation::from_bytes(&b), Err(AuthError::Malformed));
    let mut b = sample("login_full");
    b.push(0);
    assert_eq!(LoginProof::from_bytes(&b), Err(AuthError::Malformed));
    let mut b = sample("approval_full");
    b.push(0);
    assert_eq!(Approval::from_bytes(&b), Err(AuthError::Malformed));
}

#[test]
fn bytes_left_inside_the_signed_block_are_refused() {
    // A valid delegation, with one extra byte inside `signed` and the outer
    // lengths made consistent, so only the inner check can catch it.
    let b = sample("delegation_minimal");
    let at = offset_of_signed(&b);
    let signed_len = u32::from_be_bytes(b[at - 4..at].try_into().unwrap()) as usize;
    let signer_len = u32::from_be_bytes(b[2..6].try_into().unwrap()) as usize;
    let signer = &b[6..6 + signer_len];
    let mut signed = b[at..at + signed_len].to_vec();
    let sig = &b[at + signed_len + 4..];
    signed.push(0);
    let padded = envelope(0x01, 1, signer, &signed, sig);
    assert_eq!(Delegation::from_bytes(&padded), Err(AuthError::Malformed));
    // Control: the same rebuild without the extra byte is the original and
    // decodes.
    signed.pop();
    let ok = envelope(0x01, 1, signer, &signed, sig);
    assert_eq!(ok, b);
    assert!(Delegation::from_bytes(&ok).is_ok());
}

#[test]
fn a_truncated_signature_is_refused() {
    let b = sample("approval_full");
    assert_eq!(
        Approval::from_bytes(&b[..b.len() - 1]),
        Err(AuthError::Malformed)
    );
}

#[test]
fn an_unknown_tag_is_refused() {
    let mut b = sample("delegation_full");
    b[0] = 0x09;
    assert_eq!(Delegation::from_bytes(&b), Err(AuthError::Malformed));
}

#[test]
fn another_types_tag_is_refused() {
    // Delegation bytes are not a login proof, nor the reverse.
    assert_eq!(
        LoginProof::from_bytes(&sample("delegation_full")),
        Err(AuthError::Malformed)
    );
    assert_eq!(
        Delegation::from_bytes(&sample("login_full")),
        Err(AuthError::Malformed)
    );
}

#[test]
fn an_unknown_version_is_refused() {
    let mut b = sample("delegation_full");
    b[1] = 0x03;
    assert_eq!(Delegation::from_bytes(&b), Err(AuthError::Malformed));
}

#[test]
fn an_option_flag_of_2_is_refused() {
    // The full delegation, so a flag of 2 is followed by enough bytes to be
    // misread as "present" by a decoder that only checks for non-zero.
    let mut b = sample("delegation_full");
    let at = offset_of_signed(&b);
    let signed_len = u32::from_be_bytes(b[at - 4..at].try_into().unwrap()) as usize;
    // Three flagged u128 (17 bytes each) and one flagged u64 (9) end the block.
    let first_flag = at + signed_len - (3 * 17 + 9);
    assert_eq!(b[first_flag], 1);
    b[first_flag] = 2;
    assert_eq!(Delegation::from_bytes(&b), Err(AuthError::Malformed));
}

#[test]
fn a_session_commitment_of_length_31_is_refused() {
    assert_eq!(
        LoginProof::from_bytes(&login_with_commitment_len(31)),
        Err(AuthError::Malformed)
    );
}

#[test]
fn a_length_prefix_of_u32_max_is_refused() {
    // The signer's length, then the signed block's, then the signature's.
    let b = sample("login_full");
    let at = offset_of_signed(&b);
    let signed_len = u32::from_be_bytes(b[at - 4..at].try_into().unwrap()) as usize;
    for prefix in [2, at - 4, at + signed_len] {
        let mut m = b.clone();
        m[prefix..prefix + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(LoginProof::from_bytes(&m), Err(AuthError::Malformed));
    }
}

#[test]
fn an_action_count_of_u32_max_is_refused() {
    let mut signed = Vec::new();
    lp(&mut signed, b"delegate");
    lp(&mut signed, b"aud");
    signed.extend_from_slice(&1u64.to_be_bytes());
    signed.extend_from_slice(&2u64.to_be_bytes());
    signed.extend_from_slice(&u32::MAX.to_be_bytes());
    signed.extend_from_slice(&[0, 0, 0, 0]);
    let b = envelope(0x01, 1, b"key", &signed, b"sig");
    assert_eq!(Delegation::from_bytes(&b), Err(AuthError::Malformed));
}

#[test]
fn a_nonce_that_is_not_32_bytes_is_refused() {
    let mut signed = Vec::new();
    lp(&mut signed, b"aud");
    signed.extend_from_slice(&[0u8; 16]);
    lp(&mut signed, &[7u8; 31]);
    lp(&mut signed, &[]);
    let b = envelope(0x02, 1, b"key", &signed, b"sig");
    assert_eq!(LoginProof::from_bytes(&b), Err(AuthError::Malformed));
}

#[test]
fn a_request_digest_that_is_not_32_bytes_is_refused() {
    for digest_len in [0usize, 31, 33] {
        let mut signed = Vec::new();
        lp(&mut signed, b"aud");
        signed.extend_from_slice(&[0u8; 16]);
        lp(&mut signed, &[7u8; 32]);
        lp(&mut signed, &[]);
        lp(&mut signed, &vec![5u8; digest_len]);
        let b = envelope(0x02, 1, b"key", &signed, b"sig");
        assert_eq!(LoginProof::from_bytes(&b), Err(AuthError::Malformed));
    }
}

#[test]
fn an_approval_with_a_short_delegation_id_is_refused() {
    let mut signed = Vec::new();
    lp(&mut signed, b"aud");
    signed.extend_from_slice(&[0u8; 16]);
    lp(&mut signed, &[1u8; 32]);
    lp(&mut signed, &[2u8; 31]);
    lp(&mut signed, &[3u8; 32]);
    lp(&mut signed, b"pay");
    signed.extend_from_slice(&0u128.to_be_bytes());
    let b = envelope(0x03, 1, b"key", &signed, b"sig");
    assert_eq!(Approval::from_bytes(&b), Err(AuthError::Malformed));
}

#[test]
fn every_prefix_of_a_valid_encoding_is_refused() {
    for name in ["delegation_full", "login_full", "approval_full"] {
        let b = sample(name);
        for n in (0..b.len()).step_by(97).chain([b.len() - 1]) {
            let cut = &b[..n];
            assert!(
                Delegation::from_bytes(cut).is_err()
                    && LoginProof::from_bytes(cut).is_err()
                    && Approval::from_bytes(cut).is_err(),
                "{name} cut at {n}"
            );
        }
    }
}

// ---- canonical in both directions ------------------------------------------

#[test]
fn encoding_is_canonical_both_ways() {
    for (name, _, value) in values() {
        let bytes = value.to_bytes();
        assert!(value.decodes_from(&bytes), "{name}: from(to(x)) == x");
    }
    let d = Delegation::from_bytes(&sample("delegation_full")).unwrap();
    assert_eq!(d.to_bytes(), sample("delegation_full"));
    let l = LoginProof::from_bytes(&sample("login_full")).unwrap();
    assert_eq!(l.to_bytes(), sample("login_full"));
    let a = Approval::from_bytes(&sample("approval_full")).unwrap();
    assert_eq!(a.to_bytes(), sample("approval_full"));
}

#[test]
fn some_zero_and_none_encode_differently_and_survive() {
    let zero = Bounds {
        max_per_invocation: Some(0),
        ..Bounds::default()
    };
    let mut a = Delegation::from_bytes(&sample("delegation_minimal")).unwrap();
    let mut b = a.clone();
    a.bounds = Bounds::default();
    b.bounds = zero;
    assert_ne!(a.to_bytes(), b.to_bytes());
    assert_eq!(Delegation::from_bytes(&b.to_bytes()).unwrap(), b);
}

// ---- DelegationRevocation (tag 0x04) ------------------------------------------

/// A revocation's signed block, with `id_len` bytes for the delegation id.
fn revocation_with_id_len(id_len: usize) -> Vec<u8> {
    let mut signed = Vec::new();
    lp(&mut signed, b"aud");
    lp(&mut signed, &vec![5u8; id_len]);
    signed.extend_from_slice(&1u64.to_be_bytes());
    envelope(0x04, 1, b"key", &signed, b"sig")
}

#[test]
fn control_the_unmodified_revocation_encodings_decode() {
    assert!(DelegationRevocation::from_bytes(&sample("delegation_revocation_minimal")).is_ok());
    assert!(DelegationRevocation::from_bytes(&sample("delegation_revocation_full")).is_ok());
    assert!(DelegationRevocation::from_bytes(&revocation_with_id_len(32)).is_ok());
}

#[test]
fn a_revocation_uses_tag_4_version_1_and_holds_its_signed_bytes() {
    let rev = DelegationRevocation::from_bytes(&sample("delegation_revocation_full")).unwrap();
    let bytes = rev.to_bytes();
    assert_eq!(&bytes[..2], &[0x04, 0x01]);
    let at = offset_of_signed(&bytes);
    let signed = rev.signing_input();
    assert_eq!(&bytes[at..at + signed.len()], &signed[..]);
    assert_eq!(&bytes[at - 4..at], &(signed.len() as u32).to_be_bytes());
}

#[test]
fn a_revocation_id_that_is_not_32_bytes_is_refused() {
    assert_eq!(
        DelegationRevocation::from_bytes(&revocation_with_id_len(31)),
        Err(AuthError::Malformed)
    );
    assert_eq!(
        DelegationRevocation::from_bytes(&revocation_with_id_len(33)),
        Err(AuthError::Malformed)
    );
}

#[test]
fn revocation_bytes_with_a_defect_are_refused() {
    let good = sample("delegation_revocation_full");

    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(
        DelegationRevocation::from_bytes(&trailing),
        Err(AuthError::Malformed)
    );

    let mut truncated = good.clone();
    truncated.pop();
    assert_eq!(
        DelegationRevocation::from_bytes(&truncated),
        Err(AuthError::Malformed)
    );

    let mut bad_tag = good.clone();
    bad_tag[0] = 0x09;
    assert_eq!(
        DelegationRevocation::from_bytes(&bad_tag),
        Err(AuthError::Malformed)
    );

    let mut bad_version = good.clone();
    bad_version[1] = 0x03;
    assert_eq!(
        DelegationRevocation::from_bytes(&bad_version),
        Err(AuthError::Malformed)
    );

    let mut huge = good.clone();
    huge[2..6].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        DelegationRevocation::from_bytes(&huge),
        Err(AuthError::Malformed)
    );

    // Bytes inside the signed block beyond what the type defines.
    let at = offset_of_signed(&good);
    let signed_len = u32::from_be_bytes(good[at - 4..at].try_into().unwrap()) as usize;
    let signer = &good[6..at - 4];
    let mut signed = good[at..at + signed_len].to_vec();
    signed.push(0);
    assert_eq!(
        DelegationRevocation::from_bytes(&envelope(0x04, 1, signer, &signed, b"sig")),
        Err(AuthError::Malformed)
    );
}

#[test]
fn a_revocation_is_not_any_other_type_and_the_reverse() {
    let rev = sample("delegation_revocation_full");
    assert_eq!(Delegation::from_bytes(&rev), Err(AuthError::Malformed));
    assert_eq!(LoginProof::from_bytes(&rev), Err(AuthError::Malformed));
    assert_eq!(Approval::from_bytes(&rev), Err(AuthError::Malformed));
    for other in ["delegation_full", "login_full", "approval_full"] {
        assert_eq!(
            DelegationRevocation::from_bytes(&sample(other)),
            Err(AuthError::Malformed),
            "{other}"
        );
    }
}

#[test]
fn every_prefix_of_a_revocation_encoding_is_refused() {
    let good = sample("delegation_revocation_full");
    for n in 0..good.len() {
        assert_eq!(
            DelegationRevocation::from_bytes(&good[..n]),
            Err(AuthError::Malformed),
            "{n}"
        );
    }
}

// ---- version 2: delegations that name approvers ---------------------------------

fn sample_v2(name: &str) -> Vec<u8> {
    values_v2()
        .into_iter()
        .find(|(n, _, _)| *n == name)
        .unwrap()
        .2
        .to_bytes()
}

/// Whether the committed v2 entry matches the value built from its seeds:
/// bytes, decode, and (for a delegation) the id.
fn v2_entry_holds(value: &Value, entry: &serde_json::Value, hex_in_file: &str) -> bool {
    let bytes = unhex(hex_in_file);
    let id_ok = match (value.delegation_id(), entry.get("id_hex")) {
        (Some(id), Some(recorded)) => hex(&id) == recorded.as_str().unwrap(),
        (None, None) => true,
        _ => false,
    };
    id_ok && value.to_bytes() == bytes && value.decodes_from(&bytes)
}

#[test]
fn wire_v2_vectors_encode_decode_and_keep_their_ids() {
    let doc: serde_json::Value = serde_json::from_str(WIRE_V2).unwrap();
    let entries = doc["vectors"].as_array().unwrap();
    let built = values_v2();
    assert_eq!(entries.len(), built.len());
    assert_eq!(built.len(), 3);
    for (entry, (name, kind, value)) in entries.iter().zip(built.iter()) {
        assert_eq!(entry["name"], *name);
        assert_eq!(entry["type"], *kind);
        assert!(
            v2_entry_holds(value, entry, entry["hex"].as_str().unwrap()),
            "{name}"
        );
    }
}

/// Control: one changed byte in the file's hex, and one changed byte in a
/// recorded id, each make the check fail.
#[test]
fn a_changed_byte_in_a_wire_v2_vector_or_id_fails() {
    let doc: serde_json::Value = serde_json::from_str(WIRE_V2).unwrap();
    let built = values_v2();
    for (entry, (name, _, value)) in doc["vectors"].as_array().unwrap().iter().zip(built.iter()) {
        let mut bytes = unhex(entry["hex"].as_str().unwrap());
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;
        assert!(!v2_entry_holds(value, entry, &hex(&bytes)), "{name} hex");

        if let Some(id) = entry["id_hex"].as_str() {
            let mut id = unhex(id);
            id[3] ^= 0x01;
            let mut tampered = entry.clone();
            tampered["id_hex"] = serde_json::Value::String(hex(&id));
            assert!(
                !v2_entry_holds(value, &tampered, entry["hex"].as_str().unwrap()),
                "{name} id"
            );
        }
    }
}

#[test]
fn a_version_2_delegation_uses_version_byte_2_and_holds_its_signed_bytes() {
    for name in ["delegation_v2_one_approver", "delegation_v2_full"] {
        let b = sample_v2(name);
        assert_eq!(&b[..2], &[0x01, 0x02], "{name}");
        let d = Delegation::from_bytes(&b).unwrap();
        assert!(!d.bounds.approvers.is_empty());
        let at = offset_of_signed(&b);
        let signed = d.signing_input();
        assert_eq!(&b[at..at + signed.len()], &signed[..], "{name}");
        assert_eq!(d.to_bytes(), b, "{name}: canonical");
    }
}

#[test]
fn control_the_unmodified_version_2_encodings_decode() {
    assert!(Delegation::from_bytes(&sample_v2("delegation_v2_one_approver")).is_ok());
    assert!(Delegation::from_bytes(&sample_v2("delegation_v2_full")).is_ok());
    assert!(Approval::from_bytes(&sample_v2("approval_by_named_approver")).is_ok());
}

/// A version 1 header on a delegation with approvers is refused: the
/// approvers would be bytes left in a block the version does not define.
#[test]
fn a_version_1_header_on_a_delegation_with_approvers_is_refused() {
    let mut b = sample_v2("delegation_v2_full");
    assert_eq!(b[1], 0x02);
    b[1] = 0x01;
    assert_eq!(Delegation::from_bytes(&b), Err(AuthError::Malformed));
}

/// The parts of a valid minimal v1 delegation: signer, signed block, signature.
fn v1_parts() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let v1 = sample("delegation_minimal");
    let at = offset_of_signed(&v1);
    let signer_len = u32::from_be_bytes(v1[2..6].try_into().unwrap()) as usize;
    let signed_len = u32::from_be_bytes(v1[at - 4..at].try_into().unwrap()) as usize;
    (
        v1[6..6 + signer_len].to_vec(),
        v1[at..at + signed_len].to_vec(),
        v1[at + signed_len + 4..].to_vec(),
    )
}

/// A version 2 header with no approvers is refused: it would be a second
/// encoding of a version 1 delegation.
#[test]
fn a_version_2_header_on_a_delegation_without_approvers_is_refused() {
    let (signer, base, sig) = v1_parts();
    let mut zero = base.clone();
    zero.extend_from_slice(&0u32.to_be_bytes());
    assert_eq!(
        Delegation::from_bytes(&envelope(0x01, 2, &signer, &zero, &sig)),
        Err(AuthError::Malformed)
    );
    // Control: the same bytes with one approver decode.
    let mut one = base;
    one.extend_from_slice(&1u32.to_be_bytes());
    lp(&mut one, b"approver");
    assert!(Delegation::from_bytes(&envelope(0x01, 2, &signer, &one, &sig)).is_ok());
}

#[test]
fn other_types_do_not_read_version_2() {
    for name in ["approval_full", "login_full", "delegation_revocation_full"] {
        let mut b = sample(name);
        b[1] = 0x02;
        assert_eq!(
            Approval::from_bytes(&b),
            Err(AuthError::Malformed),
            "{name}"
        );
        assert_eq!(
            LoginProof::from_bytes(&b),
            Err(AuthError::Malformed),
            "{name}"
        );
        assert_eq!(
            DelegationRevocation::from_bytes(&b),
            Err(AuthError::Malformed),
            "{name}"
        );
    }
}

#[test]
fn a_version_3_delegation_is_refused() {
    let mut b = sample_v2("delegation_v2_full");
    b[1] = 0x03;
    assert_eq!(Delegation::from_bytes(&b), Err(AuthError::Malformed));
}

/// The approver count is not trusted for allocation: a count the remaining
/// bytes cannot satisfy is refused before a buffer is made.
#[test]
fn an_approver_count_the_input_cannot_hold_is_refused() {
    let (signer, base, sig) = v1_parts();
    for count in [u32::MAX, 2, 1] {
        let mut signed = base.clone();
        signed.extend_from_slice(&count.to_be_bytes());
        // No approver bytes follow the count.
        assert_eq!(
            Delegation::from_bytes(&envelope(0x01, 2, &signer, &signed, &sig)),
            Err(AuthError::Malformed),
            "count {count}"
        );
    }
}

#[test]
fn version_2_bytes_with_a_defect_are_refused() {
    let good = sample_v2("delegation_v2_full");

    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(Delegation::from_bytes(&trailing), Err(AuthError::Malformed));

    // Bytes left inside the signed block after the last approver.
    let at = offset_of_signed(&good);
    let signed_len = u32::from_be_bytes(good[at - 4..at].try_into().unwrap()) as usize;
    let signer = &good[6..at - 4];
    let sig = &good[at + signed_len + 4..];
    let mut signed = good[at..at + signed_len].to_vec();
    signed.push(0);
    assert_eq!(
        Delegation::from_bytes(&envelope(0x01, 2, signer, &signed, sig)),
        Err(AuthError::Malformed)
    );
    // Control: without the extra byte it is the original and decodes.
    signed.pop();
    assert_eq!(envelope(0x01, 2, signer, &signed, sig), good);
    assert!(Delegation::from_bytes(&good).is_ok());

    for n in (0..good.len()).step_by(61).chain([good.len() - 1]) {
        assert_eq!(
            Delegation::from_bytes(&good[..n]),
            Err(AuthError::Malformed),
            "cut at {n}"
        );
    }
}

#[test]
fn an_approval_signed_by_an_approver_is_the_same_wire_form() {
    let b = sample_v2("approval_by_named_approver");
    assert_eq!(&b[..2], &[0x03, 0x01]);
    let a = Approval::from_bytes(&b).unwrap();
    // The signer block is the approver's key.
    assert_eq!(&b[6..6 + a.approver_key.len()], &a.approver_key[..]);
    assert_eq!(a.to_bytes(), b);
}
