//! Tests for succession and revocation.
//!
//! The property these exist to pin is the asymmetry: **removing authority is
//! a safe operator power, granting it is not.** Several of these tests would
//! still pass if that were violated, so the ones that matter assert what
//! *cannot* be done, not what can.

use aethel_auth::{
    purposes, verify_revocation, verify_succession, AuthError, Revocation, RevokedBy, Succession,
};
use aethel_core::signing::Identity;

const AUDIENCE: &[u8] = b"https://console.example.com";
const OTHER_AUDIENCE: &[u8] = b"https://gateway.example.com";
const NOW: u64 = 1_700_000_000;

fn identity(seed: u8) -> Identity {
    Identity::generate(&[seed; 32]).expect("32 bytes of entropy")
}

fn sign_revocation(signer: &Identity, mut r: Revocation) -> Revocation {
    r.signature = signer
        .sign_with_purpose(purposes::AUTH_REVOCATION_V1, &r.signing_input())
        .expect("signing");
    r
}

fn sign_succession(signer: &Identity, mut s: Succession) -> Succession {
    s.signature = signer
        .sign_with_purpose(purposes::AUTH_SUCCESSION_V1, &s.signing_input())
        .expect("signing");
    s
}

fn self_revocation(holder: &Identity) -> Revocation {
    sign_revocation(
        holder,
        Revocation {
            subject_key: holder.public_key(),
            signer_key: holder.public_key(),
            by: RevokedBy::Holder,
            audience: AUDIENCE.to_vec(),
            issued_at: NOW,
            signature: Vec::new(),
        },
    )
}

// ── Revocation ───────────────────────────────────────────────────────────────

#[test]
fn a_holder_can_revoke_itself() {
    let holder = identity(60);
    let r = self_revocation(&holder);
    verify_revocation(&r, AUDIENCE, &[]).expect("a holder may always end its own authority");
}

#[test]
fn a_holder_cannot_revoke_someone_else() {
    let attacker = identity(61);
    let victim = identity(62);

    let r = sign_revocation(
        &attacker,
        Revocation {
            subject_key: victim.public_key(),
            signer_key: attacker.public_key(),
            by: RevokedBy::Holder,
            audience: AUDIENCE.to_vec(),
            issued_at: NOW,
            signature: Vec::new(),
        },
    );

    assert_eq!(
        verify_revocation(&r, AUDIENCE, &[]).unwrap_err(),
        AuthError::NotAuthorised,
        "a self-revocation must be self-signed, or anyone can lock anyone out"
    );
}

#[test]
fn an_authority_revocation_needs_a_recognised_authority() {
    let authority = identity(63);
    let victim = identity(64);

    let r = sign_revocation(
        &authority,
        Revocation {
            subject_key: victim.public_key(),
            signer_key: authority.public_key(),
            by: RevokedBy::Authority,
            audience: AUDIENCE.to_vec(),
            issued_at: NOW,
            signature: Vec::new(),
        },
    );

    verify_revocation(&r, AUDIENCE, &[authority.public_key()]).expect("recognised authority");

    assert_eq!(
        verify_revocation(&r, AUDIENCE, &[]).unwrap_err(),
        AuthError::NotAuthorised,
        "a relying party that recognises no authority must refuse every \
         authority revocation: silence grants nothing"
    );

    let stranger = identity(65);
    assert_eq!(
        verify_revocation(&r, AUDIENCE, &[stranger.public_key()]).unwrap_err(),
        AuthError::NotAuthorised,
        "an unrecognised signer is not an authority"
    );
}

#[test]
fn a_self_revocation_cannot_be_relabelled_as_an_authority_action() {
    let holder = identity(66);
    let mut r = self_revocation(&holder);

    // The audit trail says who did it. Flipping that after the fact must fail.
    r.by = RevokedBy::Authority;

    assert_eq!(
        verify_revocation(&r, AUDIENCE, &[holder.public_key()]).unwrap_err(),
        AuthError::BadSignature,
        "`by` is inside the signed input precisely so the record cannot be \
         rewritten by whoever relays it"
    );
}

#[test]
fn a_revocation_applies_at_one_relying_party() {
    let holder = identity(67);
    let r = self_revocation(&holder);

    assert_eq!(
        verify_revocation(&r, OTHER_AUDIENCE, &[]).unwrap_err(),
        AuthError::AudienceMismatch,
        "a revocation is not a broadcast"
    );
}

// ── Succession ───────────────────────────────────────────────────────────────

#[test]
fn an_outgoing_key_can_name_its_successor() {
    let old = identity(70);
    let new = identity(71);

    let s = sign_succession(
        &old,
        Succession {
            from_key: old.public_key(),
            to_key: new.public_key(),
            audience: AUDIENCE.to_vec(),
            issued_at: NOW,
            signature: Vec::new(),
        },
    );

    verify_succession(&s, AUDIENCE).expect("signed by the key standing down");
}

/// **The no-backdoor property.** An operator holding any key at all, including
/// one the relying party recognises as a revocation authority, cannot move an
/// account to a key of its choosing.
#[test]
fn nobody_but_the_outgoing_key_can_name_a_successor() {
    let victim = identity(72);
    let attacker = identity(73);
    let authority = identity(74);

    for (label, signer) in [
        ("an attacker", &attacker),
        ("a revocation authority", &authority),
    ] {
        let s = sign_succession(
            signer,
            Succession {
                from_key: victim.public_key(),
                to_key: attacker.public_key(),
                audience: AUDIENCE.to_vec(),
                issued_at: NOW,
                signature: Vec::new(),
            },
        );

        assert_eq!(
            verify_succession(&s, AUDIENCE).unwrap_err(),
            AuthError::BadSignature,
            "{label} must not be able to take over an account by naming itself \
             successor; there is no operator path to rotation and none may be added"
        );
    }
}

#[test]
fn substituting_the_successor_invalidates_the_record() {
    let old = identity(75);
    let intended = identity(76);
    let impostor = identity(77);

    let mut s = sign_succession(
        &old,
        Succession {
            from_key: old.public_key(),
            to_key: intended.public_key(),
            audience: AUDIENCE.to_vec(),
            issued_at: NOW,
            signature: Vec::new(),
        },
    );

    s.to_key = impostor.public_key();

    assert_eq!(
        verify_succession(&s, AUDIENCE).unwrap_err(),
        AuthError::BadSignature,
        "whoever relays a succession must not be able to redirect it"
    );
}

#[test]
fn a_key_cannot_succeed_itself() {
    let key = identity(78);

    let s = sign_succession(
        &key,
        Succession {
            from_key: key.public_key(),
            to_key: key.public_key(),
            audience: AUDIENCE.to_vec(),
            issued_at: NOW,
            signature: Vec::new(),
        },
    );

    assert_eq!(
        verify_succession(&s, AUDIENCE).unwrap_err(),
        AuthError::Malformed,
        "a self-succession is not a rotation, and accepting one would let a \
         replayed record look fresh forever"
    );
}

#[test]
fn a_succession_applies_at_one_relying_party() {
    let old = identity(79);
    let new = identity(80);

    let s = sign_succession(
        &old,
        Succession {
            from_key: old.public_key(),
            to_key: new.public_key(),
            audience: AUDIENCE.to_vec(),
            issued_at: NOW,
            signature: Vec::new(),
        },
    );

    assert_eq!(
        verify_succession(&s, OTHER_AUDIENCE).unwrap_err(),
        AuthError::AudienceMismatch,
        "this is what contains the correlation: a succession links two \
         identities at one verifier that already knows both"
    );
}

#[test]
fn statements_do_not_verify_under_each_others_purposes() {
    let old = identity(81);
    let new = identity(82);

    // A succession, signed under the revocation purpose.
    let mut s = Succession {
        from_key: old.public_key(),
        to_key: new.public_key(),
        audience: AUDIENCE.to_vec(),
        issued_at: NOW,
        signature: Vec::new(),
    };
    s.signature = old
        .sign_with_purpose(purposes::AUTH_REVOCATION_V1, &s.signing_input())
        .expect("signing");

    assert_eq!(
        verify_succession(&s, AUDIENCE).unwrap_err(),
        AuthError::BadSignature,
        "ending an identity and continuing it are different statements and \
         must not be interchangeable"
    );
}
