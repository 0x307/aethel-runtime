//! Revoking one delegation by id.
//!
//! A principal signs a `DelegationRevocation` naming one delegation. The
//! relying party verifies it, adds the id to its revoked set, and `authorise`
//! and `check_approval` refuse that delegation from then on, while the
//! principal's other delegations stand.
//!
//! Every refusal has its control beside it, and every refusal input is built
//! so that the check under test is the only thing that rejects it.

use aethel_auth::purposes::{AUTH_DELEGATION_REVOCATION_V1, AUTH_REVOCATION_V1};
use aethel_auth::{
    authorise, check_approval, verify_delegation_revocation, verify_revocation, AuthError, Bounds,
    Delegation, DelegationRevocation, Holder, InMemoryNonceStore, Revocation, RevokedBy,
    VerifyParams,
};
use aethel_core::signing::Identity;

const AUDIENCE: &[u8] = b"https://pay.example.com";
const OTHER_AUDIENCE: &[u8] = b"https://other.example.com";
const NOW: u64 = 1_800_000_000;
const REQUEST: [u8; 32] = [0x40; 32];
const NONE_REVOKED: &[Vec<u8>] = &[];
const NONE_DELEGATIONS_REVOKED: &[[u8; 32]] = &[];

fn block_on<F: core::future::Future>(f: F) -> F::Output {
    use core::task::{Context, Poll, Waker};
    let mut cx = Context::from_waker(Waker::noop());
    let mut f = Box::pin(f);
    match f.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("future parked"),
    }
}

fn identity(seed: u8) -> Identity {
    Identity::generate(&[seed; 32]).expect("32 bytes of entropy")
}

fn bounds(action: &[u8]) -> Bounds {
    Bounds {
        actions: vec![action.to_vec()],
        max_per_invocation: Some(10_000),
        max_total: Some(20_000),
        window_secs: Some(86_400),
        approval_required_above: Some(100),
        approvers: Vec::new(),
    }
}

fn grant(principal: &Identity, delegate: &Identity, action: &[u8]) -> Delegation {
    Holder::new(principal, AUDIENCE).delegate_to(
        delegate.public_key(),
        bounds(action),
        NOW - 10,
        NOW + 3600,
    )
}

/// A revocation signed by hand, so a test can sign it wrongly on purpose.
fn hand_signed(
    signer: &Identity,
    principal_key: Vec<u8>,
    audience: &[u8],
    delegation_id: [u8; 32],
    purpose: &[u8],
) -> DelegationRevocation {
    let mut rev = DelegationRevocation {
        principal_key,
        audience: audience.to_vec(),
        delegation_id,
        issued_at: NOW,
        signature: Vec::new(),
    };
    rev.signature = signer
        .sign_with_purpose(purpose, &rev.signing_input())
        .unwrap();
    rev
}

fn authorise_with(
    d: &Delegation,
    principal: &Identity,
    delegate: &Identity,
    gone: &[[u8; 32]],
) -> Result<(), AuthError> {
    authorise(
        d,
        AUDIENCE,
        &[principal.public_key()],
        NONE_REVOKED,
        gone,
        &delegate.public_key(),
        b"pay",
        Some(50),
        NOW,
    )
    .map(|_| ())
}

fn approval_check(
    d: &Delegation,
    principal: &Identity,
    gone: &[[u8; 32]],
    nonce: u8,
) -> Result<(), AuthError> {
    let approval = Holder::new(principal, AUDIENCE).approve(
        d,
        &REQUEST,
        b"pay",
        500,
        [nonce; 32],
        NOW - 1,
        60,
    );
    block_on(check_approval(
        d,
        &approval,
        VerifyParams {
            expected_audience: AUDIENCE,
            now: NOW,
            max_age_secs: 300,
        },
        &[principal.public_key()],
        NONE_REVOKED,
        gone,
        &REQUEST,
        b"pay",
        500,
        &InMemoryNonceStore::new(),
    ))
}

// ---- AC1 and AC2: a revoked delegation is refused ----------------------------

#[test]
fn a_principals_revocation_verifies_and_then_authorise_refuses_the_delegation() {
    let (principal, delegate) = (identity(1), identity(2));
    let d = grant(&principal, &delegate, b"pay");

    let rev = Holder::new(&principal, AUDIENCE).revoke_delegation(&d, NOW);
    assert_eq!(rev.delegation_id, d.id());
    assert_eq!(verify_delegation_revocation(&rev, &d, AUDIENCE), Ok(()));

    // Control: with nothing revoked, the same call passes.
    assert_eq!(
        authorise_with(&d, &principal, &delegate, NONE_DELEGATIONS_REVOKED),
        Ok(())
    );
    assert_eq!(
        authorise_with(&d, &principal, &delegate, &[d.id()]),
        Err(AuthError::Revoked)
    );
}

#[test]
fn revoking_one_delegation_leaves_the_principals_others_standing() {
    let (principal, delegate) = (identity(1), identity(2));
    let revoked = grant(&principal, &delegate, b"pay");
    let other = grant(&principal, &delegate, b"refund");
    assert_ne!(revoked.id(), other.id());

    let gone = [revoked.id()];
    assert_eq!(
        authorise_with(&revoked, &principal, &delegate, &gone),
        Err(AuthError::Revoked)
    );
    // The other delegation has the same principal and delegate; only its
    // action differs, so `authorise` at "refund".
    let still = authorise(
        &other,
        AUDIENCE,
        &[principal.public_key()],
        NONE_REVOKED,
        &gone[..],
        &delegate.public_key(),
        b"refund",
        Some(50),
        NOW,
    );
    assert!(still.is_ok(), "{still:?}");
}

#[test]
fn authorise_accepts_a_closure_as_the_revoked_set() {
    let (principal, delegate) = (identity(1), identity(2));
    let d = grant(&principal, &delegate, b"pay");
    let id = d.id();
    let run = |revoked: &dyn Fn(&[u8; 32]) -> bool| {
        authorise(
            &d,
            AUDIENCE,
            &[principal.public_key()],
            NONE_REVOKED,
            &revoked,
            &delegate.public_key(),
            b"pay",
            Some(50),
            NOW,
        )
        .map(|_| ())
    };
    assert_eq!(run(&|_| false), Ok(()));
    assert_eq!(run(&|x| *x == id), Err(AuthError::Revoked));
}

/// The revoked-id check comes before the signature, like the key check: a
/// delegation with a broken signature and a revoked id says `Revoked`.
#[test]
fn the_revoked_id_is_checked_before_the_signature() {
    let (principal, delegate) = (identity(1), identity(2));
    let mut d = grant(&principal, &delegate, b"pay");
    // Control: with nothing revoked, the broken signature is what refuses it.
    d.signature[0] ^= 0x01;
    assert_eq!(
        authorise_with(&d, &principal, &delegate, NONE_DELEGATIONS_REVOKED),
        Err(AuthError::BadSignature)
    );
    assert_eq!(
        authorise_with(&d, &principal, &delegate, &[d.id()]),
        Err(AuthError::Revoked)
    );
}

#[test]
fn check_approval_refuses_a_revoked_delegation() {
    let (principal, delegate) = (identity(1), identity(2));
    let d = grant(&principal, &delegate, b"pay");

    // Control: an empty set passes.
    assert_eq!(
        approval_check(&d, &principal, NONE_DELEGATIONS_REVOKED, 1),
        Ok(())
    );
    assert_eq!(
        approval_check(&d, &principal, &[d.id()], 2),
        Err(AuthError::Revoked)
    );
}

// ---- AC3: the four refusals ---------------------------------------------------

#[test]
fn control_a_well_formed_revocation_passes_in_the_hand_signed_form() {
    let (principal, delegate) = (identity(1), identity(2));
    let d = grant(&principal, &delegate, b"pay");
    let rev = hand_signed(
        &principal,
        principal.public_key(),
        AUDIENCE,
        d.id(),
        AUTH_DELEGATION_REVOCATION_V1,
    );
    assert_eq!(verify_delegation_revocation(&rev, &d, AUDIENCE), Ok(()));
}

#[test]
fn a_revocation_signed_by_the_delegate_is_refused() {
    let (principal, delegate) = (identity(1), identity(2));
    let d = grant(&principal, &delegate, b"pay");
    // Signed under the right purpose, over the right id: the signature is
    // valid for the key that made it, so only the signer check refuses this.
    let rev = hand_signed(
        &delegate,
        delegate.public_key(),
        AUDIENCE,
        d.id(),
        AUTH_DELEGATION_REVOCATION_V1,
    );
    assert_eq!(
        verify_delegation_revocation(&rev, &d, AUDIENCE),
        Err(AuthError::NotAuthorised)
    );
}

#[test]
fn a_revocation_signed_by_an_authority_is_refused() {
    let (principal, delegate, authority) = (identity(1), identity(2), identity(3));
    let d = grant(&principal, &delegate, b"pay");
    let rev = hand_signed(
        &authority,
        authority.public_key(),
        AUDIENCE,
        d.id(),
        AUTH_DELEGATION_REVOCATION_V1,
    );
    assert_eq!(
        verify_delegation_revocation(&rev, &d, AUDIENCE),
        Err(AuthError::NotAuthorised)
    );
}

#[test]
fn a_revocation_naming_a_different_delegation_is_refused() {
    let (principal, delegate) = (identity(1), identity(2));
    let d = grant(&principal, &delegate, b"pay");
    let other = grant(&principal, &delegate, b"refund");
    // The principal signs it correctly, for `other`. Only the id check
    // refuses it when presented against `d`.
    let rev = hand_signed(
        &principal,
        principal.public_key(),
        AUDIENCE,
        other.id(),
        AUTH_DELEGATION_REVOCATION_V1,
    );
    assert_eq!(verify_delegation_revocation(&rev, &other, AUDIENCE), Ok(()));
    assert_eq!(
        verify_delegation_revocation(&rev, &d, AUDIENCE),
        Err(AuthError::NotAuthorised)
    );
}

#[test]
fn a_revocation_for_another_audience_is_refused() {
    let (principal, delegate) = (identity(1), identity(2));
    let d = grant(&principal, &delegate, b"pay");
    // Correctly signed, naming the right delegation, but for another
    // audience than the relying party's own.
    let rev = hand_signed(
        &principal,
        principal.public_key(),
        OTHER_AUDIENCE,
        d.id(),
        AUTH_DELEGATION_REVOCATION_V1,
    );
    assert_eq!(
        verify_delegation_revocation(&rev, &d, AUDIENCE),
        Err(AuthError::AudienceMismatch)
    );
}

#[test]
fn a_revocation_must_also_match_the_delegations_audience() {
    // Relying party and revocation agree on the other audience, but the
    // delegation is for AUDIENCE: the delegation's own audience is the check
    // that refuses it.
    let (principal, delegate) = (identity(1), identity(2));
    let d = grant(&principal, &delegate, b"pay");
    let rev = hand_signed(
        &principal,
        principal.public_key(),
        OTHER_AUDIENCE,
        d.id(),
        AUTH_DELEGATION_REVOCATION_V1,
    );
    assert_eq!(
        verify_delegation_revocation(&rev, &d, OTHER_AUDIENCE),
        Err(AuthError::AudienceMismatch)
    );
}

#[test]
fn a_signature_under_the_key_revocation_purpose_is_refused() {
    let (principal, delegate) = (identity(1), identity(2));
    let d = grant(&principal, &delegate, b"pay");
    let rev = hand_signed(
        &principal,
        principal.public_key(),
        AUDIENCE,
        d.id(),
        AUTH_REVOCATION_V1,
    );
    assert_eq!(
        verify_delegation_revocation(&rev, &d, AUDIENCE),
        Err(AuthError::BadSignature)
    );
}

#[test]
fn an_empty_field_is_malformed() {
    let (principal, delegate) = (identity(1), identity(2));
    let d = grant(&principal, &delegate, b"pay");
    let good = Holder::new(&principal, AUDIENCE).revoke_delegation(&d, NOW);
    assert_eq!(verify_delegation_revocation(&good, &d, AUDIENCE), Ok(()));

    let mut no_key = good.clone();
    no_key.principal_key.clear();
    let mut no_audience = good.clone();
    no_audience.audience.clear();
    let mut no_signature = good.clone();
    no_signature.signature.clear();
    for (name, bad) in [
        ("principal_key", no_key),
        ("audience", no_audience),
        ("signature", no_signature),
    ] {
        assert_eq!(
            verify_delegation_revocation(&bad, &d, AUDIENCE),
            Err(AuthError::Malformed),
            "{name}"
        );
    }
}

#[test]
fn a_tampered_issued_at_breaks_the_signature() {
    let (principal, delegate) = (identity(1), identity(2));
    let d = grant(&principal, &delegate, b"pay");
    let mut rev = Holder::new(&principal, AUDIENCE).revoke_delegation(&d, NOW);
    assert_eq!(verify_delegation_revocation(&rev, &d, AUDIENCE), Ok(()));
    rev.issued_at += 1;
    assert_eq!(
        verify_delegation_revocation(&rev, &d, AUDIENCE),
        Err(AuthError::BadSignature)
    );
}

/// No time cutoff: a revocation is accepted at any later time, because
/// `verify_delegation_revocation` takes no clock at all and the delegation
/// being expired does not matter. Control: it verifies right now.
#[test]
fn an_expired_delegation_can_still_be_revoked() {
    let (principal, delegate) = (identity(1), identity(2));
    let d = Holder::new(&principal, AUDIENCE).delegate_to(
        delegate.public_key(),
        bounds(b"pay"),
        NOW - 7200,
        NOW - 3600,
    );
    let rev = Holder::new(&principal, AUDIENCE).revoke_delegation(&d, NOW);
    assert_eq!(verify_delegation_revocation(&rev, &d, AUDIENCE), Ok(()));
}

// ---- AC6: the two revocation statements cannot stand in for each other --------

#[test]
fn a_delegation_revocations_signature_is_not_a_key_revocation() {
    let (principal, delegate) = (identity(1), identity(2));
    let d = grant(&principal, &delegate, b"pay");
    let dr = Holder::new(&principal, AUDIENCE).revoke_delegation(&d, NOW);

    // The delegation revocation's signature, put on a key revocation of the
    // same principal at the same audience.
    let as_key_revocation = Revocation {
        subject_key: principal.public_key(),
        signer_key: principal.public_key(),
        by: RevokedBy::Holder,
        audience: AUDIENCE.to_vec(),
        issued_at: NOW,
        signature: dr.signature.clone(),
    };
    assert_eq!(
        verify_revocation(&as_key_revocation, AUDIENCE, &[]),
        Err(AuthError::BadSignature)
    );
}

/// The purpose is what separates them, not only the byte layout: a key
/// revocation's own signed bytes, signed under the new purpose, are refused by
/// `verify_revocation`. Control: signed under its own purpose, it verifies.
#[test]
fn a_key_revocation_signed_under_the_new_purpose_is_refused() {
    let principal = identity(1);
    let mut key_rev = Holder::new(&principal, AUDIENCE).revoke_self(NOW);
    assert_eq!(verify_revocation(&key_rev, AUDIENCE, &[]), Ok(()));

    key_rev.signature = principal
        .sign_with_purpose(AUTH_DELEGATION_REVOCATION_V1, &key_rev.signing_input())
        .unwrap();
    assert_eq!(
        verify_revocation(&key_rev, AUDIENCE, &[]),
        Err(AuthError::BadSignature)
    );
}

// ---- Holder ---------------------------------------------------------------------

#[test]
fn the_holder_builds_the_documented_statement() {
    let (principal, delegate) = (identity(1), identity(2));
    let d = grant(&principal, &delegate, b"pay");
    let rev = Holder::new(&principal, AUDIENCE).revoke_delegation(&d, NOW + 5);
    assert_eq!(rev.principal_key, principal.public_key());
    assert_eq!(rev.audience, AUDIENCE);
    assert_eq!(rev.delegation_id, d.id());
    assert_eq!(rev.issued_at, NOW + 5);
}

#[test]
#[should_panic(expected = "only the delegation's principal")]
fn a_holder_that_is_not_the_principal_cannot_revoke() {
    let (principal, delegate) = (identity(1), identity(2));
    let d = grant(&principal, &delegate, b"pay");
    let _ = Holder::new(&delegate, AUDIENCE).revoke_delegation(&d, NOW);
}

// ---- Serde ----------------------------------------------------------------------

#[cfg(feature = "serde")]
#[test]
fn serde_round_trips_the_statement() {
    let (principal, delegate) = (identity(1), identity(2));
    let d = grant(&principal, &delegate, b"pay");
    let rev = Holder::new(&principal, AUDIENCE).revoke_delegation(&d, NOW);
    let json = serde_json::to_string(&rev).unwrap();
    let back: DelegationRevocation = serde_json::from_str(&json).unwrap();
    assert_eq!(back, rev);
    assert_eq!(verify_delegation_revocation(&back, &d, AUDIENCE), Ok(()));
}
