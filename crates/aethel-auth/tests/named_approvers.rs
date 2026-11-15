//! Named approvers: keys a principal names in a delegation that may sign an
//! `Approval` besides the principal, and nothing else.
//!
//! Every refusal has its control beside it, and every refusal input is built
//! so that the check under test is the only thing that rejects it: the
//! delegations here are properly signed unless a test says otherwise.

use aethel_auth::purposes::{
    AUTH_DELEGATION_REVOCATION_V1, AUTH_DELEGATION_V1, AUTH_DELEGATION_V2,
};
use aethel_auth::{
    authorise, check_approval, verify_delegation, verify_delegation_revocation, Approval,
    AuthError, Bounds, Delegation, DelegationRevocation, Holder, InMemoryNonceStore, VerifyParams,
};
use aethel_core::signing::Identity;

const AUDIENCE: &[u8] = b"https://pay.example.com";
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

fn bounds() -> Bounds {
    Bounds {
        actions: vec![b"pay".to_vec()],
        max_per_invocation: Some(10_000),
        max_total: Some(20_000),
        window_secs: Some(86_400),
        approval_required_above: Some(100),
        approvers: Vec::new(),
    }
}

fn grant(principal: &Identity, delegate: &Identity, approvers: Vec<Vec<u8>>) -> Delegation {
    Holder::new(principal, AUDIENCE).delegate_to_with_approvers(
        delegate.public_key(),
        bounds(),
        approvers,
        NOW - 10,
        NOW + 3600,
    )
}

fn approve(signer: &Identity, d: &Delegation, nonce: u8) -> Approval {
    Holder::new(signer, AUDIENCE).approve(d, &REQUEST, b"pay", 500, [nonce; 32], NOW - 1, 60)
}

fn params() -> VerifyParams<'static> {
    VerifyParams {
        expected_audience: AUDIENCE,
        now: NOW,
        max_age_secs: 300,
    }
}

fn check(
    d: &Delegation,
    a: &Approval,
    principal: &Identity,
    revoked: &[Vec<u8>],
) -> Result<(), AuthError> {
    block_on(check_approval(
        d,
        a,
        params(),
        &[principal.public_key()],
        revoked,
        NONE_DELEGATIONS_REVOKED,
        &REQUEST,
        b"pay",
        500,
        &InMemoryNonceStore::new(),
    ))
}

// ---- who may approve ---------------------------------------------------------

#[test]
fn a_named_approver_can_approve() {
    let (owner, agent, a) = (identity(1), identity(2), identity(3));
    let d = grant(&owner, &agent, vec![a.public_key()]);
    check(&d, &approve(&a, &d, 1), &owner, NONE_REVOKED).expect("the named approver");
}

#[test]
fn the_principal_still_approves_a_delegation_that_names_approvers() {
    let (owner, agent, a) = (identity(1), identity(2), identity(3));
    let d = grant(&owner, &agent, vec![a.public_key()]);
    check(&d, &approve(&owner, &d, 1), &owner, NONE_REVOKED).expect("the principal");
}

#[test]
fn an_unnamed_key_cannot_approve() {
    let (owner, agent, a, b) = (identity(1), identity(2), identity(3), identity(4));
    let d = grant(&owner, &agent, vec![a.public_key()]);
    assert_eq!(
        check(&d, &approve(&b, &d, 1), &owner, NONE_REVOKED),
        Err(AuthError::NotAuthorised)
    );
    // Control: the named approver passes the same call.
    check(&d, &approve(&a, &d, 2), &owner, NONE_REVOKED).expect("A");
}

#[test]
fn the_delegate_cannot_approve() {
    let (owner, agent) = (identity(1), identity(2));
    let d = grant(&owner, &agent, vec![identity(3).public_key()]);
    assert_eq!(
        check(&d, &approve(&agent, &d, 1), &owner, NONE_REVOKED),
        Err(AuthError::NotAuthorised)
    );
}

#[test]
fn a_revoked_approver_is_refused() {
    let (owner, agent, a) = (identity(1), identity(2), identity(3));
    let d = grant(&owner, &agent, vec![a.public_key()]);
    let approval = approve(&a, &d, 1);
    assert_eq!(
        check(&d, &approval, &owner, &[a.public_key()]),
        Err(AuthError::Revoked)
    );
    // Control: with nothing revoked the same approval passes.
    check(&d, &approval, &owner, NONE_REVOKED).expect("not revoked");
}

#[test]
fn an_unnamed_key_that_is_revoked_is_still_not_authorised() {
    // Not named, so it never reaches the revocation check, and the answer does
    // not say whether the key is revoked.
    let (owner, agent, a, b) = (identity(1), identity(2), identity(3), identity(4));
    let d = grant(&owner, &agent, vec![a.public_key()]);
    assert_eq!(
        check(&d, &approve(&b, &d, 1), &owner, &[b.public_key()]),
        Err(AuthError::NotAuthorised)
    );
}

#[test]
fn an_approvers_approval_is_for_the_delegation_that_names_it() {
    let (owner, agent, a) = (identity(1), identity(2), identity(3));
    let names_a = grant(&owner, &agent, vec![a.public_key()]);
    let names_nobody = grant(&owner, &agent, Vec::new());
    assert_eq!(
        check(
            &names_nobody,
            &approve(&a, &names_nobody, 1),
            &owner,
            NONE_REVOKED
        ),
        Err(AuthError::NotAuthorised)
    );
    // Control: the delegation that names A accepts it.
    check(&names_a, &approve(&a, &names_a, 2), &owner, NONE_REVOKED).expect("names A");
}

// ---- approvers only approve --------------------------------------------------

#[test]
fn an_approver_cannot_revoke_the_delegation() {
    let (owner, agent, a) = (identity(1), identity(2), identity(3));
    let d = grant(&owner, &agent, vec![a.public_key()]);

    let sign_as = |signer: &Identity, claimed_signer: Vec<u8>| {
        let mut rev = DelegationRevocation {
            principal_key: claimed_signer,
            audience: AUDIENCE.to_vec(),
            delegation_id: d.id(),
            issued_at: NOW,
            signature: Vec::new(),
        };
        rev.signature = signer
            .sign_with_purpose(AUTH_DELEGATION_REVOCATION_V1, &rev.signing_input())
            .unwrap();
        rev
    };

    // The approver signs, as itself.
    assert_eq!(
        verify_delegation_revocation(&sign_as(&a, a.public_key()), &d, AUDIENCE),
        Err(AuthError::NotAuthorised)
    );
    // The approver signs, claiming to be the principal.
    assert_eq!(
        verify_delegation_revocation(&sign_as(&a, owner.public_key()), &d, AUDIENCE),
        Err(AuthError::BadSignature)
    );
    // Control: the principal's own revocation passes.
    verify_delegation_revocation(&sign_as(&owner, owner.public_key()), &d, AUDIENCE)
        .expect("the principal");
}

#[test]
fn an_approver_cannot_sign_a_delegation_for_the_principal() {
    let (owner, agent, a) = (identity(1), identity(2), identity(3));
    let at = |d: &Delegation| authorise_with_principals(&owner.public_key())(d);

    // The approver delegates as itself: not an enrolled principal.
    let by_a =
        Holder::new(&a, AUDIENCE).delegate_to(agent.public_key(), bounds(), NOW - 10, NOW + 3600);
    assert_eq!(at(&by_a), Err(AuthError::NotAuthorised));

    // The approver signs but names the principal as the signer.
    let mut forged = by_a.clone();
    forged.principal_key = owner.public_key();
    assert_eq!(at(&forged), Err(AuthError::BadSignature));

    // Control: the principal's own delegation passes.
    let real = grant(&owner, &agent, vec![a.public_key()]);
    assert!(at(&real).is_ok());
}

fn authorise_with_principals(
    principal: &[u8],
) -> impl Fn(&Delegation) -> Result<aethel_auth::RemainingObligations, AuthError> + '_ {
    move |d| {
        authorise(
            d,
            AUDIENCE,
            &[principal.to_vec()],
            NONE_REVOKED,
            NONE_DELEGATIONS_REVOKED,
            &d.delegate_key,
            b"pay",
            Some(50),
            NOW,
        )
    }
}

#[test]
fn an_approver_is_not_the_delegate() {
    let (owner, agent, a) = (identity(1), identity(2), identity(3));
    let d = grant(&owner, &agent, vec![a.public_key()]);
    let as_delegate = |key: &[u8]| {
        authorise(
            &d,
            AUDIENCE,
            &[owner.public_key()],
            NONE_REVOKED,
            NONE_DELEGATIONS_REVOKED,
            key,
            b"pay",
            Some(50),
            NOW,
        )
        .map(|_| ())
    };
    assert_eq!(as_delegate(&a.public_key()), Err(AuthError::NotDelegated));
    // Control: the real delegate passes.
    assert_eq!(as_delegate(&agent.public_key()), Ok(()));
}

// ---- version 1 and version 2 ---------------------------------------------------

#[test]
fn empty_approvers_is_version_1_exactly_as_delegate_to_signs_it() {
    let (owner, agent) = (identity(1), identity(2));
    let holder = Holder::new(&owner, AUDIENCE);
    let plain = holder.delegate_to(agent.public_key(), bounds(), NOW - 10, NOW + 3600);
    let empty = grant(&owner, &agent, Vec::new());
    assert_eq!(plain, empty);
    assert_eq!(plain.id(), empty.id());
    assert_eq!(plain.to_bytes()[..2], [0x01, 0x01]);
    verify_delegation(&plain, AUDIENCE, NOW).expect("v1 verifies");
}

#[test]
fn approvers_make_a_version_2_delegation() {
    let (owner, agent, a) = (identity(1), identity(2), identity(3));
    let v1 = grant(&owner, &agent, Vec::new());
    let v2 = grant(&owner, &agent, vec![a.public_key()]);
    assert_eq!(v2.to_bytes()[..2], [0x01, 0x02]);
    assert_ne!(v1.id(), v2.id());
    // The signed bytes are the v1 bytes, then the count and each approver.
    let mut expected = v1.signing_input();
    expected.extend_from_slice(&1u32.to_be_bytes());
    expected.extend_from_slice(&(a.public_key().len() as u32).to_be_bytes());
    expected.extend_from_slice(&a.public_key());
    assert_eq!(v2.signing_input(), expected);
    verify_delegation(&v2, AUDIENCE, NOW).expect("v2 verifies");
}

#[test]
fn a_version_1_delegation_cannot_be_upgraded_without_a_new_signature() {
    let (owner, agent, a) = (identity(1), identity(2), identity(3));
    let v1 = grant(&owner, &agent, Vec::new());
    let mut upgraded = v1.clone();
    upgraded.bounds.approvers = vec![a.public_key()];
    assert_eq!(
        verify_delegation(&upgraded, AUDIENCE, NOW),
        Err(AuthError::BadSignature)
    );
    // Control: the original verifies.
    verify_delegation(&v1, AUDIENCE, NOW).expect("v1");
}

#[test]
fn a_version_2_delegation_cannot_be_downgraded_without_a_new_signature() {
    let (owner, agent, a) = (identity(1), identity(2), identity(3));
    let v2 = grant(&owner, &agent, vec![a.public_key()]);
    let mut downgraded = v2.clone();
    downgraded.bounds.approvers.clear();
    assert_eq!(
        verify_delegation(&downgraded, AUDIENCE, NOW),
        Err(AuthError::BadSignature)
    );
    // Control: the original verifies.
    verify_delegation(&v2, AUDIENCE, NOW).expect("v2");
}

/// The two versions are separated by purpose as well as by bytes: a signature
/// made under the other version's purpose never verifies, even over the right
/// bytes.
#[test]
fn a_delegation_signature_under_the_other_versions_purpose_is_refused() {
    let (owner, agent, a) = (identity(1), identity(2), identity(3));
    let resign = |d: &Delegation, purpose: &[u8]| {
        let mut r = d.clone();
        r.signature = owner
            .sign_with_purpose(purpose, &r.signing_input())
            .unwrap();
        r
    };
    let v1 = grant(&owner, &agent, Vec::new());
    let v2 = grant(&owner, &agent, vec![a.public_key()]);

    // v2 bytes under the v1 purpose, and v1 bytes under the v2 purpose.
    assert_eq!(
        verify_delegation(&resign(&v2, AUTH_DELEGATION_V1), AUDIENCE, NOW),
        Err(AuthError::BadSignature)
    );
    assert_eq!(
        verify_delegation(&resign(&v1, AUTH_DELEGATION_V2), AUDIENCE, NOW),
        Err(AuthError::BadSignature)
    );
    // Control: each under its own purpose verifies.
    verify_delegation(&resign(&v2, AUTH_DELEGATION_V2), AUDIENCE, NOW).expect("v2/V2");
    verify_delegation(&resign(&v1, AUTH_DELEGATION_V1), AUDIENCE, NOW).expect("v1/V1");
}

// ---- limits ---------------------------------------------------------------------

fn keys(n: u8) -> Vec<Vec<u8>> {
    (0..n).map(|i| identity(100 + i).public_key()).collect()
}

#[test]
fn eight_distinct_approvers_pass() {
    let (owner, agent) = (identity(1), identity(2));
    let d = grant(&owner, &agent, keys(8));
    verify_delegation(&d, AUDIENCE, NOW).expect("8 distinct keys");
}

#[test]
fn nine_approvers_are_malformed() {
    let (owner, agent) = (identity(1), identity(2));
    let d = grant(&owner, &agent, keys(9));
    assert_eq!(
        verify_delegation(&d, AUDIENCE, NOW),
        Err(AuthError::Malformed)
    );
}

#[test]
fn a_duplicate_approver_is_malformed() {
    let (owner, agent) = (identity(1), identity(2));
    let mut list = keys(3);
    list.push(list[0].clone());
    let d = grant(&owner, &agent, list);
    assert_eq!(
        verify_delegation(&d, AUDIENCE, NOW),
        Err(AuthError::Malformed)
    );
}

#[test]
fn an_empty_approver_key_is_malformed() {
    let (owner, agent) = (identity(1), identity(2));
    let mut list = keys(2);
    list.push(Vec::new());
    let d = grant(&owner, &agent, list);
    assert_eq!(
        verify_delegation(&d, AUDIENCE, NOW),
        Err(AuthError::Malformed)
    );
}

#[test]
fn the_principal_as_approver_is_malformed() {
    let (owner, agent) = (identity(1), identity(2));
    let mut list = keys(2);
    list.push(owner.public_key());
    let d = grant(&owner, &agent, list);
    assert_eq!(
        verify_delegation(&d, AUDIENCE, NOW),
        Err(AuthError::Malformed)
    );
}

#[test]
fn the_delegate_as_approver_is_malformed() {
    let (owner, agent) = (identity(1), identity(2));
    let mut list = keys(2);
    list.push(agent.public_key());
    let d = grant(&owner, &agent, list);
    assert_eq!(
        verify_delegation(&d, AUDIENCE, NOW),
        Err(AuthError::Malformed)
    );
}

/// The limits run before the signature, so a delegation that breaks one is
/// `Malformed` whether or not it is signed, and the answer does not depend on
/// the signature.
#[test]
fn the_limits_are_checked_before_the_signature() {
    let (owner, agent) = (identity(1), identity(2));
    let mut d = grant(&owner, &agent, keys(9));
    d.signature = vec![0xAA; 16];
    assert_eq!(
        verify_delegation(&d, AUDIENCE, NOW),
        Err(AuthError::Malformed)
    );
    // Control: 8 approvers with the same unusable signature get past the
    // limits and are stopped by the signature instead.
    let mut ok = grant(&owner, &agent, keys(8));
    ok.signature = vec![0xAA; 16];
    assert_ne!(
        verify_delegation(&ok, AUDIENCE, NOW),
        Err(AuthError::Malformed)
    );
}

#[test]
fn a_delegation_with_too_many_approvers_is_refused_by_authorise_and_check_approval() {
    let (owner, agent) = (identity(1), identity(2));
    let d = grant(&owner, &agent, keys(9));
    assert_eq!(
        authorise_with_principals(&owner.public_key())(&d),
        Err(AuthError::Malformed)
    );
    let a = approve(&owner, &d, 1);
    assert_eq!(
        check(&d, &a, &owner, NONE_REVOKED),
        Err(AuthError::Malformed)
    );
}

// ---- serde ----------------------------------------------------------------------

#[test]
fn an_empty_approvers_list_serialises_exactly_as_0_3_did() {
    let (owner, agent) = (identity(1), identity(2));
    let v1 = serde_json::to_value(grant(&owner, &agent, Vec::new())).unwrap();
    assert!(v1["bounds"].get("approvers").is_none());
    // And with approvers it is present, and round-trips.
    let d = grant(&owner, &agent, keys(2));
    let json = serde_json::to_string(&d).unwrap();
    assert!(json.contains("\"approvers\""));
    assert_eq!(serde_json::from_str::<Delegation>(&json).unwrap(), d);
}

#[test]
fn a_0_3_delegation_json_without_approvers_decodes() {
    let (owner, agent) = (identity(1), identity(2));
    let d = grant(&owner, &agent, Vec::new());
    let json = serde_json::to_string(&d).unwrap();
    assert!(!json.contains("approvers"));
    let back: Delegation = serde_json::from_str(&json).unwrap();
    assert!(back.bounds.approvers.is_empty());
    assert_eq!(back, d);
}

#[test]
fn an_approval_json_from_0_3_decodes_and_a_new_one_writes_approver_key() {
    let (owner, agent) = (identity(1), identity(2));
    let d = grant(&owner, &agent, Vec::new());
    let a = approve(&owner, &d, 1);

    let new_json = serde_json::to_string(&a).unwrap();
    assert!(new_json.contains("\"approver_key\""));
    assert!(!new_json.contains("\"principal_key\""));

    // 0.3 wrote the same value under the old name.
    let old_json = new_json.replace("\"approver_key\"", "\"principal_key\"");
    let from_old: Approval = serde_json::from_str(&old_json).unwrap();
    assert_eq!(from_old, a);
    // Control: the new spelling decodes to the same value.
    assert_eq!(serde_json::from_str::<Approval>(&new_json).unwrap(), a);
}
