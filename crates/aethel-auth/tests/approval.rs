//! The principal's approval: its own statement, checked against the request
//! the relying party is about to perform and against the delegation as it
//! stands now.
//!
//! Every refusal has its control beside it, so a test cannot pass by refusing
//! everything.

use aethel_auth::{
    authorise, check_approval, retired_key, verify_login, verify_succession, Approval, AuthError,
    Bounds, Delegation, Holder, InMemoryNonceStore, VerifyParams,
};
use aethel_core::signing::Identity;

const AUDIENCE: &[u8] = b"https://pay.example.com";
const OTHER_AUDIENCE: &[u8] = b"https://other.example.com";
const NOW: u64 = 1_800_000_000;
const NONE_REVOKED: &[Vec<u8>] = &[];
const REQUEST: [u8; 32] = [0x40; 32];

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

fn params() -> VerifyParams<'static> {
    VerifyParams {
        expected_audience: AUDIENCE,
        now: NOW,
        max_age_secs: 300,
    }
}

fn bounds() -> Bounds {
    Bounds {
        actions: vec![b"pay".to_vec()],
        max_per_invocation: Some(10_000),
        max_total: Some(20_000),
        window_secs: Some(86_400),
        approval_required_above: Some(100),
    }
}

fn grant(principal: &Identity, agent: &Identity) -> Delegation {
    Holder::new(principal, AUDIENCE).delegate_to(agent.public_key(), bounds(), NOW - 10, NOW + 3600)
}

fn approve(signer: &Identity, d: &Delegation, amount: u128, nonce: u8) -> Approval {
    Holder::new(signer, AUDIENCE).approve(d, &REQUEST, b"pay", amount, [nonce; 32], NOW - 1, 60)
}

/// `check_approval` at a relying party that recognises `principal` and has
/// seen the given revocations, for a 500 `pay` of [`REQUEST`].
fn check(
    d: &Delegation,
    a: &Approval,
    principal: &Identity,
    revoked: &[Vec<u8>],
    nonces: &InMemoryNonceStore,
) -> Result<(), AuthError> {
    check_at(d, a, principal, revoked, nonces, params(), 500)
}

fn check_at(
    d: &Delegation,
    a: &Approval,
    principal: &Identity,
    revoked: &[Vec<u8>],
    nonces: &InMemoryNonceStore,
    p: VerifyParams<'_>,
    amount: u128,
) -> Result<(), AuthError> {
    block_on(check_approval(
        d,
        a,
        p,
        &[principal.public_key()],
        revoked,
        &REQUEST,
        b"pay",
        amount,
        nonces,
    ))
}

// ── Its own statement ────────────────────────────────────────────────────────

/// A general step-up from the owner, over any 32 bytes, is not an approval:
/// the approval has its own purpose. Control: a real approval of the same
/// request passes.
#[test]
fn a_step_up_signature_is_not_an_approval() {
    let (owner, agent) = (identity(1), identity(2));
    let d = grant(&owner, &agent);
    let nonces = InMemoryNonceStore::new();

    let real = approve(&owner, &d, 500, 1);
    // The owner's step-up signature, over the approval's own bytes, put on it.
    let mut from_step_up = real.clone();
    from_step_up.nonce = [2; 32];
    from_step_up.signature = owner
        .sign_with_purpose(
            aethel_auth::purposes::AUTH_STEP_UP_V1,
            &from_step_up.signing_input(),
        )
        .expect("signing");
    assert_eq!(
        check(&d, &from_step_up, &owner, NONE_REVOKED, &nonces),
        Err(AuthError::BadSignature)
    );

    check(&d, &real, &owner, NONE_REVOKED, &nonces).expect("a genuine approval");
}

#[test]
fn only_the_principal_can_approve() {
    let (owner, agent) = (identity(3), identity(4));
    let d = grant(&owner, &agent);
    let nonces = InMemoryNonceStore::new();

    let by_agent = approve(&agent, &d, 500, 3);
    assert_eq!(
        check(&d, &by_agent, &owner, NONE_REVOKED, &nonces),
        Err(AuthError::NotAuthorised)
    );
    let mut relabelled = by_agent.clone();
    relabelled.principal_key = owner.public_key();
    assert_eq!(
        check(&d, &relabelled, &owner, NONE_REVOKED, &nonces),
        Err(AuthError::BadSignature)
    );
    check(
        &d,
        &approve(&owner, &d, 500, 4),
        &owner,
        NONE_REVOKED,
        &nonces,
    )
    .expect("the owner");
}

// ── What it names ────────────────────────────────────────────────────────────

#[test]
fn an_approval_is_for_one_amount() {
    let (owner, agent) = (identity(5), identity(6));
    let d = grant(&owner, &agent);
    let nonces = InMemoryNonceStore::new();

    let at_500 = approve(&owner, &d, 500, 5);
    for other in [499, 501, 9_000] {
        assert_eq!(
            check_at(&d, &at_500, &owner, NONE_REVOKED, &nonces, params(), other),
            Err(AuthError::ActionMismatch),
            "approved 500, asked {other}"
        );
    }
    check(&d, &at_500, &owner, NONE_REVOKED, &nonces).expect("the amount it names");
}

#[test]
fn an_approval_names_one_request_action_and_delegation() {
    let (owner, agent) = (identity(7), identity(8));
    let d = grant(&owner, &agent);
    let d2 = Holder::new(&owner, AUDIENCE).delegate_to(
        identity(9).public_key(),
        bounds(),
        NOW - 10,
        NOW + 3600,
    );
    let nonces = InMemoryNonceStore::new();
    let a = approve(&owner, &d, 500, 7);

    let other_request = block_on(check_approval(
        &d,
        &a,
        params(),
        &[owner.public_key()],
        NONE_REVOKED,
        &[0x41; 32],
        b"pay",
        500,
        &nonces,
    ));
    assert_eq!(other_request, Err(AuthError::ActionMismatch));

    let other_action = block_on(check_approval(
        &d,
        &a,
        params(),
        &[owner.public_key()],
        NONE_REVOKED,
        &REQUEST,
        b"refund",
        500,
        &nonces,
    ));
    assert_eq!(other_action, Err(AuthError::ActionMismatch));

    assert_eq!(
        check(&d2, &a, &owner, NONE_REVOKED, &nonces),
        Err(AuthError::ActionMismatch),
        "an approval under one delegation does not approve under another"
    );

    check(&d, &a, &owner, NONE_REVOKED, &nonces).expect("what it names");
}

/// The values a wallet would show are the values that are signed: changing
/// any field after signing breaks the signature.
#[test]
fn every_field_is_signed() {
    let (owner, agent) = (identity(10), identity(11));
    let d = grant(&owner, &agent);
    let a = approve(&owner, &d, 500, 10);
    let mutants: Vec<(&str, Approval)> = vec![
        (
            "audience",
            Approval {
                audience: OTHER_AUDIENCE.to_vec(),
                ..a.clone()
            },
        ),
        (
            "delegation_id",
            Approval {
                delegation_id: [0; 32],
                ..a.clone()
            },
        ),
        (
            "request_digest",
            Approval {
                request_digest: [0; 32],
                ..a.clone()
            },
        ),
        (
            "action",
            Approval {
                action: b"refund".to_vec(),
                ..a.clone()
            },
        ),
        (
            "amount",
            Approval {
                amount: 501,
                ..a.clone()
            },
        ),
        (
            "nonce",
            Approval {
                nonce: [0; 32],
                ..a.clone()
            },
        ),
        (
            "issued_at",
            Approval {
                issued_at: a.issued_at - 1,
                ..a.clone()
            },
        ),
        (
            "expires_at",
            Approval {
                expires_at: a.expires_at + 1,
                ..a.clone()
            },
        ),
    ];
    for (field, m) in mutants {
        assert_ne!(
            m.signing_input(),
            a.signing_input(),
            "{field} is not in the signed bytes"
        );
    }
}

#[test]
fn an_approval_from_another_audience_is_refused() {
    let (owner, agent) = (identity(12), identity(13));
    let d = grant(&owner, &agent);
    let nonces = InMemoryNonceStore::new();
    let elsewhere = Holder::new(&owner, OTHER_AUDIENCE).approve(
        &d,
        &REQUEST,
        b"pay",
        500,
        [12; 32],
        NOW - 1,
        60,
    );
    assert_eq!(
        check(&d, &elsewhere, &owner, NONE_REVOKED, &nonces),
        Err(AuthError::AudienceMismatch)
    );
}

// ── The delegation as it stands now ──────────────────────────────────────────

#[test]
fn an_approval_under_an_expired_or_unsigned_delegation_is_refused() {
    let (owner, agent) = (identity(14), identity(15));
    let h = Holder::new(&owner, AUDIENCE);
    let nonces = InMemoryNonceStore::new();

    let expired = h.delegate_to(agent.public_key(), bounds(), NOW - 7200, NOW - 3600);
    let a = approve(&owner, &expired, 500, 14);
    assert_eq!(
        check(&expired, &a, &owner, NONE_REVOKED, &nonces),
        Err(AuthError::Expired)
    );

    let mut unsigned = grant(&owner, &agent);
    unsigned.signature = vec![0; 3309];
    let a = approve(&owner, &unsigned, 500, 15);
    assert!(check(&unsigned, &a, &owner, NONE_REVOKED, &nonces).is_err());

    let live = grant(&owner, &agent);
    check(
        &live,
        &approve(&owner, &live, 500, 16),
        &owner,
        NONE_REVOKED,
        &nonces,
    )
    .expect("a live delegation");
}

#[test]
fn an_approval_after_a_revocation_or_from_an_unrecognised_principal_is_refused() {
    let (owner, agent) = (identity(17), identity(18));
    let d = grant(&owner, &agent);
    let nonces = InMemoryNonceStore::new();
    let a = approve(&owner, &d, 500, 17);

    assert_eq!(
        check(&d, &a, &owner, &[owner.public_key()], &nonces),
        Err(AuthError::Revoked)
    );
    assert_eq!(
        check(&d, &a, &owner, &[agent.public_key()], &nonces),
        Err(AuthError::Revoked)
    );
    assert_eq!(
        check(&d, &a, &identity(19), NONE_REVOKED, &nonces),
        Err(AuthError::NotAuthorised),
        "the relying party does not recognise this principal"
    );
    check(&d, &a, &owner, NONE_REVOKED, &nonces).expect("nothing revoked");
}

#[test]
fn after_a_succession_the_old_key_no_longer_approves() {
    let (old, new, agent) = (identity(20), identity(21), identity(22));
    let d = grant(&old, &agent);
    let nonces = InMemoryNonceStore::new();

    let before = approve(&old, &d, 500, 20);
    check(&d, &before, &old, NONE_REVOKED, &nonces).expect("before the succession");

    let s = Holder::new(&old, AUDIENCE).name_successor(new.public_key(), NOW - 1);
    verify_succession(&s, AUDIENCE).expect("genuine");
    let revoked = vec![retired_key(&s, AUDIENCE).expect("retires the old key")];
    assert_eq!(revoked[0], old.public_key());

    let after = approve(&old, &d, 500, 21);
    assert_eq!(
        check(&d, &after, &old, &revoked, &nonces),
        Err(AuthError::Revoked)
    );
    assert_eq!(
        authorise(
            &d,
            AUDIENCE,
            &[old.public_key()],
            revoked.as_slice(),
            &agent.public_key(),
            b"pay",
            Some(500),
            NOW
        ),
        Err(AuthError::Revoked),
        "and the old key's delegations end with it"
    );
}

// ── Nonces ───────────────────────────────────────────────────────────────────

/// Another key's statement reusing the owner's nonce does not spend it: claims
/// are per (purpose, signer). Control: the approval itself still cannot be
/// replayed.
#[test]
fn another_keys_login_does_not_burn_the_approval_nonce() {
    let (owner, agent) = (identity(23), identity(24));
    let d = grant(&owner, &agent);
    let nonces = InMemoryNonceStore::new();
    let a = approve(&owner, &d, 500, 23);

    let burn = Holder::new(&agent, AUDIENCE).login(a.nonce, NOW - 1, 60);
    block_on(verify_login(&burn, params(), &nonces)).expect("the agent's own login");
    // The owner's own login with the same nonce is a different purpose too.
    let own_login = Holder::new(&owner, AUDIENCE).login(a.nonce, NOW - 1, 60);
    block_on(verify_login(&own_login, params(), &nonces)).expect("the owner's login");

    check(&d, &a, &owner, NONE_REVOKED, &nonces).expect("the approval is still unspent");
    assert_eq!(
        check(&d, &a, &owner, NONE_REVOKED, &nonces),
        Err(AuthError::NonceAlreadyUsed),
        "a true replay"
    );
}

/// A second instance whose clock lags the store's, or which checks with a
/// different `max_age_secs`, still sees the nonce as spent.
#[test]
fn retention_does_not_depend_on_the_callers_max_age_or_a_lagging_clock() {
    let (owner, agent) = (identity(25), identity(26));
    let d = grant(&owner, &agent);
    let a = Holder::new(&owner, AUDIENCE).approve(&d, &REQUEST, b"pay", 500, [25; 32], NOW, 3_600);
    let nonces = InMemoryNonceStore::new();

    let strict = VerifyParams {
        max_age_secs: 10,
        ..params()
    };
    let strict = VerifyParams {
        now: NOW + 5,
        ..strict
    };
    check_at(&d, &a, &owner, NONE_REVOKED, &nonces, strict, 500).expect("first use");

    // The store's clock has moved on past the strict instance's window.
    nonces.evict_expired(NOW + 120);
    let lenient_and_lagging = VerifyParams {
        now: NOW + 100,
        max_age_secs: 3_600,
        ..params()
    };
    assert_eq!(
        check_at(
            &d,
            &a,
            &owner,
            NONE_REVOKED,
            &nonces,
            lenient_and_lagging,
            500
        ),
        Err(AuthError::NonceAlreadyUsed)
    );
}
