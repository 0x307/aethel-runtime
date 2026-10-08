//! Tests for step-up and delegation.
//!
//! The theme running through these: authority must be *granted*, never
//! defaulted. Every case where a field was left unset asserts a refusal.

use aethel_auth::{
    authorise, purposes, verify_delegation, verify_step_up, AuthError, AuthMethod, Bounds,
    Delegation, InMemoryNonceStore, StepUpProof, VerifyParams,
};
use aethel_core::signing::Identity;

const AUDIENCE: &[u8] = b"https://console.example.com";
const OTHER_AUDIENCE: &[u8] = b"https://gateway.example.com";
const NOW: u64 = 1_700_000_000;
const MAX_AGE: u64 = 300;

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
        max_age_secs: MAX_AGE,
    }
}

// ── Step-up ──────────────────────────────────────────────────────────────────

fn make_step_up(id: &Identity, audience: &[u8], nonce: [u8; 32], action: [u8; 32]) -> StepUpProof {
    let mut proof = StepUpProof {
        public_key: id.public_key(),
        audience: audience.to_vec(),
        nonce,
        issued_at: NOW - 5,
        expires_at: NOW + 60,
        action_digest: action,
        signature: Vec::new(),
    };
    proof.signature = id
        .sign_with_purpose(purposes::AUTH_STEP_UP_V1, &proof.signing_input())
        .expect("signing");
    proof
}

#[test]
fn a_step_up_authorises_the_action_it_was_signed_for() {
    let id = identity(20);
    let nonces = InMemoryNonceStore::new();
    let action = [0xAA; 32];
    let proof = make_step_up(&id, AUDIENCE, [20u8; 32], action);

    let out = block_on(verify_step_up(&proof, params(), &action, &nonces)).expect("valid step-up");

    assert_eq!(out.method, AuthMethod::StepUp);
    assert_eq!(out.public_key, id.public_key());
}

#[test]
fn a_step_up_for_one_action_does_not_authorise_another() {
    let id = identity(21);
    let nonces = InMemoryNonceStore::new();
    let consented_to = [0xAA; 32];
    let actually_attempted = [0xBB; 32];
    let proof = make_step_up(&id, AUDIENCE, [21u8; 32], consented_to);

    assert_eq!(
        block_on(verify_step_up(&proof, params(), &actually_attempted, &nonces)).unwrap_err(),
        AuthError::ActionMismatch,
        "consent to transfer 5 must not authorise transferring 5000"
    );
}

#[test]
fn swapping_the_action_after_signing_is_refused() {
    let id = identity(22);
    let nonces = InMemoryNonceStore::new();
    let mut proof = make_step_up(&id, AUDIENCE, [22u8; 32], [0xAA; 32]);

    // Tamper with the field but present the tampered value as expected, so the
    // digest comparison passes and only the signature can catch it.
    proof.action_digest = [0xBB; 32];

    assert_eq!(
        block_on(verify_step_up(&proof, params(), &[0xBB; 32], &nonces)).unwrap_err(),
        AuthError::BadSignature,
        "the action digest is inside the signature, not beside it"
    );
}

#[test]
fn a_step_up_cannot_be_replayed() {
    let id = identity(23);
    let nonces = InMemoryNonceStore::new();
    let action = [0xCC; 32];
    let proof = make_step_up(&id, AUDIENCE, [23u8; 32], action);

    block_on(verify_step_up(&proof, params(), &action, &nonces)).expect("first use");
    assert_eq!(
        block_on(verify_step_up(&proof, params(), &action, &nonces)).unwrap_err(),
        AuthError::NonceAlreadyUsed,
        "one consent, one action"
    );
}

#[test]
fn a_login_proof_cannot_be_presented_as_a_step_up() {
    let id = identity(24);
    let nonces = InMemoryNonceStore::new();
    let action = [0xDD; 32];
    let mut proof = make_step_up(&id, AUDIENCE, [24u8; 32], action);

    // Same key, same bytes, signed under the login purpose instead.
    proof.signature = id
        .sign_with_purpose(purposes::AUTH_LOGIN_V1, &proof.signing_input())
        .expect("signing");

    assert_eq!(
        block_on(verify_step_up(&proof, params(), &action, &nonces)).unwrap_err(),
        AuthError::BadSignature
    );
}

// ── Delegation ───────────────────────────────────────────────────────────────

fn make_delegation(
    principal: &Identity,
    delegate: &Identity,
    audience: &[u8],
    bounds: Bounds,
) -> Delegation {
    let mut d = Delegation {
        principal_key: principal.public_key(),
        delegate_key: delegate.public_key(),
        audience: audience.to_vec(),
        bounds,
        not_before: NOW - 10,
        expires_at: NOW + 3600,
        signature: Vec::new(),
    };
    d.signature = principal
        .sign_with_purpose(purposes::AUTH_DELEGATION_V1, &d.signing_input())
        .expect("signing");
    d
}

fn spend_bounds() -> Bounds {
    Bounds {
        actions: vec![b"transfer".to_vec(), b"refund".to_vec()],
        max_per_invocation: Some(500),
        max_total: Some(2_000),
        window_secs: Some(86_400),
        approval_required_above: Some(250),
    }
}

#[test]
fn a_delegate_may_act_within_the_bounds_the_principal_signed() {
    let principal = identity(30);
    let delegate = identity(31);
    let d = make_delegation(&principal, &delegate, AUDIENCE, spend_bounds());

    let obligations = authorise(
        &d,
        AUDIENCE,
        &delegate.public_key(),
        b"transfer",
        Some(100),
        NOW,
    )
    .expect("within bounds");

    assert_eq!(obligations.cumulative_ceiling, Some(2_000));
    assert_eq!(obligations.window_secs, Some(86_400));
    assert!(
        !obligations.human_approval_required,
        "100 is under the 250 approval threshold"
    );
    assert!(!obligations.is_clear(), "a cumulative cap is still the caller's to enforce");
}

#[test]
fn a_delegation_is_valid_at_one_relying_party_and_nowhere_else() {
    let principal = identity(32);
    let delegate = identity(33);
    let d = make_delegation(&principal, &delegate, AUDIENCE, spend_bounds());

    assert_eq!(
        verify_delegation(&d, OTHER_AUDIENCE, NOW).unwrap_err(),
        AuthError::AudienceMismatch,
        "there is deliberately no way to express 'this delegation, everywhere'"
    );
}

#[test]
fn a_valid_delegation_does_not_authorise_a_different_delegate() {
    let principal = identity(34);
    let delegate = identity(35);
    let impostor = identity(36);
    let d = make_delegation(&principal, &delegate, AUDIENCE, spend_bounds());

    assert_eq!(
        authorise(&d, AUDIENCE, &impostor.public_key(), b"transfer", Some(10), NOW).unwrap_err(),
        AuthError::NotDelegated,
        "the delegate key is bound by the principal's signature"
    );
}

#[test]
fn substituting_the_delegate_invalidates_the_signature() {
    let principal = identity(37);
    let delegate = identity(38);
    let impostor = identity(39);
    let mut d = make_delegation(&principal, &delegate, AUDIENCE, spend_bounds());

    d.delegate_key = impostor.public_key();

    assert_eq!(
        verify_delegation(&d, AUDIENCE, NOW).unwrap_err(),
        AuthError::BadSignature,
        "an unbound delegate field would let anyone write themselves in"
    );
}

#[test]
fn an_action_outside_the_allow_list_is_refused() {
    let principal = identity(40);
    let delegate = identity(41);
    let d = make_delegation(&principal, &delegate, AUDIENCE, spend_bounds());

    assert_eq!(
        authorise(&d, AUDIENCE, &delegate.public_key(), b"delete_account", None, NOW).unwrap_err(),
        AuthError::NotDelegated
    );
}

#[test]
fn an_empty_allow_list_grants_nothing_rather_than_everything() {
    let principal = identity(42);
    let delegate = identity(43);
    let d = make_delegation(&principal, &delegate, AUDIENCE, Bounds::default());

    assert_eq!(
        authorise(&d, AUDIENCE, &delegate.public_key(), b"transfer", None, NOW).unwrap_err(),
        AuthError::NotDelegated,
        "a delegation that forgot to say what it allowed must allow nothing"
    );
}

#[test]
fn an_amount_with_no_ceiling_set_is_refused_rather_than_unlimited() {
    let principal = identity(44);
    let delegate = identity(45);
    let bounds = Bounds {
        actions: vec![b"transfer".to_vec()],
        max_per_invocation: None,
        ..Bounds::default()
    };
    let d = make_delegation(&principal, &delegate, AUDIENCE, bounds);

    assert_eq!(
        authorise(&d, AUDIENCE, &delegate.public_key(), b"transfer", Some(1), NOW).unwrap_err(),
        AuthError::NotDelegated,
        "reading an absent ceiling as unlimited turns a forgetful principal \
         into an unbounded one"
    );
}

#[test]
fn an_amount_over_the_per_invocation_ceiling_is_refused() {
    let principal = identity(46);
    let delegate = identity(47);
    let d = make_delegation(&principal, &delegate, AUDIENCE, spend_bounds());

    assert_eq!(
        authorise(&d, AUDIENCE, &delegate.public_key(), b"transfer", Some(501), NOW).unwrap_err(),
        AuthError::NotDelegated
    );
    assert!(
        authorise(&d, AUDIENCE, &delegate.public_key(), b"transfer", Some(500), NOW).is_ok(),
        "the ceiling is inclusive"
    );
}

#[test]
fn crossing_the_approval_threshold_reports_an_obligation_rather_than_refusing() {
    let principal = identity(48);
    let delegate = identity(49);
    let d = make_delegation(&principal, &delegate, AUDIENCE, spend_bounds());

    let under = authorise(&d, AUDIENCE, &delegate.public_key(), b"transfer", Some(250), NOW).unwrap();
    assert!(!under.human_approval_required, "the threshold is exclusive");

    let over = authorise(&d, AUDIENCE, &delegate.public_key(), b"transfer", Some(251), NOW).unwrap();
    assert!(
        over.human_approval_required,
        "above the threshold the caller must obtain a human approval, which \
         this crate cannot do for it"
    );
}

#[test]
fn a_delegation_outside_its_window_is_refused() {
    let principal = identity(50);
    let delegate = identity(51);
    let d = make_delegation(&principal, &delegate, AUDIENCE, spend_bounds());

    assert_eq!(
        verify_delegation(&d, AUDIENCE, d.not_before - 1).unwrap_err(),
        AuthError::Expired,
        "not yet valid"
    );
    assert_eq!(
        verify_delegation(&d, AUDIENCE, d.expires_at).unwrap_err(),
        AuthError::Expired,
        "expiry is exclusive"
    );
}

#[test]
fn tampering_with_any_bound_invalidates_the_signature() {
    let principal = identity(52);
    let delegate = identity(53);

    type Mutation = (&'static str, fn(&mut Delegation));
    let mutations: [Mutation; 4] = [
        ("raise the per-invocation ceiling", |d| {
            d.bounds.max_per_invocation = Some(1_000_000)
        }),
        ("add an action", |d| d.bounds.actions.push(b"delete".to_vec())),
        ("remove the approval threshold", |d| {
            d.bounds.approval_required_above = None
        }),
        ("extend the window", |d| d.expires_at += 86_400),
    ];

    for (label, mutate) in mutations {
        let mut d = make_delegation(&principal, &delegate, AUDIENCE, spend_bounds());
        mutate(&mut d);
        assert_eq!(
            verify_delegation(&d, AUDIENCE, NOW).unwrap_err(),
            AuthError::BadSignature,
            "a delegate must not be able to {label}"
        );
    }
}

#[test]
fn none_and_some_zero_are_different_grants() {
    let principal = identity(54);
    let delegate = identity(55);

    let absent = Bounds {
        actions: vec![b"x".to_vec()],
        max_per_invocation: None,
        ..Bounds::default()
    };
    let zero = Bounds {
        actions: vec![b"x".to_vec()],
        max_per_invocation: Some(0),
        ..Bounds::default()
    };

    let a = make_delegation(&principal, &delegate, AUDIENCE, absent);
    let b = make_delegation(&principal, &delegate, AUDIENCE, zero);

    assert_ne!(
        a.signing_input(),
        b.signing_input(),
        "\"I set no ceiling\" and \"I set a ceiling of zero\" are different \
         statements and must not encode alike"
    );
}
