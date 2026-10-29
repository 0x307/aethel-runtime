//! Tests for step-up and delegation.
//!
//! The theme running through these: authority must be *granted*, never
//! defaulted. Every case where a field was left unset asserts a refusal.

use aethel_auth::{
    approval_digest, authorise, check_approval, purposes, verify_delegation, verify_step_up,
    AuthError, AuthMethod, Bounds, Delegation, InMemoryNonceStore, RemainingObligations,
    StepUpProof, VerifyParams,
};
use aethel_core::signing::Identity;

const AUDIENCE: &[u8] = b"https://console.example.com";
const OTHER_AUDIENCE: &[u8] = b"https://gateway.example.com";
const NOW: u64 = 1_700_000_000;
const MAX_AGE: u64 = 300;

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
        block_on(verify_step_up(
            &proof,
            params(),
            &actually_attempted,
            &nonces
        ))
        .unwrap_err(),
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

const NO_REVOCATIONS: &[Vec<u8>] = &[];

/// `authorise` at a relying party that recognises this delegation's principal
/// and has seen no revocations. For tests about bounds, audience and the
/// delegate; the principal and revocation tests call `authorise` directly.
fn authorise_here(
    d: &Delegation,
    audience: &[u8],
    delegate_key: &[u8],
    action: &[u8],
    amount: Option<u128>,
    now: u64,
) -> Result<RemainingObligations, AuthError> {
    authorise(
        d,
        audience,
        std::slice::from_ref(&d.principal_key),
        NO_REVOCATIONS,
        delegate_key,
        action,
        amount,
        now,
    )
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

    let obligations = authorise_here(
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
    assert!(
        !obligations.is_clear(),
        "a cumulative cap is still the caller's to enforce"
    );
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
        authorise_here(
            &d,
            AUDIENCE,
            &impostor.public_key(),
            b"transfer",
            Some(10),
            NOW
        )
        .unwrap_err(),
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
        authorise_here(
            &d,
            AUDIENCE,
            &delegate.public_key(),
            b"delete_account",
            None,
            NOW
        )
        .unwrap_err(),
        AuthError::NotDelegated
    );
}

#[test]
fn an_empty_allow_list_grants_nothing_rather_than_everything() {
    let principal = identity(42);
    let delegate = identity(43);
    let d = make_delegation(&principal, &delegate, AUDIENCE, Bounds::default());

    assert_eq!(
        authorise_here(&d, AUDIENCE, &delegate.public_key(), b"transfer", None, NOW).unwrap_err(),
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
        authorise_here(
            &d,
            AUDIENCE,
            &delegate.public_key(),
            b"transfer",
            Some(1),
            NOW
        )
        .unwrap_err(),
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
        authorise_here(
            &d,
            AUDIENCE,
            &delegate.public_key(),
            b"transfer",
            Some(501),
            NOW
        )
        .unwrap_err(),
        AuthError::NotDelegated
    );
    assert!(
        authorise_here(
            &d,
            AUDIENCE,
            &delegate.public_key(),
            b"transfer",
            Some(500),
            NOW
        )
        .is_ok(),
        "the ceiling is inclusive"
    );
}

#[test]
fn crossing_the_approval_threshold_reports_an_obligation_rather_than_refusing() {
    let principal = identity(48);
    let delegate = identity(49);
    let d = make_delegation(&principal, &delegate, AUDIENCE, spend_bounds());

    let under = authorise_here(
        &d,
        AUDIENCE,
        &delegate.public_key(),
        b"transfer",
        Some(250),
        NOW,
    )
    .unwrap();
    assert!(!under.human_approval_required, "the threshold is exclusive");

    let over = authorise_here(
        &d,
        AUDIENCE,
        &delegate.public_key(),
        b"transfer",
        Some(251),
        NOW,
    )
    .unwrap();
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
    let mutations: [Mutation; 7] = [
        ("raise the per-invocation ceiling", |d| {
            d.bounds.max_per_invocation = Some(1_000_000)
        }),
        ("add an action", |d| {
            d.bounds.actions.push(b"delete".to_vec())
        }),
        ("remove the approval threshold", |d| {
            d.bounds.approval_required_above = None
        }),
        ("extend the window", |d| d.expires_at += 86_400),
        ("raise the total over the window", |d| {
            d.bounds.max_total = Some(1_000_000)
        }),
        ("shorten the window the total applies over", |d| {
            d.bounds.window_secs = Some(60)
        }),
        ("start the delegation earlier", |d| d.not_before -= 86_400),
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

// ── Approval above the threshold ─────────────────────────────────────────────

/// The relying party's own digest of the request being approved. The crate
/// does not interpret it; these tests only need two different ones.
const REQUEST: [u8; 32] = [0x40; 32];
const OTHER_REQUEST: [u8; 32] = [0x41; 32];

fn approval_by(
    signer: &Identity,
    d: &Delegation,
    audience: &[u8],
    request: [u8; 32],
    nonce: u8,
) -> StepUpProof {
    make_step_up(signer, audience, [nonce; 32], approval_digest(d, &request))
}

/// The principal's approval passes; the agent's own, for the same request
/// under the same delegation, does not. Both halves in one test, so the
/// refusal cannot pass by refusing everything.
#[test]
fn only_the_principal_can_approve_an_over_threshold_request() {
    let principal = identity(60);
    let delegate = identity(61);
    let d = make_delegation(&principal, &delegate, AUDIENCE, spend_bounds());

    let obligations = authorise_here(
        &d,
        AUDIENCE,
        &delegate.public_key(),
        b"transfer",
        Some(400),
        NOW,
    )
    .expect("400 is within the per-invocation ceiling");
    assert!(
        obligations.human_approval_required,
        "400 is above the 250 threshold"
    );

    let nonces = InMemoryNonceStore::new();
    let from_principal = approval_by(&principal, &d, AUDIENCE, REQUEST, 60);
    block_on(check_approval(
        &d,
        &from_principal,
        params(),
        &REQUEST,
        &nonces,
    ))
    .expect("the principal approves");

    let from_agent = approval_by(&delegate, &d, AUDIENCE, REQUEST, 61);
    assert_eq!(
        block_on(check_approval(&d, &from_agent, params(), &REQUEST, &nonces)).unwrap_err(),
        AuthError::NotAuthorised,
        "the agent must not be able to approve its own request"
    );
}

/// An approval is a signature, so there is nothing to hand-build. A step-up
/// carrying the principal's key with a signature by anyone else is refused.
#[test]
fn an_approval_without_the_principals_signature_is_refused() {
    let principal = identity(62);
    let delegate = identity(63);
    let d = make_delegation(&principal, &delegate, AUDIENCE, spend_bounds());
    let nonces = InMemoryNonceStore::new();

    let mut forged = approval_by(&delegate, &d, AUDIENCE, REQUEST, 62);
    forged.public_key = principal.public_key();
    assert_eq!(
        block_on(check_approval(&d, &forged, params(), &REQUEST, &nonces)).unwrap_err(),
        AuthError::BadSignature
    );

    let genuine = approval_by(&principal, &d, AUDIENCE, REQUEST, 63);
    block_on(check_approval(&d, &genuine, params(), &REQUEST, &nonces))
        .expect("the principal's own signature approves");
}

#[test]
fn an_approval_names_one_request() {
    let principal = identity(64);
    let delegate = identity(65);
    let d = make_delegation(&principal, &delegate, AUDIENCE, spend_bounds());
    let nonces = InMemoryNonceStore::new();

    let approval = approval_by(&principal, &d, AUDIENCE, REQUEST, 64);
    assert_eq!(
        block_on(check_approval(
            &d,
            &approval,
            params(),
            &OTHER_REQUEST,
            &nonces
        ))
        .unwrap_err(),
        AuthError::ActionMismatch
    );
    block_on(check_approval(&d, &approval, params(), &REQUEST, &nonces))
        .expect("the request it was signed for");
}

/// Same principal, same request digest, a different delegation: the
/// delegation id inside the approval digest keeps them apart.
#[test]
fn an_approval_names_one_delegation() {
    let principal = identity(66);
    let d1 = make_delegation(&principal, &identity(67), AUDIENCE, spend_bounds());
    let d2 = make_delegation(&principal, &identity(68), AUDIENCE, spend_bounds());
    let nonces = InMemoryNonceStore::new();

    let for_d1 = approval_by(&principal, &d1, AUDIENCE, REQUEST, 66);
    assert_eq!(
        block_on(check_approval(&d2, &for_d1, params(), &REQUEST, &nonces)).unwrap_err(),
        AuthError::ActionMismatch
    );
    block_on(check_approval(&d1, &for_d1, params(), &REQUEST, &nonces))
        .expect("the delegation it was signed for");
}

/// A bare step-up over the request digest alone, the 0.1.0 shape, does not
/// approve: the principal must sign the approval digest.
#[test]
fn a_step_up_over_the_bare_request_is_not_an_approval() {
    let principal = identity(69);
    let d = make_delegation(&principal, &identity(70), AUDIENCE, spend_bounds());
    let nonces = InMemoryNonceStore::new();

    let bare = make_step_up(&principal, AUDIENCE, [69u8; 32], REQUEST);
    assert_eq!(
        block_on(check_approval(&d, &bare, params(), &REQUEST, &nonces)).unwrap_err(),
        AuthError::ActionMismatch
    );
}

#[test]
fn an_approval_from_another_audience_is_refused() {
    let principal = identity(71);
    let delegate = identity(72);
    let d = make_delegation(&principal, &delegate, AUDIENCE, spend_bounds());
    let nonces = InMemoryNonceStore::new();

    let elsewhere = approval_by(&principal, &d, OTHER_AUDIENCE, REQUEST, 71);
    assert_eq!(
        block_on(check_approval(&d, &elsewhere, params(), &REQUEST, &nonces)).unwrap_err(),
        AuthError::AudienceMismatch
    );

    let other_params = VerifyParams {
        expected_audience: OTHER_AUDIENCE,
        ..params()
    };
    assert_eq!(
        block_on(check_approval(
            &d,
            &elsewhere,
            other_params,
            &REQUEST,
            &nonces
        ))
        .unwrap_err(),
        AuthError::AudienceMismatch,
        "a relying party checking at another audience than the delegation's"
    );
}

#[test]
fn an_approval_cannot_be_replayed() {
    let principal = identity(73);
    let d = make_delegation(&principal, &identity(74), AUDIENCE, spend_bounds());
    let nonces = InMemoryNonceStore::new();

    let approval = approval_by(&principal, &d, AUDIENCE, REQUEST, 73);
    block_on(check_approval(&d, &approval, params(), &REQUEST, &nonces)).expect("first use");
    assert_eq!(
        block_on(check_approval(&d, &approval, params(), &REQUEST, &nonces)).unwrap_err(),
        AuthError::NonceAlreadyUsed
    );
}

// ── Principal and revocation ─────────────────────────────────────────────────

/// A delegation is signed by its own principal, so a stranger can make one.
/// It authorises only when the relying party recognises that principal.
#[test]
fn a_delegation_from_an_unrecognised_principal_is_refused() {
    let enrolled = identity(80);
    let stranger = identity(81);
    let delegate = identity(82);
    let from_stranger = make_delegation(&stranger, &delegate, AUDIENCE, spend_bounds());
    let principals = [enrolled.public_key()];

    assert_eq!(
        authorise(
            &from_stranger,
            AUDIENCE,
            &principals,
            NO_REVOCATIONS,
            &delegate.public_key(),
            b"transfer",
            Some(100),
            NOW,
        )
        .unwrap_err(),
        AuthError::NotAuthorised
    );
    assert_eq!(
        authorise(
            &from_stranger,
            AUDIENCE,
            &[],
            NO_REVOCATIONS,
            &delegate.public_key(),
            b"transfer",
            Some(100),
            NOW,
        )
        .unwrap_err(),
        AuthError::NotAuthorised,
        "an empty set recognises nobody"
    );

    let from_enrolled = make_delegation(&enrolled, &delegate, AUDIENCE, spend_bounds());
    let _ = authorise(
        &from_enrolled,
        AUDIENCE,
        &principals,
        NO_REVOCATIONS,
        &delegate.public_key(),
        b"transfer",
        Some(100),
        NOW,
    )
    .expect("the enrolled principal's delegation");
}

#[test]
fn a_revoked_principal_or_delegate_ends_the_delegation() {
    let principal = identity(83);
    let delegate = identity(84);
    let d = make_delegation(&principal, &delegate, AUDIENCE, spend_bounds());
    let principals = [principal.public_key()];

    let run = |revoked: &dyn Fn(&[u8]) -> bool| {
        authorise(
            &d,
            AUDIENCE,
            &principals,
            &revoked,
            &delegate.public_key(),
            b"transfer",
            Some(100),
            NOW,
        )
    };

    let _ = run(&|_: &[u8]| false).expect("nothing revoked");
    assert_eq!(
        run(&|k: &[u8]| k == principal.public_key()).unwrap_err(),
        AuthError::Revoked
    );
    assert_eq!(
        run(&|k: &[u8]| k == delegate.public_key()).unwrap_err(),
        AuthError::Revoked
    );

    let set: std::collections::HashSet<Vec<u8>> = [principal.public_key()].into_iter().collect();
    assert_eq!(
        authorise(
            &d,
            AUDIENCE,
            &principals,
            &set,
            &delegate.public_key(),
            b"transfer",
            Some(100),
            NOW,
        )
        .unwrap_err(),
        AuthError::Revoked,
        "a HashSet of revoked keys"
    );
}

// ── Amount ───────────────────────────────────────────────────────────────────

#[test]
fn no_amount_under_a_bounded_delegation_is_refused() {
    let principal = identity(85);
    let delegate = identity(86);
    for bounds in [
        Bounds {
            max_per_invocation: Some(500),
            ..Bounds::default()
        },
        Bounds {
            max_total: Some(2_000),
            window_secs: Some(86_400),
            ..Bounds::default()
        },
        Bounds {
            approval_required_above: Some(250),
            ..Bounds::default()
        },
    ] {
        let bounds = Bounds {
            actions: vec![b"transfer".to_vec()],
            ..bounds
        };
        let d = make_delegation(&principal, &delegate, AUDIENCE, bounds.clone());
        assert_eq!(
            authorise_here(&d, AUDIENCE, &delegate.public_key(), b"transfer", None, NOW)
                .unwrap_err(),
            AuthError::NotDelegated,
            "None under {bounds:?}"
        );
    }

    let d = make_delegation(&principal, &delegate, AUDIENCE, spend_bounds());
    let zero = authorise_here(
        &d,
        AUDIENCE,
        &delegate.public_key(),
        b"transfer",
        Some(0),
        NOW,
    )
    .expect("Some(0) says there is nothing to count");
    assert!(!zero.human_approval_required);
}

#[test]
fn no_amount_under_a_delegation_with_no_amount_bound_is_accepted() {
    let principal = identity(87);
    let delegate = identity(88);
    let bounds = Bounds {
        actions: vec![b"read".to_vec()],
        ..Bounds::default()
    };
    let d = make_delegation(&principal, &delegate, AUDIENCE, bounds);
    let obligations = authorise_here(&d, AUDIENCE, &delegate.public_key(), b"read", None, NOW)
        .expect("nothing to bound");
    assert!(obligations.is_clear());
}

// ── Delegation id ────────────────────────────────────────────────────────────

#[test]
fn a_delegation_id_is_stable_and_tracks_every_signed_field() {
    let principal = identity(66);
    let delegate = identity(67);
    let d = make_delegation(&principal, &delegate, AUDIENCE, spend_bounds());

    assert_eq!(
        d.id(),
        d.clone().id(),
        "the same delegation has the same id"
    );

    let mut changed = d.clone();
    changed.bounds.max_total = Some(9_999);
    assert_ne!(
        d.id(),
        changed.id(),
        "a different budget is a different delegation"
    );

    let mut resigned = d.clone();
    resigned.signature[0] ^= 0x01;
    assert_ne!(d.id(), resigned.id(), "the id covers the signature");

    let other = make_delegation(&identity(68), &delegate, AUDIENCE, spend_bounds());
    assert_ne!(
        d.id(),
        other.id(),
        "another principal's grant is another delegation"
    );
}
