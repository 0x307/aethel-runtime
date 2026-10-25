//! Every statement a holder can produce, verified by the real verifier.
//!
//! These are round trips on purpose. The verifier's own tests build proofs by
//! hand, which proves the verifier self-consistent and nothing more: a builder
//! with a transposed argument would sail past all of them. Here the builder
//! produces and the shipped `verify_*` function checks, so the two halves have
//! to agree about the canonical bytes or nothing passes.

use aethel_auth::{
    authorise, revoke_as_authority, verify_delegation, verify_login, verify_login_for_request,
    verify_revocation, verify_step_up, verify_succession, AuthStrength, Bounds, Holder,
    InMemoryNonceStore, VerifyParams,
};
use aethel_core::signing::Identity;

const CONSOLE: &[u8] = b"https://console.example.com";
const GATEWAY: &[u8] = b"https://gateway.example.com";
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

fn params(audience: &[u8]) -> VerifyParams<'_> {
    VerifyParams {
        expected_audience: audience,
        now: NOW,
        max_age_secs: MAX_AGE,
    }
}

#[test]
fn an_agent_logs_in() {
    let id = identity(110);
    let holder = Holder::new(&id, CONSOLE);
    let nonces = InMemoryNonceStore::new();

    let proof = holder.login([1u8; 32], NOW, 60);
    let out = block_on(verify_login(&proof, params(CONSOLE), &nonces)).expect("round trip");

    assert_eq!(out.public_key, holder.public_key());
    assert_eq!(out.strength, AuthStrength::Proven);
    assert!(out.session_commitment.is_none());
}

#[test]
fn an_agent_logs_in_for_one_request() {
    let id = identity(111);
    let holder = Holder::new(&id, CONSOLE);
    let nonces = InMemoryNonceStore::new();
    let request = [0xD1; 32];

    let proof = holder.login_for_request([2u8; 32], NOW, 60, request);
    assert_eq!(proof.request_digest, Some(request));
    let out = block_on(verify_login_for_request(
        &proof,
        params(CONSOLE),
        &request,
        &nonces,
    ))
    .expect("round trip");
    assert_eq!(out.public_key, holder.public_key());

    // Plain `login` still makes an unbound proof.
    assert_eq!(holder.login([3u8; 32], NOW, 60).request_digest, None);
}

#[test]
fn a_person_steps_up_for_a_sensitive_action() {
    let id = identity(112);
    let holder = Holder::new(&id, CONSOLE);
    let nonces = InMemoryNonceStore::new();

    let action = [0xE1; 32];
    let proof = holder.step_up([4u8; 32], NOW, 60, action);

    block_on(verify_step_up(&proof, params(CONSOLE), &action, &nonces)).expect("round trip");
}

#[test]
fn a_principal_delegates_to_an_agent() {
    let principal_id = identity(114);
    let agent_id = identity(115);
    let principal = Holder::new(&principal_id, CONSOLE);

    let delegation = principal.delegate_to(
        agent_id.public_key(),
        Bounds {
            actions: vec![b"transfer".to_vec()],
            max_per_invocation: Some(500),
            approval_required_above: Some(250),
            ..Bounds::default()
        },
        NOW - 10,
        NOW + 3600,
    );

    verify_delegation(&delegation, CONSOLE, NOW).expect("round trip");

    let obligations = authorise(
        &delegation,
        CONSOLE,
        &agent_id.public_key(),
        b"transfer",
        Some(300),
        NOW,
    )
    .expect("within bounds");

    assert!(
        obligations.human_approval_required,
        "300 is over the principal's 250 threshold"
    );
}

/// Pins the `Delegation::id` doc: signing is deterministic, so identical
/// terms give the same id and share one running total. Control: changing one
/// signed term gives a separate id.
#[test]
fn identical_terms_give_the_same_delegation_id() {
    let principal_id = identity(116);
    let agent_id = identity(117);
    let principal = Holder::new(&principal_id, CONSOLE);
    let grant = |not_before| {
        principal.delegate_to(
            agent_id.public_key(),
            Bounds {
                actions: vec![b"transfer".to_vec()],
                max_total: Some(1_000),
                window_secs: Some(86_400),
                ..Bounds::default()
            },
            not_before,
            NOW + 3600,
        )
    };

    let first = grant(NOW - 10);
    let again = grant(NOW - 10);
    assert_eq!(first.signature, again.signature, "signing is deterministic");
    assert_eq!(first.id(), again.id(), "identical terms, one id");

    let separate = grant(NOW - 11);
    assert_ne!(
        first.id(),
        separate.id(),
        "a changed term is a separate budget"
    );
}

#[test]
fn a_holder_revokes_itself_and_an_authority_revokes_another() {
    let holder_id = identity(116);
    let authority_id = identity(117);
    let holder = Holder::new(&holder_id, CONSOLE);

    let mine = holder.revoke_self(NOW);
    verify_revocation(&mine, CONSOLE, &[]).expect("a holder needs nobody's permission");

    let theirs = revoke_as_authority(&authority_id, holder.public_key(), CONSOLE, NOW);
    verify_revocation(&theirs, CONSOLE, &[authority_id.public_key()])
        .expect("a recognised authority may remove authority");
}

#[test]
fn a_holder_names_its_successor() {
    let old_id = identity(118);
    let new_id = identity(119);
    let old = Holder::new(&old_id, CONSOLE);

    let succession = old.name_successor(new_id.public_key(), NOW);
    verify_succession(&succession, CONSOLE).expect("round trip");
}

#[test]
fn a_holder_bound_to_one_audience_cannot_act_at_another() {
    let id = identity(120);
    let console = Holder::new(&id, CONSOLE);
    let nonces = InMemoryNonceStore::new();

    let proof = console.login([6u8; 32], NOW, 60);

    assert!(
        block_on(verify_login(&proof, params(GATEWAY), &nonces)).is_err(),
        "binding the holder to an audience is what makes per-relying-party \
         identities the natural shape rather than a rule to remember"
    );
}

#[test]
fn two_audiences_mean_two_identities_and_nothing_links_them() {
    // The shape the docs recommend, exercised so it is known to work rather
    // than merely advised.
    let console_id = identity(121);
    let gateway_id = identity(122);

    let console = Holder::new(&console_id, CONSOLE);
    let gateway = Holder::new(&gateway_id, GATEWAY);

    let a = console.login([7u8; 32], NOW, 60);
    let b = gateway.login([8u8; 32], NOW, 60);

    assert_ne!(
        a.public_key, b.public_key,
        "two relying parties must see two unrelated keys, or they can join a \
         holder's activity across them"
    );

    let console_nonces = InMemoryNonceStore::new();
    let gateway_nonces = InMemoryNonceStore::new();
    block_on(verify_login(&a, params(CONSOLE), &console_nonces)).expect("console");
    block_on(verify_login(&b, params(GATEWAY), &gateway_nonces)).expect("gateway");
}
