//! Every statement a holder can produce, verified by the real verifier.
//!
//! These are round trips on purpose. The verifier's own tests build proofs by
//! hand, which proves the verifier self-consistent and nothing more: a builder
//! with a transposed argument would sail past all of them. Here the builder
//! produces and the shipped `verify_*` function checks, so the two halves have
//! to agree about the canonical bytes or nothing passes.

use aethel_auth::{
    authorise, revoke_as_authority, verify_delegation, verify_enrolment, verify_login,
    verify_revocation, verify_session, verify_step_up, verify_succession, AuthStrength, Bounds,
    Holder, InMemoryInviteStore, InMemoryNonceStore, InMemorySessionStore, Session, SessionSecret,
    SessionStore, SessionToken, VerifyParams,
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

    let proof = holder.login([1u8; 32], NOW, 60, None);
    let out = block_on(verify_login(&proof, params(CONSOLE), &nonces)).expect("round trip");

    assert_eq!(out.public_key, holder.public_key());
    assert_eq!(out.strength, AuthStrength::Proven);
    assert!(out.session_commitment.is_none());
}

#[test]
fn a_person_logs_in_and_the_session_carries_them() {
    let id = identity(111);
    let holder = Holder::new(&id, CONSOLE);
    let nonces = InMemoryNonceStore::new();
    let store: InMemorySessionStore<&'static str> = InMemorySessionStore::new();

    // 1. The holder picks a session secret and commits to it inside the login
    //    signature.
    let secret = SessionSecret::from_bytes([0x5A; 32]);
    let proof = holder.login([2u8; 32], NOW, 60, Some(&secret));

    let out = block_on(verify_login(&proof, params(CONSOLE), &nonces)).expect("login");
    let commitment = out.session_commitment.expect("a person asked for a session");

    // 2. The server checks the secret it is handed against what was signed.
    assert_eq!(
        commitment,
        secret.commitment(),
        "the secret must be the one the signature committed to"
    );

    // 3. A session opens, and the secret goes to the browser exactly once.
    let token = SessionToken::from_bytes([3u8; 32]);
    block_on(store.create(Session::new(
        &token,
        secret.clone(),
        "staff-1",
        CONSOLE.to_vec(),
        out.strength,
        1,
        NOW,
        NOW + 3600,
    )))
    .unwrap();

    // 4. Every later request carries the token and a MAC over it.
    let binding = b"GET /reports/42|req-0001";
    let mac = secret.mac(binding);
    let session =
        block_on(verify_session(&store, &token, binding, &mac, NOW, 1)).expect("session request");

    assert_eq!(session.actor, "staff-1");
    assert!(session.stepped_up_at.is_none(), "no step-up yet");
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
fn a_holder_enrols_against_an_invite() {
    let id = identity(113);
    let holder = Holder::new(&id, CONSOLE);
    let invites = InMemoryInviteStore::new();
    invites.issue(b"invite-abc".to_vec(), NOW + 3600);

    let proof = holder.enrol(b"invite-abc".to_vec(), [5u8; 32], NOW, 60);
    let (enrolled, ()) = block_on(verify_enrolment(&proof, params(CONSOLE), &invites)).expect("enrol");

    assert_eq!(enrolled.public_key, holder.public_key());
    assert!(invites.is_empty());
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

    let proof = console.login([6u8; 32], NOW, 60, None);

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

    let a = console.login([7u8; 32], NOW, 60, None);
    let b = gateway.login([8u8; 32], NOW, 60, None);

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
