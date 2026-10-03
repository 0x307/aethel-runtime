//! The directory's lifecycle: enrol, revoke, succeed.
//!
//! The properties worth pinning: a revoked key never authenticates again and
//! is never re-bound; only the outgoing key moves an account; an old
//! succession cannot be replayed once the account has moved on; and an
//! authority can remove but never grant.

use aethel_auth::{
    enrol, revoke, revoke_as_authority, succeed, AuthError, Directory, EnrolledIdentity, Holder,
    InMemoryDirectory, InMemoryInviteStore, VerifyParams,
};
use aethel_core::signing::Identity;

const AUDIENCE: &[u8] = b"https://console.example.com/t/1";
const NOW: u64 = 1_700_000_000;

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

type Dir = InMemoryDirectory<String, (), fn(&EnrolledIdentity, ()) -> String>;

fn mint(enrolled: &EnrolledIdentity, _: ()) -> String {
    format!("account-{}", enrolled.public_key[0])
}

/// A directory with `ids` enrolled, one account each.
fn directory_with(ids: &[&Identity]) -> Dir {
    let dir: Dir = InMemoryDirectory::new(mint as fn(&EnrolledIdentity, ()) -> String);
    let invites = InMemoryInviteStore::new();
    let params = VerifyParams { expected_audience: AUDIENCE, now: NOW, max_age_secs: 300 };
    for (i, id) in ids.iter().enumerate() {
        let code = format!("invite-{i}").into_bytes();
        invites.issue(code.clone(), NOW + 3600);
        let proof = Holder::new(id, AUDIENCE).enrol(code, [i as u8; 32], NOW, 60);
        block_on(enrol(&proof, params, &invites, &dir)).expect("enrol");
    }
    dir
}

fn resolve(dir: &Dir, id: &Identity) -> Option<String> {
    block_on(dir.resolve(&id.public_key())).unwrap()
}

#[test]
fn a_holder_revokes_its_own_key_and_it_stops_resolving() {
    let alice = identity(1);
    let dir = directory_with(&[&alice]);
    let account = resolve(&dir, &alice).unwrap();

    let statement = Holder::new(&alice, AUDIENCE).revoke_self(NOW);
    assert_eq!(block_on(revoke(&statement, AUDIENCE, &[], &dir)).unwrap(), Some(account));
    assert_eq!(resolve(&dir, &alice), None);

    // Revoking again is not an error, and reports nothing to revoke.
    assert_eq!(block_on(revoke(&statement, AUDIENCE, &[], &dir)).unwrap(), None);
}

#[test]
fn a_revoked_key_can_never_enrol_again() {
    let alice = identity(2);
    let dir = directory_with(&[&alice]);
    block_on(revoke(&Holder::new(&alice, AUDIENCE).revoke_self(NOW), AUDIENCE, &[], &dir)).unwrap();

    let invites = InMemoryInviteStore::new();
    invites.issue(b"second-chance".to_vec(), NOW + 3600);
    let proof = Holder::new(&alice, AUDIENCE).enrol(b"second-chance".to_vec(), [9; 32], NOW, 60);
    let params = VerifyParams { expected_audience: AUDIENCE, now: NOW, max_age_secs: 300 };
    assert_eq!(block_on(enrol(&proof, params, &invites, &dir)).unwrap_err(), AuthError::KeyAlreadyEnrolled);
}

#[test]
fn an_authority_may_revoke_another_key_and_nobody_else_may() {
    let (admin, bob, mallory) = (identity(3), identity(4), identity(5));
    let dir = directory_with(&[&admin, &bob, &mallory]);

    // Mallory is not a recognised authority.
    let forged = revoke_as_authority(&mallory, bob.public_key(), AUDIENCE, NOW);
    assert_eq!(block_on(revoke(&forged, AUDIENCE, &[admin.public_key()], &dir)).unwrap_err(), AuthError::NotAuthorised);
    assert!(resolve(&dir, &bob).is_some());

    let real = revoke_as_authority(&admin, bob.public_key(), AUDIENCE, NOW);
    assert!(block_on(revoke(&real, AUDIENCE, &[admin.public_key()], &dir)).unwrap().is_some());
    assert_eq!(resolve(&dir, &bob), None);
}

#[test]
fn a_revocation_for_another_relying_party_is_refused() {
    let alice = identity(6);
    let dir = directory_with(&[&alice]);
    let elsewhere = Holder::new(&alice, b"https://other.example".to_vec()).revoke_self(NOW);
    assert_eq!(block_on(revoke(&elsewhere, AUDIENCE, &[], &dir)).unwrap_err(), AuthError::AudienceMismatch);
    assert!(resolve(&dir, &alice).is_some());
}

#[test]
fn succession_moves_the_account_to_the_new_key() {
    let (old, new) = (identity(7), identity(8));
    let dir = directory_with(&[&old]);
    let account = resolve(&dir, &old).unwrap();

    let statement = Holder::new(&old, AUDIENCE).name_successor(new.public_key(), NOW);
    assert_eq!(block_on(succeed(&statement, AUDIENCE, &dir)).unwrap(), account);
    assert_eq!(resolve(&dir, &new), Some(account), "same account, new key");
    assert_eq!(resolve(&dir, &old), None, "the old key is retired");
}

#[test]
fn an_old_succession_cannot_be_replayed_after_the_account_moves_on() {
    let (k1, k2, k3) = (identity(9), identity(10), identity(11));
    let dir = directory_with(&[&k1]);
    let first = Holder::new(&k1, AUDIENCE).name_successor(k2.public_key(), NOW);
    block_on(succeed(&first, AUDIENCE, &dir)).unwrap();
    block_on(succeed(&Holder::new(&k2, AUDIENCE).name_successor(k3.public_key(), NOW), AUDIENCE, &dir)).unwrap();

    assert!(block_on(succeed(&first, AUDIENCE, &dir)).is_err(), "k1 is no longer live and k2 is retired");
    assert!(resolve(&dir, &k3).is_some());
    assert_eq!(resolve(&dir, &k2), None);
}

#[test]
fn a_revoked_key_cannot_hand_its_account_over() {
    let (old, new) = (identity(12), identity(13));
    let dir = directory_with(&[&old]);
    block_on(revoke(&Holder::new(&old, AUDIENCE).revoke_self(NOW), AUDIENCE, &[], &dir)).unwrap();

    let statement = Holder::new(&old, AUDIENCE).name_successor(new.public_key(), NOW);
    assert_eq!(block_on(succeed(&statement, AUDIENCE, &dir)).unwrap_err(), AuthError::NotAuthorised);
    assert_eq!(resolve(&dir, &new), None);
}

#[test]
fn a_successor_already_bound_to_another_account_is_refused() {
    let (alice, bob) = (identity(14), identity(15));
    let dir = directory_with(&[&alice, &bob]);
    let statement = Holder::new(&alice, AUDIENCE).name_successor(bob.public_key(), NOW);
    assert_eq!(block_on(succeed(&statement, AUDIENCE, &dir)).unwrap_err(), AuthError::KeyAlreadyEnrolled);
    assert_ne!(resolve(&dir, &alice), resolve(&dir, &bob), "neither account moved");
}

#[test]
fn only_the_outgoing_key_can_name_a_successor() {
    let (alice, mallory) = (identity(16), identity(17));
    let dir = directory_with(&[&alice]);
    // Mallory signs a statement claiming to move Alice's account to herself.
    let mut forged = Holder::new(&mallory, AUDIENCE).name_successor(mallory.public_key(), NOW);
    forged.from_key = alice.public_key();
    assert!(block_on(succeed(&forged, AUDIENCE, &dir)).is_err());
    assert!(resolve(&dir, &alice).is_some());
}
