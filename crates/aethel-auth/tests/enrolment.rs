//! Tests for enrolment.
//!
//! The property worth pinning: an invite is spent once, it cannot be
//! redirected, and a failed attempt does not destroy it.

use aethel_auth::{
    purposes, verify_enrolment, AuthError, AuthMethod, AuthStrength, EnrolmentProof,
    InMemoryInviteStore, VerifyParams,
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

fn make_proof(id: &Identity, audience: &[u8], invite: &[u8], nonce: [u8; 32]) -> EnrolmentProof {
    let mut p = EnrolmentProof {
        public_key: id.public_key(),
        audience: audience.to_vec(),
        invite_id: invite.to_vec(),
        nonce,
        issued_at: NOW - 5,
        expires_at: NOW + 60,
        signature: Vec::new(),
    };
    p.signature = id
        .sign_with_purpose(purposes::AUTH_ENROL_V1, &p.signing_input())
        .expect("signing");
    p
}

fn store_with(invite: &[u8]) -> InMemoryInviteStore {
    let s = InMemoryInviteStore::new();
    s.issue(invite.to_vec(), NOW + 3600);
    s
}

#[test]
fn a_holder_enrols_by_proving_possession_against_an_invite() {
    let id = identity(90);
    let invites = store_with(b"invite-1");
    let proof = make_proof(&id, AUDIENCE, b"invite-1", [90u8; 32]);

    let (enrolled, ()) = block_on(verify_enrolment(&proof, params(), &invites)).expect("valid enrolment");

    assert_eq!(enrolled.public_key, id.public_key());
    assert_eq!(enrolled.invite_id, b"invite-1");
    assert_eq!(enrolled.strength, AuthStrength::Proven);
    assert_eq!(enrolled.method, AuthMethod::Enrolment);
    assert!(invites.is_empty(), "the invite is spent");
}

#[test]
fn an_invite_can_be_redeemed_only_once() {
    let first = identity(91);
    let second = identity(92);
    let invites = store_with(b"invite-2");

    block_on(verify_enrolment(
        &make_proof(&first, AUDIENCE, b"invite-2", [91u8; 32]),
        params(),
        &invites,
    ))
    .expect("first holder wins");

    assert_eq!(
        block_on(verify_enrolment(
            &make_proof(&second, AUDIENCE, b"invite-2", [92u8; 32]),
            params(),
            &invites,
        ))
        .unwrap_err(),
        AuthError::InviteNotRedeemable,
        "two keys must not be able to claim one invitation"
    );
}

#[test]
fn a_proof_cannot_be_redirected_to_a_different_invite() {
    let id = identity(93);
    let invites = InMemoryInviteStore::new();
    invites.issue(b"invite-intended".to_vec(), NOW + 3600);
    invites.issue(b"invite-other".to_vec(), NOW + 3600);

    let mut proof = make_proof(&id, AUDIENCE, b"invite-intended", [93u8; 32]);
    proof.invite_id = b"invite-other".to_vec();

    assert_eq!(
        block_on(verify_enrolment(&proof, params(), &invites)).unwrap_err(),
        AuthError::BadSignature,
        "the invite is bound by the signature, so an intercepted enrolment \
         cannot be pointed at a different invitation"
    );
    assert_eq!(invites.len(), 2, "and neither invite is spent");
}

#[test]
fn a_failed_attempt_does_not_burn_the_invite() {
    let id = identity(94);
    let invites = store_with(b"invite-3");
    let mut proof = make_proof(&id, AUDIENCE, b"invite-3", [94u8; 32]);
    proof.signature[0] ^= 0xff;

    assert_eq!(
        block_on(verify_enrolment(&proof, params(), &invites)).unwrap_err(),
        AuthError::BadSignature
    );
    assert_eq!(
        invites.len(),
        1,
        "an invite is a scarce thing someone issued; a garbled request must \
         not turn into a support ticket"
    );

    // And the holder can still enrol once the request is well formed.
    let good = make_proof(&id, AUDIENCE, b"invite-3", [95u8; 32]);
    block_on(verify_enrolment(&good, params(), &invites)).expect("retry succeeds");
}

#[test]
fn unknown_spent_and_lapsed_invites_are_indistinguishable() {
    let id = identity(96);

    // Unknown.
    let empty: InMemoryInviteStore = InMemoryInviteStore::new();
    let unknown = block_on(verify_enrolment(
        &make_proof(&id, AUDIENCE, b"never-issued", [96u8; 32]),
        params(),
        &empty,
    ))
    .unwrap_err();

    // Lapsed.
    let lapsed_store = InMemoryInviteStore::new();
    lapsed_store.issue(b"invite-old".to_vec(), NOW - 1);
    let lapsed = block_on(verify_enrolment(
        &make_proof(&id, AUDIENCE, b"invite-old", [97u8; 32]),
        params(),
        &lapsed_store,
    ))
    .unwrap_err();

    // Spent.
    let spent_store = store_with(b"invite-4");
    block_on(verify_enrolment(
        &make_proof(&id, AUDIENCE, b"invite-4", [98u8; 32]),
        params(),
        &spent_store,
    ))
    .expect("spend it");
    let spent = block_on(verify_enrolment(
        &make_proof(&id, AUDIENCE, b"invite-4", [99u8; 32]),
        params(),
        &spent_store,
    ))
    .unwrap_err();

    assert_eq!(unknown, lapsed);
    assert_eq!(lapsed, spent);
    assert_eq!(
        unknown,
        AuthError::InviteNotRedeemable,
        "distinguishing them would let someone probe which invitations exist"
    );
}

#[test]
fn an_enrolment_for_another_audience_is_refused() {
    let id = identity(100);
    let invites = store_with(b"invite-5");
    let proof = make_proof(&id, OTHER_AUDIENCE, b"invite-5", [100u8; 32]);

    assert_eq!(
        block_on(verify_enrolment(&proof, params(), &invites)).unwrap_err(),
        AuthError::AudienceMismatch
    );
    assert_eq!(invites.len(), 1, "and the invite survives");
}

#[test]
fn an_enrolment_signature_is_not_a_login_signature() {
    let id = identity(101);
    let invites = store_with(b"invite-6");
    let mut proof = make_proof(&id, AUDIENCE, b"invite-6", [101u8; 32]);

    // Same key, same bytes, login purpose. Enrolment establishes a key the
    // directory does not know; login proves control of one it does. Letting
    // one stand for the other would collapse that distinction.
    proof.signature = id
        .sign_with_purpose(purposes::AUTH_LOGIN_V1, &proof.signing_input())
        .expect("signing");

    assert_eq!(
        block_on(verify_enrolment(&proof, params(), &invites)).unwrap_err(),
        AuthError::BadSignature
    );
}

#[test]
fn a_stale_enrolment_is_refused() {
    let id = identity(102);
    let invites = store_with(b"invite-7");
    let mut proof = make_proof(&id, AUDIENCE, b"invite-7", [102u8; 32]);
    proof.issued_at = NOW - 10_000;
    proof.signature = id
        .sign_with_purpose(purposes::AUTH_ENROL_V1, &proof.signing_input())
        .expect("re-signing");

    assert_eq!(
        block_on(verify_enrolment(&proof, params(), &invites)).unwrap_err(),
        AuthError::StaleOrFutureProof,
        "enrolment shares the envelope checks with every other proof"
    );
}

// ── Grants and the directory ─────────────────────────────────────────────────

use aethel_auth::{enrol, Directory, InMemoryDirectory};

#[test]
fn redeeming_an_invite_returns_what_it_grants() {
    let id = identity(70);
    let invites: InMemoryInviteStore<&'static str> = InMemoryInviteStore::new();
    invites.issue_granting(b"invite-g".to_vec(), NOW + 3600, "tenant-7:admin");
    let proof = make_proof(&id, AUDIENCE, b"invite-g", [70u8; 32]);

    let (_, grant) = block_on(verify_enrolment(&proof, params(), &invites)).unwrap();
    assert_eq!(grant, "tenant-7:admin");
}

fn directory() -> impl Directory<Account = String, Grant = &'static str> {
    // Each enrolment mints a fresh account from the grant.
    let counter = std::sync::atomic::AtomicU32::new(0);
    InMemoryDirectory::new(move |_: &aethel_auth::EnrolledIdentity, grant: &'static str| {
        let n = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        format!("account-{n}@{grant}")
    })
}

#[test]
fn enrolling_creates_an_account_from_the_grant_and_the_key_then_resolves() {
    let id = identity(71);
    let invites: InMemoryInviteStore<&'static str> = InMemoryInviteStore::new();
    invites.issue_granting(b"invite-1".to_vec(), NOW + 3600, "tenant-7");
    let dir = directory();

    let account = block_on(enrol(&make_proof(&id, AUDIENCE, b"invite-1", [71u8; 32]), params(), &invites, &dir)).unwrap();
    assert_eq!(account, "account-0@tenant-7");
    assert_eq!(block_on(dir.resolve(&id.public_key())).unwrap(), Some(account));
    assert!(invites.is_empty());
}

#[test]
fn a_key_already_enrolled_is_refused_without_spending_the_invite() {
    let id = identity(72);
    let invites: InMemoryInviteStore<&'static str> = InMemoryInviteStore::new();
    invites.issue_granting(b"invite-1".to_vec(), NOW + 3600, "tenant-7");
    invites.issue_granting(b"invite-2".to_vec(), NOW + 3600, "tenant-7");
    let dir = directory();
    block_on(enrol(&make_proof(&id, AUDIENCE, b"invite-1", [72u8; 32]), params(), &invites, &dir)).unwrap();

    let again = block_on(enrol(&make_proof(&id, AUDIENCE, b"invite-2", [73u8; 32]), params(), &invites, &dir));
    assert_eq!(again.unwrap_err(), AuthError::KeyAlreadyEnrolled);
    assert_eq!(invites.len(), 1, "the second invite must survive a mistaken re-enrolment");
}

#[test]
fn a_bad_signature_neither_spends_the_invite_nor_creates_an_account() {
    let id = identity(74);
    let invites: InMemoryInviteStore<&'static str> = InMemoryInviteStore::new();
    invites.issue_granting(b"invite-1".to_vec(), NOW + 3600, "tenant-7");
    let dir = directory();
    let mut proof = make_proof(&id, AUDIENCE, b"invite-1", [74u8; 32]);
    proof.signature[0] ^= 1;

    assert!(block_on(enrol(&proof, params(), &invites, &dir)).is_err());
    assert_eq!(invites.len(), 1);
    assert_eq!(block_on(dir.resolve(&id.public_key())).unwrap(), None);
}

#[test]
fn two_keys_on_two_invites_get_two_accounts() {
    let invites: InMemoryInviteStore<&'static str> = InMemoryInviteStore::new();
    invites.issue_granting(b"invite-1".to_vec(), NOW + 3600, "tenant-7");
    invites.issue_granting(b"invite-2".to_vec(), NOW + 3600, "tenant-7");
    let dir = directory();
    let a = block_on(enrol(&make_proof(&identity(75), AUDIENCE, b"invite-1", [75u8; 32]), params(), &invites, &dir)).unwrap();
    let b = block_on(enrol(&make_proof(&identity(76), AUDIENCE, b"invite-2", [76u8; 32]), params(), &invites, &dir)).unwrap();
    assert_ne!(a, b, "an invite for the same tenant still mints a new account");
}
