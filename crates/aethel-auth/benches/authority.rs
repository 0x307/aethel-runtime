//! Every authority-layer operation, benched individually.
//!
//! Fourth and last in the family, after `pqc-sig`, `pqc-kem` and
//! `aethel-core`, and written to the same rules. The generated table is
//! `BENCHMARKS.md` at the repository root.
//!
//! # Why this one matters most
//!
//! The layer below is measured per *interaction*. This one is measured per
//! *request*. `verify_request` runs on every HTTP call of every live session,
//! so it is the only operation here whose cost multiplies by traffic rather
//! than by users.
//!
//! It was also shipped, declared complete, and left unmeasured, which is the
//! specific gap this file closes.
//!
//! # The hot path and the cold path, kept apart
//!
//! | Path | Frequency | Cost driver |
//! |---|---|---|
//! | `session/verify_request` | every request | HMAC-SHA-256 and a store lookup |
//! | `login/verify_login` | once per session | ML-DSA-65 verification |
//! | `statements/*` | rarely | ML-DSA-65 verification |
//!
//! The whole design rests on the first row being cheap relative to the
//! second — that is what a session *buys*. Until now nobody had checked the
//! ratio held.
//!
//! # Requires the `holder` feature
//!
//! Verifying a proof means having one, and building one is the holder's job.
//! Declared as `required-features` rather than skipped at runtime, so an
//! attempt to bench without it fails to select the target instead of
//! measuring a subset and reporting success.

use criterion::{criterion_group, criterion_main, Criterion};

use aethel_auth::{
    authorise, key_fingerprint, sha256_32, verify_delegation, verify_enrolment, verify_login,
    verify_request, verify_revocation, verify_session, verify_step_up, verify_succession,
    AuthStrength, Bounds, Holder, InMemoryInviteStore, InMemoryNonceStore, InMemorySessionStore,
    RequestBinding, Session, SessionSecret, SessionStore, SessionToken, VerifyParams,
};
use aethel_core::signing::Identity;

const AUDIENCE: &[u8] = b"https://console.example.com";
const NOW: u64 = 1_758_000_000;
const MAX_AGE: u64 = 300;

/// Minimal executor. The crate pulls in no async runtime, and none of these
/// futures actually yield, so polling once is enough.
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
        Poll::Pending => panic!("future parked; these stores do not yield"),
    }
}

fn params() -> VerifyParams<'static> {
    VerifyParams {
        expected_audience: AUDIENCE,
        now: NOW,
        max_age_secs: MAX_AGE,
    }
}

/// The login handshake: one ML-DSA-65 verification plus an atomic nonce claim.
///
/// A fresh nonce store per iteration, because a claimed nonce is refused on
/// the second call — benching the same nonce twice would measure the rejection
/// path, which is cheaper and is not what a login costs.
fn login(c: &mut Criterion) {
    let mut group = c.benchmark_group("login");

    let identity = Identity::generate(&[5u8; 32]).expect("identity");
    let holder = Holder::new(&identity, AUDIENCE);

    group.bench_function("build_login_proof", |b| {
        b.iter(|| holder.login([1u8; 32], NOW, 300, None))
    });

    // A fresh store and an unused proof for every iteration.
    //
    // Cycling a fixed pool against one long-lived store does not work:
    // criterion runs far more iterations than any pool has entries, so once
    // the pool wraps, every nonce is already claimed and the benchmark
    // measures the replay refusal instead of a verification. The first
    // version of this file did that, and because this particular call had no
    // `.expect()`, it reported the refusal path as a login cost rather than
    // failing.
    //
    // `iter_batched` excludes setup from the measurement, so building the
    // store and the proof costs nothing here.
    group.bench_function("verify_login", |b| {
        let mut n = 0u32;
        b.iter_batched(
            || {
                n += 1;
                let mut nonce = [0u8; 32];
                nonce[..4].copy_from_slice(&n.to_le_bytes());
                (
                    InMemoryNonceStore::new(),
                    holder.login(nonce, NOW, 300, None),
                )
            },
            |(nonces, proof)| {
                block_on(verify_login(&proof, params(), &nonces)).expect("verify")
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.finish();
}

/// The per-request path. This is the number the session model exists to make
/// small.
fn session(c: &mut Criterion) {
    let mut group = c.benchmark_group("session");

    let sessions = InMemorySessionStore::new();
    let token = SessionToken::from_bytes([7u8; 32]);
    let secret = SessionSecret::from_bytes([9u8; 32]);
    block_on(sessions.create(Session::new(
        &token,
        secret.clone(),
        1u32,
        AUDIENCE.to_vec(),
        AuthStrength::Proven,
        0,
        NOW,
        NOW + 3600,
    )))
    .expect("create");

    let body_hash = sha256_32(b"");
    let binding = RequestBinding {
        audience: AUDIENCE,
        method: "GET",
        path: "/profile",
        query: "",
        body_sha256: body_hash,
        timestamp: NOW,
        nonce: [11u8; 32],
    };

    group.bench_function("encode_binding", |b| b.iter(|| binding.encode()));

    let encoded = binding.encode();
    group.bench_function("mac", |b| b.iter(|| secret.mac(&encoded)));

    let mac = secret.mac(&encoded);
    group.bench_function("verify_mac", |b| {
        b.iter(|| assert!(secret.verify_mac(&encoded, &mac)))
    });

    // `verify_session` without the replay check: a store lookup plus a MAC.
    group.bench_function("verify_session", |b| {
        b.iter(|| {
            block_on(verify_session(
                &sessions, &token, &encoded, &mac, NOW, 0,
            ))
            .expect("verify")
        })
    });

    // The whole per-request path, replay protection included. This is the
    // number the session model exists to make small.
    //
    // Fresh store and unused nonce per iteration, for the reason given on
    // `verify_login` above: a claimed nonce takes the refusal path, which is
    // cheaper and is not what a request costs.
    group.bench_function("verify_request (full per-request path)", |b| {
        let mut n = 0u32;
        b.iter_batched(
            || {
                n += 1;
                let mut nonce = [0u8; 32];
                nonce[..4].copy_from_slice(&n.to_le_bytes());
                let bound = RequestBinding { nonce, ..binding };
                let mac = secret.mac(&bound.encode());
                (InMemoryNonceStore::new(), bound, mac)
            },
            |(nonces, bound, mac)| {
                block_on(verify_request(
                    &sessions, &nonces, &token, &bound, &mac, NOW, MAX_AGE, 0,
                ))
                .expect("verify")
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.finish();
}

/// Step-up, delegation and authorisation.
fn delegation(c: &mut Criterion) {
    let mut group = c.benchmark_group("delegation");

    let principal_id = Identity::generate(&[21u8; 32]).expect("identity");
    let principal = Holder::new(&principal_id, AUDIENCE);
    let delegate_id = Identity::generate(&[22u8; 32]).expect("identity");
    let delegate_key = delegate_id.public_key();

    let action = [3u8; 32];
    group.bench_function("verify_step_up", |b| {
        let mut n = 0u32;
        b.iter_batched(
            || {
                n += 1;
                let mut nonce = [0u8; 32];
                nonce[..4].copy_from_slice(&n.to_le_bytes());
                (
                    InMemoryNonceStore::new(),
                    principal.step_up(nonce, NOW, 300, action),
                )
            },
            |(nonces, proof)| {
                block_on(verify_step_up(&proof, params(), &action, &nonces)).expect("verify")
            },
            criterion::BatchSize::SmallInput,
        )
    });

    // A delegation that actually permits something. `Bounds::default()` has an
    // empty action list, which means no action is permitted, so `authorise`
    // would take the refusal path — cheaper than the real one, and not what an
    // authorisation costs.
    let bounds = Bounds {
        actions: vec![b"transfer".to_vec()],
        max_per_invocation: Some(1_000),
        max_total: Some(10_000),
        window_secs: Some(86_400),
        approval_required_above: Some(500),
    };
    let delegate_key_copy = delegate_key.clone();
    let delegation = principal.delegate_to(delegate_key, bounds, NOW, NOW + 3600);

    group.bench_function("verify_delegation", |b| {
        b.iter(|| verify_delegation(&delegation, AUDIENCE, NOW).expect("verify"))
    });

    group.bench_function("authorise", |b| {
        b.iter(|| {
            authorise(
                &delegation,
                AUDIENCE,
                &delegate_key_copy,
                b"transfer",
                Some(100),
                NOW,
            )
            .expect("authorise")
        })
    });

    group.finish();
}

/// Succession, revocation and enrolment: the rare statements.
///
/// Each is one ML-DSA-65 verification, so these should all land near
/// `login/verify_login`. They are measured anyway — an unmeasured operation is
/// one nobody notices getting slower, and revocation being slow is discovered
/// at the worst possible moment.
fn statements(c: &mut Criterion) {
    let mut group = c.benchmark_group("statements");

    let identity = Identity::generate(&[31u8; 32]).expect("identity");
    let holder = Holder::new(&identity, AUDIENCE);
    let successor = Identity::generate(&[32u8; 32]).expect("identity");

    let succession = holder.name_successor(successor.public_key(), NOW);
    group.bench_function("verify_succession", |b| {
        b.iter(|| verify_succession(&succession, AUDIENCE).expect("verify"))
    });

    let revocation = holder.revoke_self(NOW);
    group.bench_function("verify_revocation", |b| {
        b.iter(|| verify_revocation(&revocation, AUDIENCE, &[]).expect("verify"))
    });

    // An invite is single-use and a nonce is single-claim, so both stores are
    // rebuilt per iteration. Reusing either would measure the refusal path.
    group.bench_function("verify_enrolment", |b| {
        let mut n = 0u32;
        b.iter_batched(
            || {
                n += 1;
                let mut nonce = [0u8; 32];
                nonce[..4].copy_from_slice(&n.to_le_bytes());
                let invite = format!("invite-{n}");
                let invites = InMemoryInviteStore::new();
                invites.issue(invite.clone().into_bytes(), NOW + 3600);
                (invites, holder.enrol(invite, nonce, NOW, 300))
            },
            |(invites, proof)| {
                block_on(verify_enrolment(&proof, params(), &invites)).expect("verify")
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.bench_function("key_fingerprint", |b| {
        b.iter(|| key_fingerprint(&identity.public_key()))
    });

    group.finish();
}

criterion_group!(authority, login, session, delegation, statements);
criterion_main!(authority);
