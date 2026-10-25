//! Every authority-layer operation, benched individually.
//!
//! Fourth and last in the family, after `pqc-sig`, `pqc-kem` and
//! `aethel-core`, and written to the same rules.
//!
//! # What runs how often
//!
//! | Path | Frequency | Cost driver |
//! |---|---|---|
//! | `login/verify_login` | every agent request | ML-DSA-65 verification and a nonce claim |
//! | `delegation/authorise` | every agent request | ML-DSA-65 verification of the delegation |
//! | `delegation/verify_step_up` | above the approval threshold | ML-DSA-65 verification |
//! | `statements/*` | rarely | ML-DSA-65 verification |
//!
//! An agent proves itself on every request, so the first two rows are the
//! per-request cost.
//!
//! # Requires the `holder` feature
//!
//! Verifying a proof means having one, and building one is the holder's job.
//! Declared as `required-features` rather than skipped at runtime, so an
//! attempt to bench without it fails to select the target instead of
//! measuring a subset and reporting success.

use criterion::{criterion_group, criterion_main, Criterion};

use aethel_auth::{
    authorise, key_fingerprint, verify_delegation, verify_login, verify_revocation, verify_step_up,
    verify_succession, Bounds, Holder, InMemoryNonceStore, VerifyParams,
};
use aethel_core::signing::Identity;

const AUDIENCE: &[u8] = b"https://console.example.com";
const NOW: u64 = 1_758_000_000;
const MAX_AGE: u64 = 300;

/// Minimal executor. The crate pulls in no async runtime, and none of these
/// futures actually yield, so polling once is enough.
fn block_on<F: core::future::Future>(f: F) -> F::Output {
    use core::task::{Context, Poll, Waker};
    let mut cx = Context::from_waker(Waker::noop());
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
        b.iter(|| holder.login([1u8; 32], NOW, 300))
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
                (InMemoryNonceStore::new(), holder.login(nonce, NOW, 300))
            },
            |(nonces, proof)| block_on(verify_login(&proof, params(), &nonces)).expect("verify"),
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

/// Succession and revocation: the rare statements.
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

    group.bench_function("key_fingerprint", |b| {
        b.iter(|| key_fingerprint(&identity.public_key()))
    });

    group.finish();
}

criterion_group!(authority, login, delegation, statements);
criterion_main!(authority);
