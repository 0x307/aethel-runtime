//! Tests for `VerifiedDelegation`: verify once, re-check cheaply.

use aethel_auth::{
    authorise, purposes, verify_delegation, AuthError, Bounds, Delegation, RemainingObligations,
    VerifiedDelegation,
};
use aethel_core::signing::Identity;

const AUDIENCE: &[u8] = b"https://console.example.com";
const OTHER_AUDIENCE: &[u8] = b"https://gateway.example.com";
const NOW: u64 = 1_700_000_000;
const NO_KEYS: &[Vec<u8>] = &[];
const NO_IDS: &[[u8; 32]] = &[];

fn identity(seed: u8) -> Identity {
    Identity::generate(&[seed; 32]).expect("32 bytes of entropy")
}

fn spend_bounds() -> Bounds {
    Bounds {
        actions: vec![b"transfer".to_vec(), b"refund".to_vec()],
        max_per_invocation: Some(500),
        max_total: Some(2_000),
        window_secs: Some(86_400),
        approval_required_above: Some(250),
        approvers: Vec::new(),
    }
}

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

struct Fixture {
    principal: Identity,
    delegate: Identity,
    d: Delegation,
    handle: VerifiedDelegation,
}

fn fixture() -> Fixture {
    let principal = identity(130);
    let delegate = identity(131);
    let d = make_delegation(&principal, &delegate, AUDIENCE, spend_bounds());
    let handle = VerifiedDelegation::verify(
        &d,
        AUDIENCE,
        std::slice::from_ref(&d.principal_key),
        NO_KEYS,
        NO_IDS,
        NOW,
    )
    .expect("verifies");
    Fixture {
        principal,
        delegate,
        d,
        handle,
    }
}

#[test]
fn a_handle_reports_the_delegation_it_was_built_from() {
    let f = fixture();
    assert_eq!(f.handle.id(), f.d.id());
    assert_eq!(f.handle.principal_key(), f.d.principal_key.as_slice());
    assert_eq!(f.handle.delegate_key(), f.d.delegate_key.as_slice());
}

#[test]
fn recheck_passes_while_nothing_has_changed() {
    let f = fixture();
    f.handle
        .recheck(AUDIENCE, NO_KEYS, NO_IDS, NOW)
        .expect("positive control");
    f.handle
        .recheck(AUDIENCE, NO_KEYS, NO_IDS, NOW + 3599)
        .expect("last second of the window");
}

#[test]
fn recheck_refuses_after_expiry_and_before_the_window() {
    let f = fixture();
    f.handle
        .recheck(AUDIENCE, NO_KEYS, NO_IDS, NOW)
        .expect("control");
    assert_eq!(
        f.handle
            .recheck(AUDIENCE, NO_KEYS, NO_IDS, f.d.expires_at)
            .unwrap_err(),
        AuthError::Expired
    );
    assert_eq!(
        f.handle
            .recheck(AUDIENCE, NO_KEYS, NO_IDS, f.d.not_before - 1)
            .unwrap_err(),
        AuthError::Expired
    );
}

#[test]
fn recheck_refuses_once_the_principal_key_is_revoked() {
    let f = fixture();
    f.handle
        .recheck(AUDIENCE, NO_KEYS, NO_IDS, NOW)
        .expect("control");
    let revoked = [f.principal.public_key()];
    assert_eq!(
        f.handle
            .recheck(AUDIENCE, &revoked[..], NO_IDS, NOW)
            .unwrap_err(),
        AuthError::Revoked
    );
}

#[test]
fn recheck_refuses_once_the_delegate_key_is_revoked() {
    let f = fixture();
    f.handle
        .recheck(AUDIENCE, NO_KEYS, NO_IDS, NOW)
        .expect("control");
    let revoked = [f.delegate.public_key()];
    assert_eq!(
        f.handle
            .recheck(AUDIENCE, &revoked[..], NO_IDS, NOW)
            .unwrap_err(),
        AuthError::Revoked
    );
}

#[test]
fn recheck_refuses_once_the_delegation_id_is_revoked() {
    let f = fixture();
    f.handle
        .recheck(AUDIENCE, NO_KEYS, NO_IDS, NOW)
        .expect("control");
    let ids = [f.d.id()];
    assert_eq!(
        f.handle
            .recheck(AUDIENCE, NO_KEYS, &ids[..], NOW)
            .unwrap_err(),
        AuthError::Revoked
    );
    // A different id does not revoke it.
    let other = [[9u8; 32]];
    f.handle
        .recheck(AUDIENCE, NO_KEYS, &other[..], NOW)
        .expect("another id is not this delegation");
}

#[test]
fn recheck_refuses_at_another_audience() {
    let f = fixture();
    f.handle
        .recheck(AUDIENCE, NO_KEYS, NO_IDS, NOW)
        .expect("control");
    assert_eq!(
        f.handle
            .recheck(OTHER_AUDIENCE, NO_KEYS, NO_IDS, NOW)
            .unwrap_err(),
        AuthError::AudienceMismatch
    );
}

#[test]
fn recheck_works_with_closures_as_the_revoked_sets() {
    let f = fixture();
    let id = f.d.id();
    let by_id = move |i: &[u8; 32]| *i == id;
    assert_eq!(
        f.handle
            .recheck(AUDIENCE, &|_: &[u8]| false, &by_id, NOW)
            .unwrap_err(),
        AuthError::Revoked
    );
}

#[test]
fn verify_refuses_what_the_free_function_refuses() {
    let principal = identity(132);
    let delegate = identity(133);
    let d = make_delegation(&principal, &delegate, AUDIENCE, spend_bounds());
    let principals = [principal.public_key()];

    VerifiedDelegation::verify(&d, AUDIENCE, &principals, NO_KEYS, NO_IDS, NOW).expect("control");

    assert_eq!(
        VerifiedDelegation::verify(&d, AUDIENCE, &[], NO_KEYS, NO_IDS, NOW).unwrap_err(),
        AuthError::NotAuthorised
    );
    assert_eq!(
        VerifiedDelegation::verify(&d, OTHER_AUDIENCE, &principals, NO_KEYS, NO_IDS, NOW)
            .unwrap_err(),
        AuthError::AudienceMismatch
    );
    assert_eq!(
        VerifiedDelegation::verify(&d, AUDIENCE, &principals, NO_KEYS, NO_IDS, d.expires_at)
            .unwrap_err(),
        AuthError::Expired
    );
    let mut forged = d.clone();
    forged.bounds.max_per_invocation = Some(u128::MAX);
    assert_eq!(
        VerifiedDelegation::verify(&forged, AUDIENCE, &principals, NO_KEYS, NO_IDS, NOW)
            .unwrap_err(),
        AuthError::BadSignature
    );
}

/// The body of the free `authorise` as it was before the split, rebuilt here
/// from public pieces (`verify_delegation`, `Delegation::id`) so the table
/// below compares against an independent copy of the check order and not only
/// against code that now shares an implementation.
#[allow(clippy::too_many_arguments)]
fn reference_authorise(
    delegation: &Delegation,
    expected_audience: &[u8],
    principals: &[Vec<u8>],
    revoked: &[Vec<u8>],
    revoked_delegations: &[[u8; 32]],
    delegate_key: &[u8],
    action: &[u8],
    amount: Option<u128>,
    now: u64,
) -> Result<RemainingObligations, AuthError> {
    if !principals.contains(&delegation.principal_key) {
        return Err(AuthError::NotAuthorised);
    }
    if revoked.contains(&delegation.principal_key)
        || revoked.contains(&delegation.delegate_key)
        || revoked_delegations.contains(&delegation.id())
    {
        return Err(AuthError::Revoked);
    }
    verify_delegation(delegation, expected_audience, now)?;
    if delegation.delegate_key != delegate_key {
        return Err(AuthError::NotDelegated);
    }
    if !delegation.bounds.actions.iter().any(|a| a == action) {
        return Err(AuthError::NotDelegated);
    }
    let bounds = &delegation.bounds;
    let sets_an_amount_bound = bounds.max_per_invocation.is_some()
        || bounds.max_total.is_some()
        || bounds.approval_required_above.is_some();
    if amount.is_none() && sets_an_amount_bound {
        return Err(AuthError::NotDelegated);
    }
    if let Some(amount) = amount {
        match bounds.max_per_invocation {
            Some(ceiling) if amount <= ceiling => {}
            _ => return Err(AuthError::NotDelegated),
        }
    }
    let human_approval_required = match (amount, bounds.approval_required_above) {
        (Some(amount), Some(threshold)) => amount > threshold,
        _ => false,
    };
    Ok(RemainingObligations {
        cumulative_ceiling: bounds.max_total,
        window_secs: bounds.window_secs,
        human_approval_required,
    })
}

/// AC3: the handle's `authorise` and the free `authorise` agree on every input
/// in this table, which reuses the inputs of the existing delegation tests
/// (in-bounds, wrong delegate, wrong action, amounts, window, audience,
/// principals, revocation, tampering).
///
/// The free function is `verify` then the handle's `authorise`, so this pins
/// that the split changed neither a result nor which error comes first.
#[test]
fn the_handle_authorise_equals_the_free_authorise() {
    let principal = identity(134);
    let delegate = identity(135);
    let stranger = identity(136);
    let d = make_delegation(&principal, &delegate, AUDIENCE, spend_bounds());
    let unbounded = make_delegation(
        &principal,
        &delegate,
        AUDIENCE,
        Bounds {
            actions: vec![b"read".to_vec()],
            ..Bounds::default()
        },
    );
    let empty_actions = make_delegation(&principal, &delegate, AUDIENCE, Bounds::default());
    let zero_threshold = make_delegation(
        &principal,
        &delegate,
        AUDIENCE,
        Bounds {
            actions: vec![b"transfer".to_vec()],
            max_per_invocation: Some(500),
            approval_required_above: Some(0),
            ..Bounds::default()
        },
    );
    let no_ceiling = make_delegation(
        &principal,
        &delegate,
        AUDIENCE,
        Bounds {
            actions: vec![b"transfer".to_vec()],
            max_total: Some(10),
            ..Bounds::default()
        },
    );
    let mut tampered = d.clone();
    tampered.bounds.max_per_invocation = Some(u128::MAX);
    let mut bad_sig = d.clone();
    bad_sig.signature[0] ^= 1;
    let mut empty_key = d.clone();
    empty_key.delegate_key.clear();

    let delegations: Vec<(&str, &Delegation)> = vec![
        ("spend", &d),
        ("unbounded", &unbounded),
        ("empty_actions", &empty_actions),
        ("zero_threshold", &zero_threshold),
        ("no_ceiling", &no_ceiling),
        ("tampered", &tampered),
        ("bad_sig", &bad_sig),
        ("empty_key", &empty_key),
    ];

    let own = [principal.public_key()];
    let other = [stranger.public_key()];
    let principal_sets: [(&str, &[Vec<u8>]); 3] = [("own", &own), ("other", &other), ("none", &[])];

    let pk = principal.public_key();
    let dk = delegate.public_key();
    let sk = stranger.public_key();
    let key_sets: [(&str, Vec<Vec<u8>>); 3] = [
        ("none", vec![]),
        ("principal", vec![pk.clone()]),
        ("delegate", vec![dk.clone()]),
    ];

    let delegate_keys: [(&str, &[u8]); 2] = [("delegate", &dk), ("stranger", &sk)];
    let actions: [&[u8]; 3] = [b"transfer", b"read", b"nope"];
    let amounts: [Option<u128>; 5] = [None, Some(0), Some(100), Some(300), Some(501)];
    let audiences: [&[u8]; 2] = [AUDIENCE, OTHER_AUDIENCE];
    let nows: [u64; 3] = [NOW, NOW - 11, NOW + 3600];

    let mut compared = 0usize;
    let mut oks = 0usize;
    let mut errs = std::collections::BTreeSet::new();
    for (dname, del) in &delegations {
        let id_sets: [(&str, Vec<[u8; 32]>); 2] = [("none", vec![]), ("this", vec![del.id()])];
        for (pname, principals) in &principal_sets {
            for (kname, keys) in &key_sets {
                for (iname, ids) in &id_sets {
                    for (dkname, dkey) in &delegate_keys {
                        for action in actions {
                            for amount in amounts {
                                for aud in audiences {
                                    for now in nows {
                                        let free = authorise(
                                            del,
                                            aud,
                                            principals,
                                            &keys[..],
                                            &ids[..],
                                            dkey,
                                            action,
                                            amount,
                                            now,
                                        );
                                        let via_handle = VerifiedDelegation::verify(
                                            del,
                                            aud,
                                            principals,
                                            &keys[..],
                                            &ids[..],
                                            now,
                                        )
                                        .and_then(|h| {
                                            h.authorise(
                                                aud,
                                                &keys[..],
                                                &ids[..],
                                                dkey,
                                                action,
                                                amount,
                                                now,
                                            )
                                        });
                                        let reference = reference_authorise(
                                            del,
                                            aud,
                                            principals,
                                            &keys[..],
                                            &ids[..],
                                            dkey,
                                            action,
                                            amount,
                                            now,
                                        );
                                        assert_eq!(
                                            free, via_handle,
                                            "{dname}/{pname}/{kname}/{iname}/{dkname}/{action:?}/{amount:?}/{aud:?}/{now}"
                                        );
                                        assert_eq!(
                                            free, reference,
                                            "free vs 0.3 logic: {dname}/{pname}/{kname}/{iname}/{dkname}/{action:?}/{amount:?}/{aud:?}/{now}"
                                        );
                                        compared += 1;
                                        match free {
                                            Ok(_) => oks += 1,
                                            Err(e) => {
                                                errs.insert(format!("{e:?}"));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(compared > 1_000, "compared {compared}");
    assert!(oks > 0, "no input succeeded");
    for e in [
        "Malformed",
        "AudienceMismatch",
        "Expired",
        "BadSignature",
        "NotAuthorised",
        "NotDelegated",
        "Revoked",
    ] {
        assert!(errs.contains(e), "no table input produced {e}: {errs:?}");
    }
}

#[test]
fn the_handle_authorise_reports_the_same_obligations() {
    let f = fixture();
    let got: RemainingObligations = f
        .handle
        .authorise(
            AUDIENCE,
            NO_KEYS,
            NO_IDS,
            &f.delegate.public_key(),
            b"transfer",
            Some(300),
            NOW,
        )
        .expect("within bounds");
    assert_eq!(got.cumulative_ceiling, Some(2_000));
    assert_eq!(got.window_secs, Some(86_400));
    assert!(got.human_approval_required, "300 is over 250");
}

#[test]
fn the_handle_authorise_rechecks_revocation_at_each_call() {
    let f = fixture();
    let dk = f.delegate.public_key();
    let _ = f
        .handle
        .authorise(AUDIENCE, NO_KEYS, NO_IDS, &dk, b"transfer", Some(1), NOW)
        .expect("control");
    let ids = [f.d.id()];
    assert_eq!(
        f.handle
            .authorise(AUDIENCE, NO_KEYS, &ids[..], &dk, b"transfer", Some(1), NOW)
            .unwrap_err(),
        AuthError::Revoked
    );
}

#[test]
fn a_handle_is_clone_and_debug() {
    fn clone_debug<T: Clone + core::fmt::Debug>() {}
    clone_debug::<VerifiedDelegation>();
}
