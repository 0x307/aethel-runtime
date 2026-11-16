//! The revoked sets a relying party actually keeps.
//!
//! The README and the CHANGELOG's migration notes pass `&revoked_keys` and
//! `&revoked_ids` held as plain collections. These tests call `authorise` and
//! `VerifiedDelegation` exactly that way with each supported container, so a
//! snippet that stops compiling, or a container that stops answering, fails
//! here. Each refusal has its control: the same call with the set empty passes.

use std::collections::{BTreeSet, HashSet};

use aethel_auth::{
    authorise, AuthError, Bounds, Delegation, Holder, RevokedDelegations, RevokedKeys,
    VerifiedDelegation,
};
use aethel_core::signing::Identity;

const AUDIENCE: &[u8] = b"https://pay.example.com";
const NOW: u64 = 1_800_000_000;

fn identity(seed: u8) -> Identity {
    Identity::generate(&[seed; 32]).expect("32 bytes of entropy")
}

fn grant(principal: &Identity, delegate: &Identity) -> Delegation {
    Holder::new(principal, AUDIENCE).delegate_to(
        delegate.public_key(),
        Bounds {
            actions: vec![b"transfer".to_vec()],
            max_per_invocation: Some(10_000),
            ..Bounds::default()
        },
        NOW - 10,
        NOW + 3600,
    )
}

fn check<R: RevokedKeys + ?Sized, D: RevokedDelegations + ?Sized>(
    delegation: &Delegation,
    principals: &[Vec<u8>],
    delegate_key: &[u8],
    revoked_keys: &R,
    revoked_ids: &D,
) -> Result<(), AuthError> {
    let _ = authorise(
        delegation,
        AUDIENCE,
        principals,
        revoked_keys,
        revoked_ids,
        delegate_key,
        b"transfer",
        Some(5),
        NOW,
    )?;
    let verified = VerifiedDelegation::verify(
        delegation,
        AUDIENCE,
        principals,
        revoked_keys,
        revoked_ids,
        NOW,
    )?;
    verified.recheck(AUDIENCE, revoked_keys, revoked_ids, NOW)?;
    let _ = verified.authorise(
        AUDIENCE,
        revoked_keys,
        revoked_ids,
        delegate_key,
        b"transfer",
        Some(5),
        NOW,
    )?;
    Ok(())
}

#[test]
fn a_vec_of_revoked_keys_works_as_written_in_the_readme() {
    let (principal, delegate) = (identity(1), identity(2));
    let delegation = grant(&principal, &delegate);
    let principals = vec![principal.public_key()];
    let revoked_ids: Vec<[u8; 32]> = Vec::new();

    let none: Vec<Vec<u8>> = Vec::new();
    assert_eq!(
        check(
            &delegation,
            &principals,
            &delegate.public_key(),
            &none,
            &revoked_ids
        ),
        Ok(())
    );

    let revoked_keys: Vec<Vec<u8>> = vec![delegate.public_key()];
    assert_eq!(
        check(
            &delegation,
            &principals,
            &delegate.public_key(),
            &revoked_keys,
            &revoked_ids
        ),
        Err(AuthError::Revoked),
    );
}

#[test]
fn a_vec_of_revoked_ids_works_as_written_in_the_readme() {
    let (principal, delegate) = (identity(3), identity(4));
    let delegation = grant(&principal, &delegate);
    let principals = vec![principal.public_key()];
    let revoked_keys: Vec<Vec<u8>> = Vec::new();

    let mut revoked_ids: Vec<[u8; 32]> = Vec::new();
    assert_eq!(
        check(
            &delegation,
            &principals,
            &delegate.public_key(),
            &revoked_keys,
            &revoked_ids
        ),
        Ok(())
    );

    revoked_ids.push(delegation.id());
    assert_eq!(
        check(
            &delegation,
            &principals,
            &delegate.public_key(),
            &revoked_keys,
            &revoked_ids
        ),
        Err(AuthError::Revoked),
    );
}

#[test]
fn hash_and_btree_sets_of_revoked_ids_refuse_the_delegation() {
    let (principal, delegate) = (identity(5), identity(6));
    let delegation = grant(&principal, &delegate);
    let principals = vec![principal.public_key()];
    let keys: Vec<Vec<u8>> = Vec::new();

    let empty_hash: HashSet<[u8; 32]> = HashSet::new();
    let empty_btree: BTreeSet<[u8; 32]> = BTreeSet::new();
    assert_eq!(
        check(
            &delegation,
            &principals,
            &delegate.public_key(),
            &keys,
            &empty_hash
        ),
        Ok(())
    );
    assert_eq!(
        check(
            &delegation,
            &principals,
            &delegate.public_key(),
            &keys,
            &empty_btree
        ),
        Ok(())
    );

    let hash: HashSet<[u8; 32]> = [delegation.id()].into_iter().collect();
    let btree: BTreeSet<[u8; 32]> = [delegation.id()].into_iter().collect();
    assert_eq!(
        check(
            &delegation,
            &principals,
            &delegate.public_key(),
            &keys,
            &hash
        ),
        Err(AuthError::Revoked),
    );
    assert_eq!(
        check(
            &delegation,
            &principals,
            &delegate.public_key(),
            &keys,
            &btree
        ),
        Err(AuthError::Revoked),
    );
}
