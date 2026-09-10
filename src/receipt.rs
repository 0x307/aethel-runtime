//! Optional signed settlement receipt (SAGP-PG-001 V-5).
//!
//! A receipt is emitted **only on request** — nothing in
//! [`crate::settlement::Wallet::authorize_eip3009`] signs or transmits one
//! automatically. Disclosure is the agent's own choice (UX-001): call
//! [`crate::settlement::Wallet::last_receipt`] to see whether one is
//! available, and [`crate::settlement::Wallet::sign_receipt`] (or
//! [`Receipt::sign`] directly) only when the agent decides to hand it to
//! someone. There is no network transport in this crate — the agent
//! forwards the bytes itself, however it sees fit.

extern crate alloc;

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use aethel_core::signing::purpose;
use aethel_core::signing::Identity;

use crate::error::VaultError;

/// A settlement receipt: what was authorized, to whom, when, and on which
/// chain.
///
/// `auth_hash` is the EIP-712 digest of the `TransferWithAuthorization`
/// this receipt attests to (see
/// [`crate::settlement::TransferWithAuthorization::eip712_digest`]) — a
/// commitment to the exact authorization without repeating every field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// The EIP-712 digest of the authorization this receipt attests to.
    pub auth_hash: [u8; 32],
    /// The amount, in the settlement asset's minor unit.
    pub amount: u128,
    /// The recipient address.
    pub dst: [u8; 20],
    /// Unix timestamp the authorization was produced at.
    pub ts: u64,
    /// The chain id the authorization targets.
    pub chain_id: u64,
}

impl Receipt {
    fn to_bytes(&self) -> Result<Vec<u8>, VaultError> {
        bincode::serialize(self).map_err(|_| VaultError::SerializationError)
    }

    /// Sign this receipt with `identity`'s ML-DSA-65 key, under
    /// [`purpose::VAULT_SETTLEMENT_RECEIPT_V1`].
    ///
    /// This purpose is **never** reused for anything else — in particular,
    /// never for [`purpose::VAULT_SPEND_INTENT_V1`] — see
    /// `tests/vault_tests.rs`'s (or this module's) cross-purpose negative
    /// test.
    pub fn sign(&self, identity: &Identity) -> Result<SignedReceipt, VaultError> {
        let bytes = self.to_bytes()?;
        let signature = identity
            .sign_with_purpose(purpose::VAULT_SETTLEMENT_RECEIPT_V1, &bytes)
            .map_err(VaultError::from)?;
        Ok(SignedReceipt {
            receipt: self.clone(),
            signer_pk: identity.public_key(),
            signature,
        })
    }
}

/// A [`Receipt`] plus the ML-DSA-65 signature and public key that attest
/// to it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedReceipt {
    /// The receipt.
    pub receipt: Receipt,
    /// The ML-DSA-65 public key `signature` verifies under.
    pub signer_pk: Vec<u8>,
    /// The signature, under [`purpose::VAULT_SETTLEMENT_RECEIPT_V1`].
    pub signature: Vec<u8>,
}

impl SignedReceipt {
    /// Verify this receipt's signature.
    ///
    /// `Ok(false)` is a verdict (well-formed but does not verify);
    /// `Err` only for a malformed key/signature that cannot be evaluated.
    pub fn verify(&self) -> Result<bool, VaultError> {
        let bytes = self.receipt.to_bytes()?;
        aethel_core::signing::verify_with_purpose(
            &self.signer_pk,
            purpose::VAULT_SETTLEMENT_RECEIPT_V1,
            &bytes,
            &self.signature,
        )
        .map_err(VaultError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_receipt() -> Receipt {
        Receipt {
            auth_hash: [0x11u8; 32],
            amount: 500_000,
            dst: [0x22u8; 20],
            ts: 1_700_000_000,
            chain_id: 8453,
        }
    }

    #[test]
    fn receipt_round_trips_and_verifies() {
        let identity = Identity::generate(&[0x77u8; 32]).expect("generate");
        let receipt = sample_receipt();
        let signed = receipt.sign(&identity).expect("sign");
        assert_eq!(signed.verify(), Ok(true));
    }

    #[test]
    fn tampered_amount_fails_verification() {
        let identity = Identity::generate(&[0x77u8; 32]).expect("generate");
        let receipt = sample_receipt();
        let mut signed = receipt.sign(&identity).expect("sign");
        signed.receipt.amount += 1;
        assert_eq!(signed.verify(), Ok(false));
    }

    #[test]
    fn receipt_signed_by_another_identity_fails() {
        let identity = Identity::generate(&[0x77u8; 32]).expect("generate");
        let other = Identity::generate(&[0x88u8; 32]).expect("generate");
        let receipt = sample_receipt();
        let mut signed = receipt.sign(&identity).expect("sign");
        signed.signer_pk = other.public_key();
        assert_eq!(signed.verify(), Ok(false));
    }

    /// V-5 cross-purpose test: a receipt signature must not verify under
    /// the spend-intent purpose, and vice versa — the two purposes must
    /// never be interchangeable (see `aethel_core::signing::purpose`'s
    /// "a key must never sign under a purpose other than the one it was
    /// invoked for" rule).
    #[test]
    fn receipt_signature_does_not_verify_under_the_spend_intent_purpose() {
        let identity = Identity::generate(&[0x77u8; 32]).expect("generate");
        let receipt = sample_receipt();
        let signed = receipt.sign(&identity).expect("sign");

        let bytes = bincode::serialize(&signed.receipt).unwrap();
        assert_eq!(
            aethel_core::signing::verify_with_purpose(
                &signed.signer_pk,
                purpose::VAULT_SPEND_INTENT_V1,
                &bytes,
                &signed.signature,
            ),
            Ok(false),
            "a settlement-receipt signature verified under the spend-intent purpose"
        );
    }

    /// The reverse direction: a spend-intent-purpose signature over the
    /// same bytes must not verify as a receipt.
    #[test]
    fn a_spend_intent_signature_does_not_verify_as_a_receipt() {
        let identity = Identity::generate(&[0x77u8; 32]).expect("generate");
        let receipt = sample_receipt();
        let bytes = bincode::serialize(&receipt).unwrap();

        let spend_intent_sig = identity
            .sign_with_purpose(purpose::VAULT_SPEND_INTENT_V1, &bytes)
            .expect("sign");

        let signed = SignedReceipt {
            receipt,
            signer_pk: identity.public_key(),
            signature: spend_intent_sig,
        };
        assert_eq!(
            signed.verify(),
            Ok(false),
            "a spend-intent signature verified as a settlement receipt"
        );
    }

    #[test]
    fn no_receipt_is_produced_unless_requested() {
        // See crate::settlement::tests::no_receipt_is_produced_unless_requested
        // for the Wallet-level version of this property; this is the
        // type-level half: a bare Receipt is never implicitly signed.
        let receipt = sample_receipt();
        // Constructing a Receipt does not, by itself, produce a signature —
        // there is no `Receipt::default()`/`From` path that yields a
        // `SignedReceipt` without an explicit `.sign(identity)` call. This
        // test exists as a documentation anchor; it passes trivially by
        // virtue of the API shape (no signature type exists yet here).
        let _ = receipt;
    }
}
