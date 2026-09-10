//! Error type for the `signer`-mode surface (V-1/V-4/V-5).
//!
//! Distinct from the `extern "C"` `ERR_*` `u32` codes in
//! [`crate::vault`], which stay as they are for the confidential-ledger
//! state machine's ABI. [`VaultError`] is the Rust-native error type for
//! [`crate::settlement::Wallet`], [`crate::policy::SpendPolicy`], and
//! [`crate::receipt`].

extern crate alloc;

use crate::policy::PolicyViolation;
use crate::settlement::SettlementError;

/// Errors produced by the `signer`-mode surface: settlement authorization,
/// spend policy enforcement, and receipt signing/verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    /// The spend policy denied the request outright (no HITL escalation
    /// possible for this violation — see [`PolicyViolation`]).
    PolicyDenied(PolicyViolation),
    /// The amount is above the policy's `hitl_above` threshold and no
    /// valid [`crate::policy::HitlApproval`] was supplied (or the one
    /// supplied did not verify against the configured approver key,
    /// the expected intent, or was expired).
    HitlRequired,
    /// The injected [`crate::settlement::SettlementSigner`] failed to
    /// produce a signature over the EIP-712 digest.
    SignerFailure(SettlementError),
    /// An address argument was structurally invalid (reserved for future
    /// validation; addresses are fixed-size `[u8; 20]` today so this is not
    /// yet reachable, but kept so a future checksum/format validation has
    /// somewhere to report to without another breaking enum change).
    InvalidAddress,
    /// The requested rail is not in the policy's `allow_rails` list.
    ///
    /// Distinct from [`Self::PolicyDenied`]`(`[`PolicyViolation::RailNotAllowed`]`)`
    /// only in which layer detected it; both are surfaced identically to a
    /// caller and this variant exists for call sites that check the rail
    /// before constructing a [`crate::policy::SpendRequest`] at all.
    RailNotAllowed,
    /// The aethel-core identity signing/verification layer reported a
    /// failure (malformed key, oversized purpose, etc.) — see
    /// [`aethel_core::IdentityError`].
    IdentityError(aethel_core::IdentityError),
    /// Bincode (de)serialization of an intent/receipt/approval message
    /// failed.
    SerializationError,
}

impl From<aethel_core::IdentityError> for VaultError {
    fn from(e: aethel_core::IdentityError) -> Self {
        VaultError::IdentityError(e)
    }
}

impl From<PolicyViolation> for VaultError {
    fn from(e: PolicyViolation) -> Self {
        VaultError::PolicyDenied(e)
    }
}

impl From<SettlementError> for VaultError {
    fn from(e: SettlementError) -> Self {
        VaultError::SignerFailure(e)
    }
}

impl core::fmt::Display for VaultError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VaultError::PolicyDenied(v) => write!(f, "spend policy denied: {v:?}"),
            VaultError::HitlRequired => write!(f, "amount requires human-in-the-loop approval"),
            VaultError::SignerFailure(e) => write!(f, "settlement signer failed: {e:?}"),
            VaultError::InvalidAddress => write!(f, "invalid address"),
            VaultError::RailNotAllowed => write!(f, "rail not allowed by policy"),
            VaultError::IdentityError(e) => write!(f, "identity error: {e:?}"),
            VaultError::SerializationError => write!(f, "serialization error"),
        }
    }
}
