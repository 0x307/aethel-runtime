//! Standing spend policy, enforced before any settlement intent is signed
//! (SAGP-PG-001 V-4).
//!
//! > "This is G-POLICY living in the agent, not on 8gentz.ai." — policy is
//! > checked here, inside the vault, before
//! > [`crate::settlement::Wallet::authorize_eip3009`] ever calls the
//! > injected [`crate::settlement::SettlementSigner`] or signs a
//! > [`crate::settlement::SpendIntent`]. A denied or HITL-blocked request
//! > produces **no signature of any kind** — see that function's docs.
//!
//! Time is always caller-supplied (`now_unix`): this module is
//! `no_std`+alloc and has no system clock, and deterministic tests need a
//! fixed clock anyway.

extern crate alloc;

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use aethel_core::signing::purpose;

/// One settlement rail (or the confidential-ledger's internal rail) a spend
/// policy may allow or deny.
///
/// `FheInternal` gates [`crate::client`]'s confidential-ledger transfers
/// (`fhe-state` feature) on the plaintext amount, client-side, before
/// encryption — see that module's `build_payload`. The `Eip3009*` variants
/// gate [`crate::settlement::Wallet::authorize_eip3009`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Rail {
    /// EIP-3009 `transferWithAuthorization` on Base USDC.
    Eip3009Base,
    /// EIP-3009 `transferWithAuthorization` on Ethereum mainnet USDC.
    Eip3009Ethereum,
    /// EIP-3009 `transferWithAuthorization` on Arbitrum One USDC.
    Eip3009Arbitrum,
    /// The confidential internal ledger (`fhe-state` feature). Not a
    /// settlement rail at all — see [`crate::vault`]'s "Two assets" docs.
    FheInternal,
}

/// A standing spend policy, enforced before any settlement intent is
/// signed.
///
/// Amounts are `u128` in the settlement asset's minor unit (USDC has 6
/// decimal places, so `1_000_000` is 1.00 USDC).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendPolicy {
    /// Maximum amount allowed in a single call, regardless of the daily cap.
    pub max_per_call: u128,
    /// Maximum cumulative amount allowed within a rolling 86,400-second
    /// window (see [`PolicyState::record`]).
    pub daily_cap: u128,
    /// Rails this policy permits. A request for a rail not in this list is
    /// denied with [`PolicyViolation::RailNotAllowed`], even if it is under
    /// every other limit.
    pub allow_rails: Vec<Rail>,
    /// Amounts strictly above this threshold require a valid
    /// [`HitlApproval`] — see [`SpendPolicy::check`].
    pub hitl_above: u128,
    /// Validity window (seconds) requested authorizations should carry:
    /// `valid_before = now_unix + ttl_secs`. Not itself a limit `check`
    /// enforces; consumed by [`crate::settlement::Wallet::authorize_eip3009`]
    /// (SAGP-PG-001 plan §5, ambiguity 5).
    pub ttl_secs: u64,
    /// The ML-DSA-65 public key a [`HitlApproval`] must be signed by, under
    /// [`purpose::VAULT_HITL_APPROVAL_V1`]. `None` means HITL can never be
    /// satisfied — any request above `hitl_above` is unconditionally
    /// blocked.
    pub hitl_approver_pk: Option<Vec<u8>>,
}

/// Mutable, persistable running state a [`SpendPolicy`] is checked against.
///
/// Not itself secret — it may be persisted in the clear alongside (or
/// separately from) the sealed identity. Losing a [`PolicyState`] resets
/// the daily window, which **fails open** on the cap (a fresh
/// `spent_today = 0`), so losing it is a caution, not a crash: persist it
/// if the daily cap matters to you.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PolicyState {
    /// Unix timestamp (seconds) the current daily window started at.
    pub day_start_unix: u64,
    /// Cumulative amount spent within the current daily window.
    pub spent_today: u128,
}

/// A single proposed spend, checked against a [`SpendPolicy`]/[`PolicyState`]
/// pair.
#[derive(Debug, Clone)]
pub struct SpendRequest {
    /// The rail this spend would use.
    pub rail: Rail,
    /// The amount, in the settlement asset's minor unit.
    pub amount: u128,
    /// The destination address (informational; not itself checked by
    /// `SpendPolicy::check` today, but part of what a `HitlApproval`'s
    /// canonical message binds to via the intent hash — see
    /// [`crate::settlement`]).
    pub to: [u8; 20],
}

/// The policy's verdict for a [`SpendRequest`] that passed every hard limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The request may proceed and be signed immediately.
    Allow,
    /// The request is within hard limits but above `hitl_above`: it may
    /// proceed only with a verified [`HitlApproval`].
    RequireHitl,
}

/// A hard policy violation. Distinct variants (not one "denied" catch-all)
/// so a caller — or a test — can tell *which* limit was hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyViolation {
    /// `amount > max_per_call`.
    ExceedsMaxPerCall,
    /// `spent_today + amount > daily_cap` (after rolling the window).
    ExceedsDailyCap,
    /// `rail` is not in `allow_rails`.
    RailNotAllowed,
}

/// Seconds in a day — the daily window's rolling period.
const DAY_SECONDS: u64 = 86_400;

impl SpendPolicy {
    /// Check `req` against this policy and `state`'s current daily window.
    ///
    /// `now_unix` is caller-supplied (no system clock in this module).
    /// Does **not** mutate `state` — call [`PolicyState::record`]
    /// separately, and only after the request has actually been signed
    /// (see [`crate::settlement::Wallet::authorize_eip3009`]'s ordering:
    /// check → sign → record).
    ///
    /// # Order of checks
    ///
    /// Rail is checked first (a disallowed rail is denied regardless of
    /// amount), then `max_per_call`, then the rolling daily cap (computed
    /// against what `spent_today` *would* be after rolling the window
    /// forward to `now_unix`, without mutating `state`). Amounts strictly
    /// above `hitl_above` that pass all three return
    /// [`Decision::RequireHitl`] rather than a violation — HITL is an
    /// escalation, not a denial.
    pub fn check(
        &self,
        state: &PolicyState,
        req: &SpendRequest,
        now_unix: u64,
    ) -> Result<Decision, PolicyViolation> {
        if !self.allow_rails.contains(&req.rail) {
            return Err(PolicyViolation::RailNotAllowed);
        }
        if req.amount > self.max_per_call {
            return Err(PolicyViolation::ExceedsMaxPerCall);
        }

        let spent_today = effective_spent_today(state, now_unix);
        let projected = spent_today.saturating_add(req.amount);
        if projected > self.daily_cap {
            return Err(PolicyViolation::ExceedsDailyCap);
        }

        if req.amount > self.hitl_above {
            Ok(Decision::RequireHitl)
        } else {
            Ok(Decision::Allow)
        }
    }
}

/// What `state.spent_today` effectively is at `now_unix`, accounting for a
/// daily window roll, without mutating `state`.
fn effective_spent_today(state: &PolicyState, now_unix: u64) -> u128 {
    if now_unix.saturating_sub(state.day_start_unix) >= DAY_SECONDS {
        0
    } else {
        state.spent_today
    }
}

impl PolicyState {
    /// Record a spend of `amount` at `now_unix`, rolling the daily window
    /// forward if it has elapsed.
    ///
    /// Call this only *after* the corresponding request was actually
    /// signed — recording a denied or not-yet-approved request would make
    /// the cap tighter than intended without ever having spent anything.
    pub fn record(&mut self, amount: u128, now_unix: u64) {
        if now_unix.saturating_sub(self.day_start_unix) >= DAY_SECONDS {
            self.day_start_unix = now_unix;
            self.spent_today = 0;
        }
        self.spent_today = self.spent_today.saturating_add(amount);
    }
}

// ── Human-in-the-loop approval (V-4) ────────────────────────────────────────

/// Build the canonical, deterministic byte message a [`HitlApproval`]
/// signs: `intent_hash(32) ‖ amount(16, BE) ‖ expiry_unix(8, BE)`.
///
/// Fixed-width and field-order-fixed on purpose — no ambiguity for a
/// verifier to get wrong, and no serialization library dependency for this
/// one small message.
pub fn hitl_approval_message(intent_hash: &[u8; 32], amount: u128, expiry_unix: u64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(32 + 16 + 8);
    msg.extend_from_slice(intent_hash);
    msg.extend_from_slice(&amount.to_be_bytes());
    msg.extend_from_slice(&expiry_unix.to_be_bytes());
    msg
}

/// A human-in-the-loop approval: an ML-DSA-65 signature, by the principal's
/// `aethel_core::signing::Identity`, over a canonical message binding an
/// intent hash, an amount, and an expiry — under
/// [`purpose::VAULT_HITL_APPROVAL_V1`].
///
/// This is what makes "HITL-off-by-default" possible without a principal
/// portal: the approval is a signed artifact the agent can be handed
/// out-of-band (e.g. from a principal's own device), not a live
/// synchronous call to anything.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HitlApproval {
    /// The approver's ML-DSA-65 public key.
    pub approver_pk: Vec<u8>,
    /// The signature over [`hitl_approval_message`]`(intent_hash, amount, expiry_unix)`.
    pub signature: Vec<u8>,
    /// The intent hash this approval is bound to (the EIP-712 digest of the
    /// `TransferWithAuthorization` it approves — see
    /// [`crate::settlement::TransferWithAuthorization::eip712_digest`]).
    pub intent_hash: [u8; 32],
    /// The amount this approval authorizes. Must equal the request's amount
    /// exactly — an approval for a smaller amount does not authorize a
    /// larger one.
    pub amount: u128,
    /// Unix timestamp after which this approval is no longer valid.
    pub expiry_unix: u64,
}

impl HitlApproval {
    /// Verify this approval against an expected intent hash, amount, and
    /// the current time, and against the policy's configured approver key
    /// (if any).
    ///
    /// Returns `Ok(true)` only if: `now_unix < expiry_unix`, `intent_hash`
    /// and `amount` match exactly, `approver_pk` matches
    /// `expected_approver_pk` (when `Some`), and the ML-DSA-65 signature
    /// verifies under [`purpose::VAULT_HITL_APPROVAL_V1`].
    ///
    /// `Ok(false)` is a verdict (a well-formed approval that simply does
    /// not satisfy this request); `Err` is reserved for a malformed key or
    /// signature that cannot be evaluated at all.
    pub fn verify(
        &self,
        expected_intent_hash: &[u8; 32],
        expected_amount: u128,
        expected_approver_pk: Option<&[u8]>,
        now_unix: u64,
    ) -> Result<bool, aethel_core::IdentityError> {
        if now_unix >= self.expiry_unix {
            return Ok(false);
        }
        if &self.intent_hash != expected_intent_hash || self.amount != expected_amount {
            return Ok(false);
        }
        if let Some(expected_pk) = expected_approver_pk {
            if self.approver_pk != expected_pk {
                return Ok(false);
            }
        }
        let msg = hitl_approval_message(&self.intent_hash, self.amount, self.expiry_unix);
        aethel_core::signing::verify_with_purpose(
            &self.approver_pk,
            purpose::VAULT_HITL_APPROVAL_V1,
            &msg,
            &self.signature,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aethel_core::signing::Identity;

    /// Policy for the pure `max_per_call`/`daily_cap`/rail tests: `hitl_above`
    /// is set above `daily_cap` so those tests never cross into HITL
    /// territory, keeping each test isolated to the one limit it names.
    fn policy(hitl_approver_pk: Option<Vec<u8>>) -> SpendPolicy {
        SpendPolicy {
            max_per_call: 50_000, // 0.05 USDC (6dp)
            daily_cap: 2_000_000, // 2.00 USDC
            allow_rails: alloc::vec![Rail::Eip3009Base],
            hitl_above: 10_000_000, // above daily_cap: never triggers here
            ttl_secs: 3600,
            hitl_approver_pk,
        }
    }

    /// Policy for the HITL-threshold tests: `max_per_call`/`daily_cap` are
    /// set well above `hitl_above` so an amount just over the threshold is
    /// denied for exceeding *that*, not for hitting an unrelated ceiling.
    fn hitl_policy(hitl_approver_pk: Option<Vec<u8>>) -> SpendPolicy {
        SpendPolicy {
            max_per_call: 1_000_000, // 1.00 USDC
            daily_cap: 2_000_000,    // 2.00 USDC
            allow_rails: alloc::vec![Rail::Eip3009Base],
            hitl_above: 500_000, // 0.50 USDC
            ttl_secs: 3600,
            hitl_approver_pk,
        }
    }

    fn req(amount: u128) -> SpendRequest {
        SpendRequest {
            rail: Rail::Eip3009Base,
            amount,
            to: [0xAAu8; 20],
        }
    }

    #[test]
    fn over_max_per_call_denied() {
        let p = policy(None);
        let st = PolicyState::default();
        assert_eq!(
            p.check(&st, &req(50_001), 1_000),
            Err(PolicyViolation::ExceedsMaxPerCall)
        );
    }

    #[test]
    fn at_max_per_call_is_allowed() {
        let p = policy(None);
        let st = PolicyState::default();
        assert_eq!(p.check(&st, &req(50_000), 1_000), Ok(Decision::Allow));
    }

    #[test]
    fn daily_cap_accumulates_and_resets_after_86400s() {
        let p = policy(None);
        let mut st = PolicyState::default();

        // Spend up to just under the cap across several calls.
        for _ in 0..39 {
            let d = p.check(&st, &req(50_000), 1_000).expect("allowed");
            assert_eq!(d, Decision::Allow);
            st.record(50_000, 1_000);
        }
        assert_eq!(st.spent_today, 1_950_000);

        // One more 50_000 would hit exactly the 2_000_000 cap — allowed.
        assert_eq!(p.check(&st, &req(50_000), 1_000), Ok(Decision::Allow));
        st.record(50_000, 1_000);
        assert_eq!(st.spent_today, 2_000_000);

        // Any further spend within the same window is denied.
        assert_eq!(
            p.check(&st, &req(1), 1_000),
            Err(PolicyViolation::ExceedsDailyCap)
        );

        // After the window rolls (>= 86_400s later), the cap resets.
        let later = 1_000 + 86_400;
        assert_eq!(p.check(&st, &req(50_000), later), Ok(Decision::Allow));
    }

    #[test]
    fn amount_above_hitl_requires_approval() {
        let p = hitl_policy(None);
        let st = PolicyState::default();
        assert_eq!(
            p.check(&st, &req(500_001), 1_000),
            Ok(Decision::RequireHitl)
        );
    }

    #[test]
    fn amount_at_hitl_threshold_does_not_require_approval() {
        let p = hitl_policy(None);
        let st = PolicyState::default();
        assert_eq!(p.check(&st, &req(500_000), 1_000), Ok(Decision::Allow));
    }

    #[test]
    fn disallowed_rail_denied() {
        let p = policy(None);
        let st = PolicyState::default();
        let mut r = req(1);
        r.rail = Rail::Eip3009Ethereum;
        assert_eq!(
            p.check(&st, &r, 1_000),
            Err(PolicyViolation::RailNotAllowed)
        );
    }

    #[test]
    fn rail_check_takes_priority_over_amount_checks() {
        let p = policy(None);
        let st = PolicyState::default();
        let mut r = req(999_999_999); // also exceeds max_per_call and daily_cap
        r.rail = Rail::FheInternal;
        assert_eq!(
            p.check(&st, &r, 1_000),
            Err(PolicyViolation::RailNotAllowed)
        );
    }

    #[test]
    fn valid_hitl_approval_unblocks() {
        let approver = Identity::generate(&[0x42u8; 32]).expect("generate");
        let intent_hash = [0x11u8; 32];
        let amount = 500_001u128;
        let expiry = 10_000u64;
        let msg = hitl_approval_message(&intent_hash, amount, expiry);
        let sig = approver
            .sign_with_purpose(purpose::VAULT_HITL_APPROVAL_V1, &msg)
            .expect("sign");
        let approval = HitlApproval {
            approver_pk: approver.public_key(),
            signature: sig,
            intent_hash,
            amount,
            expiry_unix: expiry,
        };
        assert_eq!(
            approval.verify(&intent_hash, amount, Some(&approver.public_key()), 1_000),
            Ok(true)
        );
    }

    #[test]
    fn wrong_approver_key_does_not_unblock() {
        let approver = Identity::generate(&[0x42u8; 32]).expect("generate");
        let other = Identity::generate(&[0x43u8; 32]).expect("generate");
        let intent_hash = [0x22u8; 32];
        let amount = 500_001u128;
        let expiry = 10_000u64;
        let msg = hitl_approval_message(&intent_hash, amount, expiry);
        let sig = approver
            .sign_with_purpose(purpose::VAULT_HITL_APPROVAL_V1, &msg)
            .expect("sign");
        let approval = HitlApproval {
            approver_pk: approver.public_key(),
            signature: sig,
            intent_hash,
            amount,
            expiry_unix: expiry,
        };
        // Policy pins a *different* approver key than the one that signed.
        assert_eq!(
            approval.verify(&intent_hash, amount, Some(&other.public_key()), 1_000),
            Ok(false)
        );
    }

    #[test]
    fn expired_approval_does_not_unblock() {
        let approver = Identity::generate(&[0x42u8; 32]).expect("generate");
        let intent_hash = [0x33u8; 32];
        let amount = 500_001u128;
        let expiry = 1_000u64;
        let msg = hitl_approval_message(&intent_hash, amount, expiry);
        let sig = approver
            .sign_with_purpose(purpose::VAULT_HITL_APPROVAL_V1, &msg)
            .expect("sign");
        let approval = HitlApproval {
            approver_pk: approver.public_key(),
            signature: sig,
            intent_hash,
            amount,
            expiry_unix: expiry,
        };
        assert_eq!(
            approval.verify(&intent_hash, amount, None, expiry /* now == expiry */),
            Ok(false)
        );
    }

    #[test]
    fn approval_for_a_different_amount_does_not_unblock() {
        let approver = Identity::generate(&[0x42u8; 32]).expect("generate");
        let intent_hash = [0x44u8; 32];
        let expiry = 10_000u64;
        let msg = hitl_approval_message(&intent_hash, 500_001, expiry);
        let sig = approver
            .sign_with_purpose(purpose::VAULT_HITL_APPROVAL_V1, &msg)
            .expect("sign");
        let approval = HitlApproval {
            approver_pk: approver.public_key(),
            signature: sig,
            intent_hash,
            amount: 500_001,
            expiry_unix: expiry,
        };
        // Verifying against a larger requested amount than the approval covers.
        assert_eq!(
            approval.verify(&intent_hash, 600_000, None, 1_000),
            Ok(false)
        );
    }
}
