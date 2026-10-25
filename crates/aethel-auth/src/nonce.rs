//! Replay protection for client-asserted proofs.
//!
//! # This is the replay protection, not a cache
//!
//! The handshake is client-asserted: the holder picks its own nonce and the
//! verifier never issued anything. So the only thing standing between a
//! captured proof and a successful replay is this store remembering that the
//! nonce has been seen.
//!
//! That is a sharper requirement than a server-issued challenge had. There,
//! losing state was harmless, because a forgotten challenge simply means the
//! user tries again. Here, **a forgotten nonce is a replay window** lasting as
//! long as the proof's validity. A store that is per-process, or that empties
//! on restart, is not a correct deployment of this crate. It is a test double.

use core::future::Future;

use crate::error::StoreError;

/// Remembers which nonces have been spent.
///
/// # Implementors must make [`claim`](NonceStore::claim) atomic
///
/// The whole contract is in one operation: insert the nonce **and** report
/// whether it was already there, indivisibly. A implementation that reads and
/// then writes lets two concurrent requests carrying the same proof both
/// observe "not present" and both succeed, which is precisely the replay this
/// exists to stop.
///
/// In SQL that is an `INSERT ... ON CONFLICT DO NOTHING` and checking the rows
/// affected. In Redis it is `SET key value NX EX ttl` and checking for nil.
/// Neither is a read followed by a write.
pub trait NonceStore: Send + Sync {
    /// Claim `nonce` until `expires_at` (unix seconds).
    ///
    /// Returns `Ok(true)` if this call claimed it, `Ok(false)` if it was
    /// already spent. An `Err` means the store could not answer, which is not
    /// the same as a rejection and must not be reported to the client as one.
    ///
    /// `expires_at` lets the store drop the entry once the proof it protects
    /// could no longer be valid anyway. A store is free to keep it longer;
    /// keeping it for less is a replay window.
    fn claim(
        &self,
        nonce: &[u8; 32],
        expires_at: u64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
}

/// In-process nonce store.
///
/// # Reference implementation. Not for a real deployment
///
/// State lives in one process's memory, so it is wrong in the two ways that
/// matter: a second instance of your service shares none of it, and a restart
/// forgets all of it. Either one reopens the replay window this type exists to
/// close.
///
/// It is here so the tests in this crate, and a consumer's own tests, have
/// something to run against. A deployment needs a store that every instance
/// sees and that survives a restart.
pub struct InMemoryNonceStore {
    seen: std::sync::Mutex<std::collections::HashMap<[u8; 32], u64>>,
}

impl Default for InMemoryNonceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryNonceStore {
    /// An empty store.
    pub fn new() -> Self {
        Self {
            seen: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Drop entries that can no longer protect anything. A real store does
    /// this with a TTL; here it is manual so a long-lived test process does
    /// not grow without bound.
    pub fn evict_expired(&self, now: u64) {
        self.seen
            .lock()
            .expect("nonce store mutex poisoned")
            .retain(|_, expires_at| *expires_at > now);
    }

    /// How many nonces are currently remembered. Tests only.
    pub fn len(&self) -> usize {
        self.seen.lock().expect("nonce store mutex poisoned").len()
    }

    /// Whether nothing is currently remembered. Tests only.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl NonceStore for InMemoryNonceStore {
    async fn claim(&self, nonce: &[u8; 32], expires_at: u64) -> Result<bool, StoreError> {
        let mut seen = self.seen.lock().expect("nonce store mutex poisoned");
        // `entry` is the atomic read-and-write. Checking `contains_key` first
        // and inserting after would be the race this trait's contract forbids.
        match seen.entry(*nonce) {
            std::collections::hash_map::Entry::Occupied(_) => Ok(false),
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(expires_at);
                Ok(true)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block_on<F: Future>(f: F) -> F::Output {
        // A one-shot executor. The crate has no runtime dependency and these
        // futures never actually yield, so polling once is sufficient.
        use core::task::{Context, Poll, Waker};
        let mut cx = Context::from_waker(Waker::noop());
        let mut f = Box::pin(f);
        match f.as_mut().poll(&mut cx) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("future parked; this store does not yield"),
        }
    }

    #[test]
    fn a_nonce_can_be_claimed_exactly_once() {
        let store = InMemoryNonceStore::new();
        let nonce = [9u8; 32];

        assert!(
            block_on(store.claim(&nonce, 1_000)).unwrap(),
            "first claim wins"
        );
        assert!(
            !block_on(store.claim(&nonce, 1_000)).unwrap(),
            "the same nonce must not be claimable twice: that is the replay"
        );
    }

    #[test]
    fn distinct_nonces_do_not_interfere() {
        let store = InMemoryNonceStore::new();
        assert!(block_on(store.claim(&[1u8; 32], 1_000)).unwrap());
        assert!(block_on(store.claim(&[2u8; 32], 1_000)).unwrap());
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn eviction_drops_only_what_can_no_longer_protect_anything() {
        let store = InMemoryNonceStore::new();
        block_on(store.claim(&[1u8; 32], 100)).unwrap();
        block_on(store.claim(&[2u8; 32], 900)).unwrap();

        store.evict_expired(500);

        assert_eq!(store.len(), 1, "the entry expiring at 900 must survive");
        assert!(
            !block_on(store.claim(&[2u8; 32], 900)).unwrap(),
            "a surviving entry still blocks its replay"
        );
        assert!(
            block_on(store.claim(&[1u8; 32], 900)).unwrap(),
            "an evicted entry is claimable again, which is why eviction must \
             never run ahead of the proof's own expiry"
        );
    }
}
