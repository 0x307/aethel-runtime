//! The directory: which key is which account at a relying party, and the four
//! things that may ever happen to that binding.
//!
//! 1. **Enrol** ([`enrol`]): a key proves possession against an invite and a
//!    new account is created for it.
//! 2. **Resolve**: a key names its account, if it is live.
//! 3. **Revoke** ([`revoke`]): a key stops naming its account. Signed by the
//!    holder, or by a recognised authority.
//! 4. **Succeed** ([`succeed`]): an account moves from one key to another,
//!    signed by the **outgoing** key and nobody else.
//!
//! # What is absent, deliberately
//!
//! Nothing binds a key to an account that already exists except succession,
//! and succession needs the old key's signature. So no operator, inviter or
//! authority can move an account to a key they hold. Revocation only removes;
//! nothing here grants. That asymmetry is what lets an operator safely hold
//! revocation powers (see [`crate::statements`]).
//!
//! # This crate stores nothing
//!
//! [`Directory`] says what a relying party's directory must do; the relying
//! party implements it over its own storage. Recording revocations and
//! successions durably, and ending sessions opened under a revoked key, are
//! the relying party's job.

use core::future::Future;

use crate::enrolment::{enrolled, verify_possession, EnrolledIdentity, EnrolmentProof, InviteStore};
use crate::error::{AuthError, StoreError};
use crate::proof::VerifyParams;
use crate::statements::{verify_revocation, verify_succession, Revocation, Succession};

/// Where a relying party records which key belongs to which account.
///
/// # The rules an implementation must keep
///
/// - [`Directory::create_account`] **creates**. It mints a new account for the
///   key and never binds the key to one that already exists, whatever the
///   grant says. An implementation that looks up "the account this invite was
///   for" and attaches the key to it is account takeover by invite.
/// - [`Directory::revoke_key`] and [`Directory::succeed_key`] are only ever
///   called with a statement that has **already been verified**. Use
///   [`revoke`] and [`succeed`], which verify first.
/// - Every mutating method is atomic with respect to the others: two
///   enrolments of one key, or a succession racing a revocation, must not both
///   take effect.
pub trait Directory: Send + Sync {
    /// The relying party's account type, as sessions carry it.
    type Account: Send;
    /// What an invite grants. Must match the [`InviteStore`] used with it.
    type Grant: Send;

    /// The account `public_key` is bound to, if the key is live.
    fn resolve(&self, public_key: &[u8])
        -> impl Future<Output = Result<Option<Self::Account>, StoreError>> + Send;

    /// Create a new account for a freshly enrolled key, shaped by `grant`.
    ///
    /// Refuses with [`AuthError::KeyAlreadyEnrolled`] if the key is already
    /// bound, or was ever revoked: a revoked key never comes back.
    fn create_account(&self, enrolled: &EnrolledIdentity, grant: Self::Grant)
        -> impl Future<Output = Result<Self::Account, AuthError>> + Send;

    /// Unbind a verified revocation's subject key from its account.
    ///
    /// Returns the account it named, or `None` if the key was not live (never
    /// enrolled, already revoked, or succeeded). Revoking twice is not an
    /// error: the outcome the signer asked for already holds.
    fn revoke_key(&self, revocation: &Revocation)
        -> impl Future<Output = Result<Option<Self::Account>, AuthError>> + Send;

    /// Move an account from a verified succession's outgoing key to its
    /// successor, and return the account.
    ///
    /// Refuses with [`AuthError::NotAuthorised`] if the outgoing key is not
    /// live (an old succession replayed after a later one, or a revoked key
    /// trying to hand over), and with [`AuthError::KeyAlreadyEnrolled`] if the
    /// successor is already bound or was ever revoked.
    fn succeed_key(&self, succession: &Succession)
        -> impl Future<Output = Result<Self::Account, AuthError>> + Send;
}

/// Enrol a key: verify possession, spend the invite, create the account.
///
/// The way a relying party should handle an enrolment. A key that is already
/// enrolled is refused **before** the invite is spent, so a holder who enrols
/// twice by mistake does not burn an invitation. (Two enrolments of one key
/// racing each other can still spend one invite; the directory's atomic check
/// then refuses the loser. So does a key that was once revoked: it no longer
/// resolves, so it is caught by [`Directory::create_account`] after the
/// invite is spent. Rare, and it fails closed.)
pub async fn enrol<I, D>(
    proof: &EnrolmentProof,
    params: VerifyParams<'_>,
    invites: &I,
    directory: &D,
) -> Result<D::Account, AuthError>
where
    I: InviteStore,
    D: Directory<Grant = I::Grant>,
{
    verify_possession(proof, &params)?;
    if directory.resolve(&proof.public_key).await?.is_some() {
        return Err(AuthError::KeyAlreadyEnrolled);
    }
    let grant = invites
        .redeem(&proof.invite_id, params.now)
        .await?
        .ok_or(AuthError::InviteNotRedeemable)?;
    directory.create_account(&enrolled(proof), grant).await
}

/// Verify a revocation and apply it. Returns the account the key named, if it
/// was live.
///
/// `authority_keys` are the keys this relying party recognises as entitled to
/// revoke *other* keys. A holder revoking its own key needs none of them.
pub async fn revoke<D: Directory>(
    revocation: &Revocation,
    expected_audience: &[u8],
    authority_keys: &[Vec<u8>],
    directory: &D,
) -> Result<Option<D::Account>, AuthError> {
    verify_revocation(revocation, expected_audience, authority_keys)?;
    directory.revoke_key(revocation).await
}

/// Verify a succession and apply it. Returns the account, now on its new key.
pub async fn succeed<D: Directory>(
    succession: &Succession,
    expected_audience: &[u8],
    directory: &D,
) -> Result<D::Account, AuthError> {
    verify_succession(succession, expected_audience)?;
    directory.succeed_key(succession).await
}

/// In-process directory. Reference implementation, not a deployment.
///
/// `mint` turns a grant into a **new** account; it is called once per
/// successful enrolment and nowhere else.
pub struct InMemoryDirectory<A, G, F> {
    state: std::sync::Mutex<MemoryState<A>>,
    mint: F,
    _grant: core::marker::PhantomData<fn(G)>,
}

struct MemoryState<A> {
    live: std::collections::HashMap<Vec<u8>, A>,
    /// Every key that was ever revoked or succeeded away from. None of them
    /// may be bound again.
    retired: std::collections::HashSet<Vec<u8>>,
}

impl<A, G, F> InMemoryDirectory<A, G, F>
where
    F: Fn(&EnrolledIdentity, G) -> A,
{
    /// An empty directory that mints accounts with `mint`.
    pub fn new(mint: F) -> Self {
        Self {
            state: std::sync::Mutex::new(MemoryState {
                live: std::collections::HashMap::new(),
                retired: std::collections::HashSet::new(),
            }),
            mint,
            _grant: core::marker::PhantomData,
        }
    }
}

impl<A, G, F> Directory for InMemoryDirectory<A, G, F>
where
    A: Clone + Send,
    G: Send,
    F: Fn(&EnrolledIdentity, G) -> A + Send + Sync,
{
    type Account = A;
    type Grant = G;

    async fn resolve(&self, public_key: &[u8]) -> Result<Option<A>, StoreError> {
        Ok(self.state.lock().expect("directory mutex poisoned").live.get(public_key).cloned())
    }

    async fn create_account(&self, enrolled: &EnrolledIdentity, grant: G) -> Result<A, AuthError> {
        let mut state = self.state.lock().expect("directory mutex poisoned");
        if state.live.contains_key(&enrolled.public_key) || state.retired.contains(&enrolled.public_key) {
            return Err(AuthError::KeyAlreadyEnrolled);
        }
        let account = (self.mint)(enrolled, grant);
        state.live.insert(enrolled.public_key.clone(), account.clone());
        Ok(account)
    }

    async fn revoke_key(&self, revocation: &Revocation) -> Result<Option<A>, AuthError> {
        let mut state = self.state.lock().expect("directory mutex poisoned");
        let account = state.live.remove(&revocation.subject_key);
        state.retired.insert(revocation.subject_key.clone());
        Ok(account)
    }

    async fn succeed_key(&self, succession: &Succession) -> Result<A, AuthError> {
        let mut state = self.state.lock().expect("directory mutex poisoned");
        if state.live.contains_key(&succession.to_key) || state.retired.contains(&succession.to_key) {
            return Err(AuthError::KeyAlreadyEnrolled);
        }
        let account = state.live.remove(&succession.from_key).ok_or(AuthError::NotAuthorised)?;
        state.retired.insert(succession.from_key.clone());
        state.live.insert(succession.to_key.clone(), account.clone());
        Ok(account)
    }
}
