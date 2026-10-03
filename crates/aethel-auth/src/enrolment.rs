//! Enrolment: how a relying party first comes to know a key.
//!
//! Login proves control of a key the directory already knows. Enrolment is the
//! step before that. They get separate purposes because they are separate
//! claims, and reusing one purpose for both is exactly the confusion the
//! registry exists to prevent.
//!
//! # Enrolment creates an account. It never adopts one
//!
//! This is the load-bearing rule in the module, and it is worth being blunt
//! about why.
//!
//! An invite that can attach a *fresh* key to an *existing* account is account
//! takeover with a helpful name. Whoever issues invites could then read any
//! account by inviting a key they hold. That is precisely the capability an
//! operator must not have.
//!
//! So moving an existing account to a new key is **not** enrolment. It is a
//! [`Succession`](crate::statements::Succession), signed by the key standing
//! down. The two paths are different types, different purposes, different
//! functions.
//!
//! **What this crate can and cannot enforce.** There is no API here that binds
//! a fresh key to an account that already exists, so the crate offers no path
//! to the dangerous thing. It cannot stop a relying party taking an
//! [`EnrolledIdentity`] and attaching it to an existing row in its own
//! database. Nothing in a library can. What it can do is make sure the
//! convenient path and the correct path are the same one, and say plainly what
//! the incorrect one costs.
//!
//! # Recovery is HTSS, not an administrator
//!
//! Anyone looking for a way to let someone back in will arrive here, so the
//! answer lives here too.
//!
//! `AETHEL-PRODUCT-SPEC` calls recovery "a policy decision, not a
//! cryptographic one". That is true of re-establishing an **account** and
//! false of re-establishing a **key**. HTSS 3-of-5 is built: a holder splits
//! their identity's entropy, distributes shares to parties they choose, and
//! reconstructs without any operator involved.
//!
//! So the recovery story is holder-controlled and needs no administrator. An
//! administrator who *could* restore access could also take it, which is the
//! backdoor this whole design refuses.
//!
//! **The price, stated once and plainly:** with no operator path and no HTSS
//! shares arranged in advance, a lost key is a lost account at that relying
//! party. Under the per-relying-party identity model that costs one
//! relationship rather than all of them, which is the strongest argument for
//! that model. It also means a holder who adopts per-relying-party identities
//! *without* adopting HTSS has multiplied the number of things they can lose.

use core::future::Future;

use aethel_core::signing::verify_with_purpose;

use crate::error::{AuthError, StoreError};
use crate::proof::{push_len_prefixed, AuthMethod, AuthStrength, VerifyParams};
use crate::purposes::AUTH_ENROL_V1;

/// A holder's proof that it controls the key it is registering.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolmentProof {
    /// The ML-DSA-65 public key being registered.
    pub public_key: Vec<u8>,
    /// The relying party being registered with.
    pub audience: Vec<u8>,
    /// The invite being redeemed. Opaque to this crate; the relying party
    /// issued it and knows what it means.
    pub invite_id: Vec<u8>,
    /// 256 bits, fresh. Makes each enrolment signature unique even for a
    /// holder re-enrolling at the same service after leaving.
    pub nonce: [u8; 32],
    /// Unix seconds, per the holder's clock.
    pub issued_at: u64,
    /// Unix seconds, per the holder's clock.
    pub expires_at: u64,
    /// ML-DSA-65 signature over [`EnrolmentProof::signing_input`], under
    /// `AUTH_ENROL_V1`.
    pub signature: Vec<u8>,
}

impl EnrolmentProof {
    /// The exact bytes the signature covers.
    ///
    /// The invite is bound, so a proof of possession made for one invite
    /// cannot be redirected to another. Without that, an intercepted
    /// enrolment could be replayed against a different invitation.
    pub fn signing_input(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128 + self.audience.len() + self.invite_id.len());
        push_len_prefixed(&mut out, &self.audience);
        push_len_prefixed(&mut out, &self.invite_id);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        push_len_prefixed(&mut out, &self.nonce);
        out
    }
}

/// A key that has proven possession against a valid, unredeemed invite.
///
/// # What a relying party does with this
///
/// **Create a new account and bind this key to it.**
///
/// Not: look up an account by email, or name, or anything else the invite
/// might have been associated with, and attach the key to that. If the person
/// behind this key already has an account and has lost its key, the route back
/// is a succession signed by the old key, or HTSS recovery of the old key
/// itself. There is no third route, deliberately.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolledIdentity {
    /// The key that proved possession.
    pub public_key: Vec<u8>,
    /// The relying party it enrolled at.
    pub audience: Vec<u8>,
    /// The invite it redeemed, now spent.
    pub invite_id: Vec<u8>,
    /// Always [`AuthStrength::Proven`]: an enrolment that did not prove
    /// possession is not an enrolment.
    pub strength: AuthStrength,
    /// Always [`AuthMethod::Enrolment`].
    pub method: AuthMethod,
}

/// Single-use invitations.
///
/// # Redeem must be atomic
///
/// Same contract as the nonce store, for the same reason: a read followed by a
/// write lets two concurrent enrolments redeem one invite, which means two
/// keys claiming one invitation.
///
/// # An invite carries its grant
///
/// An invitation is *to* something: a tenant, a set of capabilities, whatever
/// the relying party means by it. [`InviteStore::Grant`] is that, in the
/// relying party's own terms, and redeeming hands it back **in the same atomic
/// step** that spends the invite. A store that only answered "spent or not"
/// would leave the relying party to look the meaning up separately, which is a
/// second read that can disagree with the first. `()` when invites carry
/// nothing.
pub trait InviteStore: Send + Sync {
    /// What redeeming an invite entitles the new account to.
    type Grant: Send;

    /// Spend `invite_id` if it exists, is unspent, and has not lapsed, and
    /// return what it grants.
    ///
    /// Returns `Ok(Some(grant))` if this call spent it, `Ok(None)` if it was
    /// unknown, already spent, or expired. The three are deliberately one
    /// answer: distinguishing them would let someone probe which invitations
    /// exist.
    fn redeem(&self, invite_id: &[u8], now: u64)
        -> impl Future<Output = Result<Option<Self::Grant>, StoreError>> + Send;
}

/// In-process invite store. Reference implementation, not a deployment.
pub struct InMemoryInviteStore<G = ()> {
    invites: std::sync::Mutex<std::collections::HashMap<Vec<u8>, (u64, G)>>,
}

impl<G> Default for InMemoryInviteStore<G> {
    fn default() -> Self {
        Self::new()
    }
}

impl<G> InMemoryInviteStore<G> {
    /// An empty store.
    pub fn new() -> Self {
        Self {
            invites: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Issue an invite valid until `expires_at` that grants `grant`.
    pub fn issue_granting(&self, invite_id: Vec<u8>, expires_at: u64, grant: G) {
        self.invites
            .lock()
            .expect("invite store mutex poisoned")
            .insert(invite_id, (expires_at, grant));
    }

    /// How many invitations are outstanding. Tests only.
    pub fn len(&self) -> usize {
        self.invites.lock().expect("invite store mutex poisoned").len()
    }

    /// Whether none are outstanding. Tests only.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl InMemoryInviteStore<()> {
    /// Issue an invite that grants nothing beyond an account, valid until
    /// `expires_at`.
    pub fn issue(&self, invite_id: Vec<u8>, expires_at: u64) {
        self.issue_granting(invite_id, expires_at, ());
    }
}

impl<G: Send> InviteStore for InMemoryInviteStore<G> {
    type Grant = G;

    async fn redeem(&self, invite_id: &[u8], now: u64) -> Result<Option<G>, StoreError> {
        let mut invites = self.invites.lock().expect("invite store mutex poisoned");
        match invites.get(invite_id) {
            Some((expires_at, _)) if *expires_at > now => Ok(invites.remove(invite_id).map(|(_, grant)| grant)),
            // Unknown, spent and lapsed are one answer on purpose.
            _ => Ok(None),
        }
    }
}

/// The signature and envelope half of enrolment, with no store touched.
fn verify_possession(proof: &EnrolmentProof, params: &VerifyParams<'_>) -> Result<(), AuthError> {
    if proof.public_key.is_empty() || proof.signature.is_empty() || proof.invite_id.is_empty() {
        return Err(AuthError::Malformed);
    }

    crate::proof::check_envelope(&proof.audience, proof.issued_at, proof.expires_at, params)?;

    let verified = verify_with_purpose(
        &proof.public_key,
        AUTH_ENROL_V1,
        &proof.signing_input(),
        &proof.signature,
    )
    .map_err(|_| AuthError::Malformed)?;

    if !verified {
        return Err(AuthError::BadSignature);
    }
    Ok(())
}

fn enrolled(proof: &EnrolmentProof) -> EnrolledIdentity {
    EnrolledIdentity {
        public_key: proof.public_key.clone(),
        audience: proof.audience.clone(),
        invite_id: proof.invite_id.clone(),
        strength: AuthStrength::Proven,
        method: AuthMethod::Enrolment,
    }
}

/// Verify an enrolment, spend its invite, and return what the invite granted.
///
/// # Order of checks
///
/// The signature is verified **before** the invite is redeemed, so a bad
/// signature does not burn a holder's invitation. That matters more here than
/// it does for a nonce: a nonce is the holder's own throwaway value, whereas
/// an invite is a scarce thing someone had to issue, and burning it on a
/// failed attempt would turn a garbled request into a support ticket.
///
/// Prefer [`enrol`], which also creates the account through a [`Directory`].
pub async fn verify_enrolment<I: InviteStore>(
    proof: &EnrolmentProof,
    params: VerifyParams<'_>,
    invites: &I,
) -> Result<(EnrolledIdentity, I::Grant), AuthError> {
    verify_possession(proof, &params)?;
    let grant = invites
        .redeem(&proof.invite_id, params.now)
        .await?
        .ok_or(AuthError::InviteNotRedeemable)?;
    Ok((enrolled(proof), grant))
}

// ── The directory ────────────────────────────────────────────────────────────

/// Where a relying party records which key belongs to which account.
///
/// This crate defines what a directory must do and stores nothing itself; the
/// relying party implements it over its own storage. It is a trait here, not
/// left to each consumer, so that the one operation that creates an account is
/// named for exactly that and the safe enrolment path is the convenient one.
///
/// # The rule an implementation must keep
///
/// [`Directory::create_account`] **creates**. It must mint a new account for
/// the key and must never bind the key to an account that already exists,
/// whatever the grant says. An implementation that looks up "the account this
/// invite was for" and attaches the key to it is account takeover by invite:
/// whoever issues invites could then take any account. See the module docs.
pub trait Directory: Send + Sync {
    /// The relying party's account type, as sessions carry it.
    type Account: Send;
    /// What an invite grants. Must match the [`InviteStore`] used with it.
    type Grant: Send;

    /// The account `public_key` is bound to, if any.
    fn resolve(&self, public_key: &[u8])
        -> impl Future<Output = Result<Option<Self::Account>, StoreError>> + Send;

    /// Create a new account for a freshly enrolled key, shaped by `grant`.
    ///
    /// Must refuse with [`AuthError::KeyAlreadyEnrolled`] if the key is
    /// already bound, atomically: two concurrent enrolments of one key must
    /// not both succeed.
    fn create_account(&self, enrolled: &EnrolledIdentity, grant: Self::Grant)
        -> impl Future<Output = Result<Self::Account, AuthError>> + Send;
}

/// Enrol a key: verify possession, spend the invite, create the account.
///
/// The way a relying party should handle an enrolment. A key that is already
/// enrolled is refused **before** the invite is spent, so a holder who enrols
/// twice by mistake does not burn an invitation. (Two enrolments of one key
/// racing each other can still spend one invite; the directory's atomic check
/// then refuses the loser.)
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

/// In-process directory. Reference implementation, not a deployment.
///
/// `mint` turns a grant into a **new** account; it is called once per
/// successful enrolment and nowhere else.
pub struct InMemoryDirectory<A, G, F> {
    accounts: std::sync::Mutex<std::collections::HashMap<Vec<u8>, A>>,
    mint: F,
    _grant: core::marker::PhantomData<fn(G)>,
}

impl<A, G, F> InMemoryDirectory<A, G, F>
where
    F: Fn(&EnrolledIdentity, G) -> A,
{
    /// An empty directory that mints accounts with `mint`.
    pub fn new(mint: F) -> Self {
        Self {
            accounts: std::sync::Mutex::new(std::collections::HashMap::new()),
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
        Ok(self.accounts.lock().expect("directory mutex poisoned").get(public_key).cloned())
    }

    async fn create_account(&self, enrolled: &EnrolledIdentity, grant: G) -> Result<A, AuthError> {
        let mut accounts = self.accounts.lock().expect("directory mutex poisoned");
        if accounts.contains_key(&enrolled.public_key) {
            return Err(AuthError::KeyAlreadyEnrolled);
        }
        let account = (self.mint)(enrolled, grant);
        accounts.insert(enrolled.public_key.clone(), account.clone());
        Ok(account)
    }
}
