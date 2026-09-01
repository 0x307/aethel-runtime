//! # Aethel-Vault TFHE Vault Smart Contract
//!
//! Production-grade Rust smart contract targeting WebAssembly
//! (`wasm32-unknown-unknown`). Implements blind-state balance management
//! using TFHE homomorphic encryption.
//!
//! ## Architecture
//!
//! ### WASM Target (`wasm32-unknown-unknown`)
//!
//! The WASM binary is a **pure state machine** — it stores serialized
//! ciphertext bytes and delegates all homomorphic operations to the
//! wasmer.io host environment via WASM host imports. This keeps the
//! binary small and avoids the tfhe WASM compilation complexity.
//!
//! The host provides:
//! - `host_fhe_sub(sender_ct, transfer_ct) -> new_sender_ct`
//! - `host_fhe_add(receiver_ct, transfer_ct) -> new_receiver_ct`
//! - `host_fhe_ge(a_ct, b_ct) -> bool_ct`
//! - `host_fhe_select(cond_ct, true_ct, false_ct) -> result_ct`
//!
//! ### Native Target (std)
//!
//! Uses `tfhe` crate directly with `FheUint64` for homomorphic operations.
//!
//! ## Vault ID Binding
//!
//! Vault IDs are derived from PLP ephemeral projections via SHAKE-256:
//! ```text
//! vault_id = SHAKE-256("AETHEL_VAULT_ID_V1" || plp_projection_bytes)[0..32]
//! ```
//!
//! ## Entry Points
//!
//! - [`init_vault`] — Initialize contract with TFHE ServerKey
//! - [`register_vault_ciphertext`] — Deposit encrypted balance
//! - [`homomorphic_transfer`] — Execute blind transfer (unauthenticated: any
//!   caller who knows a sender vault ID and possesses a `ServerKey` can move
//!   its funds)
//! - [`register_vault_with_identity`] — Deposit encrypted balance bound to a
//!   real `aethel-core` PLP identity projection
//! - [`homomorphic_transfer_authenticated`] — Execute blind transfer gated on
//!   a `aethel-core` PLP ownership proof, verified against the projection the
//!   sender vault was registered with
//! - [`derive_vault_id`] — Derive vault ID from PLP projection bytes
//! - [`export_vault_state_len`] / [`export_vault_state_ptr`] — State export
//! - [`import_vault_state`] — State import
//!
//! ## Identity Coupling
//!
//! [`homomorphic_transfer`] authorizes a transfer by possession of
//! ciphertexts and a `ServerKey` alone — nothing checks who is asking.
//! [`homomorphic_transfer_authenticated`] is the first operation that does:
//! it requires a `aethel_core::plp::ZkIdentityProof` that verifies (via
//! `aethel_core::plp::Verifier::verify`) against the sender vault's bound
//! `EphemeralProjection`, so a caller must prove knowledge of the master
//! secret behind the projection the vault was registered under, not merely
//! know the vault's ID.
//!
//! This wires a PLP ownership proof rather than a full SAAP presentation.
//! Both hit the same constraint: `aethel-core` deliberately exposes no public
//! constructor for the polynomial types inside a proof or a SAAP
//! presentation (only its own `Prover`/`credential::prove` can produce one),
//! so neither can be deserialized from bytes submitted by an untrusted
//! network caller with the current `aethel-core` API. Because a full SAAP
//! presentation would face that identical wire-format gap for strictly more
//! implementation work, the PLP proof is the smaller correct step. See
//! `docs/ROADMAP.md` for what closing that gap would take.

extern crate alloc;

use alloc::vec::Vec;
use core::cell::RefCell;
use serde::{Deserialize, Serialize};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

// ── Error Codes ───────────────────────────────────────────────────────────────

/// Success — operation completed without error.
pub const ERR_OK: u32 = 0;
/// Vault not found — the specified vault ID is not registered.
pub const ERR_NOT_FOUND: u32 = 1;
/// Insufficient balance — handled homomorphically (not returned as error).
pub const ERR_INSUFFICIENT_BALANCE: u32 = 2;
/// Deserialization error — ciphertext or key bytes are malformed.
pub const ERR_DESER: u32 = 3;
/// Invalid key — ServerKey not initialized or invalid.
pub const ERR_INVALID_KEY: u32 = 4;
/// Unauthorized — the sender vault has no identity binding, the supplied
/// projection does not match the one it was registered with, or the supplied
/// proof does not verify against it.
pub const ERR_UNAUTHORIZED: u32 = 5;

// ── Vault State ───────────────────────────────────────────────────────────────

/// Persistent Vault Contract State.
///
/// Stores the mapping of anonymous ephemeral vault IDs to serialized
/// `FheUint64` ciphertext bytes. The ciphertexts are opaque byte blobs
/// from the vault's perspective — homomorphic operations are performed
/// by the host environment (wasmer.io) on native, or by the tfhe crate
/// on native test builds.
#[derive(Serialize, Deserialize)]
pub struct VaultState {
    /// Mapping of 32-byte vault IDs to serialized `FheUint64` ciphertext bytes.
    pub balances: Vec<([u8; 32], Vec<u8>)>,
    /// Serialized `ServerKey` bytes (stored for native builds; unused in WASM).
    pub server_key_bytes: Option<Vec<u8>>,
    /// Mapping of 32-byte vault IDs to the serialized `aethel-core`
    /// `EphemeralProjection` bytes they were registered under, for vaults
    /// registered via [`register_vault_with_identity`]. A vault registered
    /// via the plain [`register_vault_ciphertext`] has no entry here, and
    /// [`homomorphic_transfer_authenticated`] refuses to move its funds.
    pub identity_projections: Vec<([u8; 32], Vec<u8>)>,
}

impl VaultState {
    fn new() -> Self {
        VaultState {
            balances: Vec::new(),
            server_key_bytes: None,
            identity_projections: Vec::new(),
        }
    }
}

// ── Thread-Local State (WASM-safe, single-threaded) ───────────────────────────

thread_local! {
    static STATE: RefCell<Option<VaultState>> = RefCell::new(None);
}

fn with_state_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut VaultState) -> R,
{
    STATE.with(|s| {
        let mut borrow = s.borrow_mut();
        let state = borrow.get_or_insert_with(VaultState::new);
        f(state)
    })
}

// ── Vault ID Derivation ───────────────────────────────────────────────────────

/// Derive a 32-byte vault ID from PLP ephemeral projection bytes.
///
/// Uses SHAKE-256 with domain separation prefix `"AETHEL_VAULT_ID_V1"` to
/// create a one-way binding between the identity layer (aethel-core PLP) and
/// the vault layer (aethel-runtime) without exposing the underlying secret.
///
/// ```text
/// vault_id = SHAKE-256("AETHEL_VAULT_ID_V1" || plp_projection_bytes)[0..32]
/// ```
pub fn derive_vault_id(plp_projection_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(b"AETHEL_VAULT_ID_V1");
    hasher.update(plp_projection_bytes);
    let mut xof = hasher.finalize_xof();
    let mut vault_id = [0u8; 32];
    xof.read(&mut vault_id);
    vault_id
}

// ── WASM Host Imports (wasm32 target only) ────────────────────────────────────
//
// On wasm32, homomorphic operations are delegated to the wasmer.io host.
// The host provides these functions via WASM imports.
// The vault contract passes serialized ciphertext bytes to the host and
// receives updated ciphertext bytes back.

#[cfg(target_arch = "wasm32")]
mod host_fhe {
    // Declare WASM host imports from the "env" module.
    // The wasmer.io host environment provides these functions.
    // The `#[link(wasm_import_module = "env")]` attribute tells the WASM
    // linker that these symbols come from the host's "env" import namespace.
    #[link(wasm_import_module = "env")]
    extern "C" {
        /// Homomorphic subtraction: returns serialized (a - b) ciphertext.
        /// Result is written to `out_ptr`; returns length of result.
        pub fn host_fhe_sub(
            a_ptr: *const u8, a_len: usize,
            b_ptr: *const u8, b_len: usize,
            out_ptr: *mut u8, out_max: usize,
        ) -> usize;

        /// Homomorphic addition: returns serialized (a + b) ciphertext.
        pub fn host_fhe_add(
            a_ptr: *const u8, a_len: usize,
            b_ptr: *const u8, b_len: usize,
            out_ptr: *mut u8, out_max: usize,
        ) -> usize;

        /// Homomorphic comparison: returns serialized FheBool (a >= b).
        pub fn host_fhe_ge(
            a_ptr: *const u8, a_len: usize,
            b_ptr: *const u8, b_len: usize,
            out_ptr: *mut u8, out_max: usize,
        ) -> usize;

        /// Homomorphic conditional select: returns cond ? true_ct : false_ct.
        pub fn host_fhe_select(
            cond_ptr: *const u8, cond_len: usize,
            true_ptr: *const u8, true_len: usize,
            false_ptr: *const u8, false_len: usize,
            out_ptr: *mut u8, out_max: usize,
        ) -> usize;

        /// Trivial encryption of 0u64. Returns serialized FheUint64.
        pub fn host_fhe_zero(out_ptr: *mut u8, out_max: usize) -> usize;
    }
}

// ── WASM Transfer Implementation ──────────────────────────────────────────────

#[cfg(target_arch = "wasm32")]
fn do_homomorphic_transfer(
    sender_ct: &[u8],
    receiver_ct: &[u8],
    transfer_ct: &[u8],
) -> Option<(Vec<u8>, Vec<u8>)> {
    // Buffer for host FHE results — 64KB should be sufficient for FheUint64
    const BUF_SIZE: usize = 65536;

    unsafe {
        // Step 1: is_sufficient = (sender_balance >= transfer_amount)
        let mut ge_buf = alloc::vec![0u8; BUF_SIZE];
        let ge_len = host_fhe::host_fhe_ge(
            sender_ct.as_ptr(), sender_ct.len(),
            transfer_ct.as_ptr(), transfer_ct.len(),
            ge_buf.as_mut_ptr(), BUF_SIZE,
        );
        if ge_len == 0 { return None; }
        ge_buf.truncate(ge_len);

        // Step 2: zero = trivial_encrypt(0)
        let mut zero_buf = alloc::vec![0u8; BUF_SIZE];
        let zero_len = host_fhe::host_fhe_zero(zero_buf.as_mut_ptr(), BUF_SIZE);
        if zero_len == 0 { return None; }
        zero_buf.truncate(zero_len);

        // Step 3: actual_deduction = is_sufficient ? transfer_amount : 0
        let mut deduction_buf = alloc::vec![0u8; BUF_SIZE];
        let deduction_len = host_fhe::host_fhe_select(
            ge_buf.as_ptr(), ge_buf.len(),
            transfer_ct.as_ptr(), transfer_ct.len(),
            zero_buf.as_ptr(), zero_buf.len(),
            deduction_buf.as_mut_ptr(), BUF_SIZE,
        );
        if deduction_len == 0 { return None; }
        deduction_buf.truncate(deduction_len);

        // Step 4: new_sender = sender_balance - actual_deduction
        let mut new_sender_buf = alloc::vec![0u8; BUF_SIZE];
        let new_sender_len = host_fhe::host_fhe_sub(
            sender_ct.as_ptr(), sender_ct.len(),
            deduction_buf.as_ptr(), deduction_buf.len(),
            new_sender_buf.as_mut_ptr(), BUF_SIZE,
        );
        if new_sender_len == 0 { return None; }
        new_sender_buf.truncate(new_sender_len);

        // Step 5: new_receiver = receiver_balance + actual_deduction
        let mut new_receiver_buf = alloc::vec![0u8; BUF_SIZE];
        let new_receiver_len = host_fhe::host_fhe_add(
            receiver_ct.as_ptr(), receiver_ct.len(),
            deduction_buf.as_ptr(), deduction_buf.len(),
            new_receiver_buf.as_mut_ptr(), BUF_SIZE,
        );
        if new_receiver_len == 0 { return None; }
        new_receiver_buf.truncate(new_receiver_len);

        Some((new_sender_buf, new_receiver_buf))
    }
}

// ── Native Transfer Implementation ────────────────────────────────────────────

#[cfg(not(target_arch = "wasm32"))]
fn do_homomorphic_transfer(
    sender_ct_bytes: &[u8],
    receiver_ct_bytes: &[u8],
    transfer_ct_bytes: &[u8],
    server_key_bytes: &[u8],
) -> Option<(Vec<u8>, Vec<u8>)> {
    use tfhe::{prelude::*, FheUint64, ServerKey};

    let server_key: ServerKey = bincode::deserialize(server_key_bytes).ok()?;
    tfhe::set_server_key(server_key);

    let sender_balance: FheUint64 = bincode::deserialize(sender_ct_bytes).ok()?;
    let receiver_balance: FheUint64 = bincode::deserialize(receiver_ct_bytes).ok()?;
    let transfer_amount: FheUint64 = bincode::deserialize(transfer_ct_bytes).ok()?;

    // Homomorphic solvency check
    let is_sufficient = sender_balance.ge(&transfer_amount);

    // Conditional deduction
    let zero: FheUint64 = FheUint64::encrypt_trivial(0u64);
    let actual_deduction = is_sufficient.if_then_else(&transfer_amount, &zero);

    // Homomorphic arithmetic
    let new_sender = sender_balance - &actual_deduction;
    let new_receiver = receiver_balance + &actual_deduction;

    let new_sender_bytes = bincode::serialize(&new_sender).ok()?;
    let new_receiver_bytes = bincode::serialize(&new_receiver).ok()?;

    Some((new_sender_bytes, new_receiver_bytes))
}

// ── WASM Exports ──────────────────────────────────────────────────────────────

/// Initialize contract and set the TFHE Server Key (Evaluation Key).
///
/// On WASM: stores the key bytes for the host to use.
/// On native: validates and stores the key for homomorphic operations.
///
/// # Returns
///
/// - `ERR_OK` (0) on success
/// - `ERR_DESER` (3) if key bytes are invalid
#[no_mangle]
pub extern "C" fn init_vault(server_key_bytes_ptr: *const u8, len: usize) -> u32 {
    let key_bytes = unsafe { core::slice::from_raw_parts(server_key_bytes_ptr, len) };

    // On native: validate by deserializing
    #[cfg(not(target_arch = "wasm32"))]
    {
        use tfhe::ServerKey;
        let _: ServerKey = match bincode::deserialize(key_bytes) {
            Ok(k) => k,
            Err(_) => return ERR_DESER,
        };
    }

    with_state_mut(|state| {
        state.server_key_bytes = Some(key_bytes.to_vec());
    });

    ERR_OK
}

/// Deposit/Initialize an encrypted balance into an anonymous vault.
///
/// # Returns
///
/// - `ERR_OK` (0) on success
/// - `ERR_DESER` (3) if vault_id is not 32 bytes
#[no_mangle]
pub extern "C" fn register_vault_ciphertext(
    vault_id_ptr: *const u8,
    vault_id_len: usize,
    initial_ct_ptr: *const u8,
    initial_ct_len: usize,
) -> u32 {
    let vault_id_slice = unsafe { core::slice::from_raw_parts(vault_id_ptr, vault_id_len) };
    let ct_bytes = unsafe { core::slice::from_raw_parts(initial_ct_ptr, initial_ct_len) };

    if vault_id_slice.len() != 32 {
        return ERR_DESER;
    }

    let mut vault_id = [0u8; 32];
    vault_id.copy_from_slice(vault_id_slice);

    with_state_mut(|state| {
        state.balances.push((vault_id, ct_bytes.to_vec()));
    });

    ERR_OK
}

/// Execute an encrypted transfer between sender and receiver vaults.
///
/// The transfer is fully blind — the contract never sees plaintext balances.
/// Homomorphic operations are delegated to the host (WASM) or tfhe (native).
///
/// # Returns
///
/// - `ERR_OK` (0) on success (including insufficient-funds — blind execution)
/// - `ERR_INVALID_KEY` (4) if ServerKey not initialized (native only)
/// - `ERR_NOT_FOUND` (1) if sender or receiver vault not registered
/// - `ERR_DESER` (3) if any ciphertext is malformed
#[no_mangle]
pub extern "C" fn homomorphic_transfer(
    sender_id_ptr: *const u8,
    sender_id_len: usize,
    receiver_id_ptr: *const u8,
    receiver_id_len: usize,
    transfer_ct_ptr: *const u8,
    transfer_ct_len: usize,
) -> u32 {
    let sender_id_slice =
        unsafe { core::slice::from_raw_parts(sender_id_ptr, sender_id_len) };
    let receiver_id_slice =
        unsafe { core::slice::from_raw_parts(receiver_id_ptr, receiver_id_len) };
    let transfer_ct =
        unsafe { core::slice::from_raw_parts(transfer_ct_ptr, transfer_ct_len) };

    if sender_id_slice.len() != 32 || receiver_id_slice.len() != 32 {
        return ERR_DESER;
    }

    let mut sender_id = [0u8; 32];
    let mut receiver_id = [0u8; 32];
    sender_id.copy_from_slice(sender_id_slice);
    receiver_id.copy_from_slice(receiver_id_slice);

    // Find sender and receiver indices
    let indices_opt: Option<(usize, usize)> = STATE.with(|s| {
        let borrow = s.borrow();
        let state = borrow.as_ref()?;
        let si = state.balances.iter().position(|(id, _)| *id == sender_id)?;
        let ri = state.balances.iter().position(|(id, _)| *id == receiver_id)?;
        Some((si, ri))
    });

    let (sender_idx, receiver_idx) = match indices_opt {
        Some(pair) => pair,
        None => return ERR_NOT_FOUND,
    };

    // Extract ciphertext bytes
    let (sender_ct_bytes, receiver_ct_bytes) = STATE.with(|s| {
        let borrow = s.borrow();
        let state = borrow.as_ref().unwrap();
        (
            state.balances[sender_idx].1.clone(),
            state.balances[receiver_idx].1.clone(),
        )
    });

    // Perform homomorphic transfer
    #[cfg(target_arch = "wasm32")]
    let result = do_homomorphic_transfer(&sender_ct_bytes, &receiver_ct_bytes, transfer_ct);

    #[cfg(not(target_arch = "wasm32"))]
    let result = {
        let server_key_bytes_opt: Option<Vec<u8>> = STATE.with(|s| {
            s.borrow()
                .as_ref()
                .and_then(|st| st.server_key_bytes.clone())
        });
        let server_key_bytes = match server_key_bytes_opt {
            Some(b) => b,
            None => return ERR_INVALID_KEY,
        };
        do_homomorphic_transfer(&sender_ct_bytes, &receiver_ct_bytes, transfer_ct, &server_key_bytes)
    };

    match result {
        Some((new_sender_bytes, new_receiver_bytes)) => {
            with_state_mut(|state| {
                state.balances[sender_idx].1 = new_sender_bytes;
                state.balances[receiver_idx].1 = new_receiver_bytes;
            });
            ERR_OK
        }
        None => ERR_DESER,
    }
}

// ── State Persistence ─────────────────────────────────────────────────────────

thread_local! {
    static EXPORT_BUFFER: RefCell<Vec<u8>> = RefCell::new(Vec::new());
}

/// Internal: serialize vault state to bytes.
pub fn export_vault_state_inner() -> Vec<u8> {
    STATE.with(|s| {
        let borrow = s.borrow();
        match borrow.as_ref() {
            Some(state) => bincode::serialize(state).unwrap_or_default(),
            None => Vec::new(),
        }
    })
}

/// Get the length of the serialized vault state (call before `export_vault_state_ptr`).
#[no_mangle]
pub extern "C" fn export_vault_state_len() -> usize {
    let bytes = export_vault_state_inner();
    EXPORT_BUFFER.with(|b| {
        *b.borrow_mut() = bytes;
    });
    EXPORT_BUFFER.with(|b| b.borrow().len())
}

/// Get a pointer to the serialized vault state buffer (call after `export_vault_state_len`).
#[no_mangle]
#[allow(missing_docs)]
pub extern "C" fn export_vault_state_ptr() -> *const u8 {
    EXPORT_BUFFER.with(|b| b.borrow().as_ptr())
}

/// Deserialize vault state from HelixDB bytes.
///
/// # Returns
///
/// - `ERR_OK` (0) on success
/// - `ERR_DESER` (3) if deserialization fails
#[no_mangle]
pub extern "C" fn import_vault_state(state_bytes_ptr: *const u8, len: usize) -> u32 {
    let state_bytes = unsafe { core::slice::from_raw_parts(state_bytes_ptr, len) };
    let new_state: VaultState = match bincode::deserialize(state_bytes) {
        Ok(s) => s,
        Err(_) => return ERR_DESER,
    };
    STATE.with(|s| {
        *s.borrow_mut() = Some(new_state);
    });
    ERR_OK
}

// ── High-Level Rust API (for native tests and WASM feature exports) ───────────

/// High-level: initialize vault with server key bytes.
pub fn vault_init_from_bytes(server_key_bytes: &[u8]) -> u32 {
    init_vault(server_key_bytes.as_ptr(), server_key_bytes.len())
}

/// High-level: register a vault with an encrypted balance.
pub fn vault_register_from_bytes(vault_id: &[u8], initial_balance_ct: &[u8]) -> u32 {
    register_vault_ciphertext(
        vault_id.as_ptr(),
        vault_id.len(),
        initial_balance_ct.as_ptr(),
        initial_balance_ct.len(),
    )
}

/// High-level: execute a homomorphic transfer.
pub fn vault_transfer_from_bytes(
    sender_id: &[u8],
    receiver_id: &[u8],
    transfer_ct: &[u8],
) -> u32 {
    homomorphic_transfer(
        sender_id.as_ptr(),
        sender_id.len(),
        receiver_id.as_ptr(),
        receiver_id.len(),
        transfer_ct.as_ptr(),
        transfer_ct.len(),
    )
}

/// High-level: read a vault's current serialized ciphertext balance, if it's registered.
pub fn vault_get_balance(vault_id: &[u8]) -> Option<Vec<u8>> {
    STATE.with(|s| {
        let borrow = s.borrow();
        let state = borrow.as_ref()?;
        state
            .balances
            .iter()
            .find(|(id, _)| id.as_slice() == vault_id)
            .map(|(_, ct)| ct.clone())
    })
}

/// Register a vault with an encrypted balance, bound to a real `aethel-core`
/// PLP identity projection.
///
/// Unlike [`register_vault_ciphertext`], the vault ID is not caller-supplied:
/// it is derived server-side from `projection_bytes` via [`derive_vault_id`],
/// the same derivation the vault ID was always documented as using. That
/// closes the gap the plain registration path leaves open, where a caller
/// can supply any 32 bytes as a "vault ID" with nothing to check it actually
/// came from a projection. [`homomorphic_transfer_authenticated`] checks a
/// caller's proof against the projection stored here.
///
/// # Returns
///
/// - `Ok(vault_id)` on success
/// - `Err(ERR_DESER)` if `projection_bytes` does not decode as an
///   `aethel_core::EphemeralProjection`
pub fn register_vault_with_identity(
    projection_bytes: &[u8],
    initial_balance_ct: &[u8],
) -> Result<[u8; 32], u32> {
    if aethel_core::EphemeralProjection::from_bytes(projection_bytes).is_err() {
        return Err(ERR_DESER);
    }

    let vault_id = derive_vault_id(projection_bytes);

    with_state_mut(|state| {
        state.balances.push((vault_id, initial_balance_ct.to_vec()));
        state
            .identity_projections
            .push((vault_id, projection_bytes.to_vec()));
    });

    Ok(vault_id)
}

/// Execute an authenticated homomorphic transfer.
///
/// Identical to [`homomorphic_transfer`] (same blind, homomorphic-select
/// arithmetic — insufficient funds is still a silent no-op, not an error)
/// except that it first requires proof that the caller controls the sender
/// vault's identity:
///
/// 1. `sender_id` must have been registered via
///    [`register_vault_with_identity`], and `sender_projection` must be
///    exactly the projection it was registered with (re-checked by
///    recomputing its byte encoding, not merely trusting the caller's claim).
/// 2. `proof` must verify against `sender_projection` via
///    `aethel_core::plp::Verifier::verify`.
///
/// Only once both hold does this fall through to the same transfer logic
/// [`homomorphic_transfer`] uses.
///
/// See the module-level "Identity Coupling" docs for why this takes
/// `sender_projection`/`proof` as native `aethel-core` values rather than raw
/// bytes: `ZkIdentityProof` has no public byte constructor, so this entry
/// point is reachable only by a caller linking `aethel-vault` and
/// `aethel-core` together in the same Rust binary, not through the
/// `extern "C"`/wasm-bindgen boundary this module's other exports use.
///
/// # Returns
///
/// - `ERR_OK` (0) on success (including insufficient-funds — blind execution)
/// - `ERR_UNAUTHORIZED` (5) if `sender_id` has no identity binding, the
///   binding doesn't match `sender_projection`, or `proof` fails verification
/// - `ERR_NOT_FOUND` / `ERR_INVALID_KEY` / `ERR_DESER` as in
///   [`homomorphic_transfer`]
pub fn homomorphic_transfer_authenticated(
    sender_id: &[u8; 32],
    receiver_id: &[u8; 32],
    transfer_ct: &[u8],
    sender_projection: &aethel_core::EphemeralProjection,
    proof: &aethel_core::ZkIdentityProof,
) -> u32 {
    let bound_projection_bytes: Option<Vec<u8>> = STATE.with(|s| {
        let borrow = s.borrow();
        borrow.as_ref().and_then(|state| {
            state
                .identity_projections
                .iter()
                .find(|(id, _)| id == sender_id)
                .map(|(_, bytes)| bytes.clone())
        })
    });

    let bound_projection_bytes = match bound_projection_bytes {
        Some(bytes) => bytes,
        None => return ERR_UNAUTHORIZED,
    };

    if bound_projection_bytes != sender_projection.to_bytes() {
        return ERR_UNAUTHORIZED;
    }

    if !aethel_core::Verifier::verify(sender_projection, proof) {
        return ERR_UNAUTHORIZED;
    }

    vault_transfer_from_bytes(sender_id, receiver_id, transfer_ct)
}

/// High-level: export vault state as bytes.
pub fn vault_export_state() -> Vec<u8> {
    export_vault_state_inner()
}

/// High-level: import vault state from bytes.
pub fn vault_import_state(state_bytes: &[u8]) -> u32 {
    import_vault_state(state_bytes.as_ptr(), state_bytes.len())
}

// ── WASM-bindgen Exports ──────────────────────────────────────────────────────

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// Derive a vault ID from PLP projection bytes (WASM export).
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn derive_vault_id_from_projection(projection_bytes: &[u8]) -> Vec<u8> {
    derive_vault_id(projection_bytes).to_vec()
}

/// Initialize vault with TFHE ServerKey (WASM export).
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_vault_init(server_key_bytes: &[u8]) -> u32 {
    vault_init_from_bytes(server_key_bytes)
}

/// Register a vault with an encrypted balance (WASM export).
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_vault_register(vault_id: &[u8], initial_balance_ct: &[u8]) -> u32 {
    vault_register_from_bytes(vault_id, initial_balance_ct)
}

/// Execute a homomorphic transfer (WASM export).
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_vault_transfer(sender_id: &[u8], receiver_id: &[u8], transfer_ct: &[u8]) -> u32 {
    vault_transfer_from_bytes(sender_id, receiver_id, transfer_ct)
}

/// Register a vault bound to an `aethel-core` PLP identity projection (WASM export).
///
/// Returns the derived vault ID on success, or an empty `Vec` if
/// `projection_bytes` does not decode as an `EphemeralProjection`.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_vault_register_with_identity(
    projection_bytes: &[u8],
    initial_balance_ct: &[u8],
) -> Vec<u8> {
    register_vault_with_identity(projection_bytes, initial_balance_ct)
        .map(|id| id.to_vec())
        .unwrap_or_default()
}

/// Export vault state as bytes (WASM export).
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_vault_export_state() -> Vec<u8> {
    vault_export_state()
}

/// Import vault state from bytes (WASM export).
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_vault_import_state(state_bytes: &[u8]) -> u32 {
    vault_import_state(state_bytes)
}
