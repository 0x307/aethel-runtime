//! Canonical binary encoding of the signed statements.
//!
//! [`Delegation`], [`LoginProof`], [`Approval`] and [`DelegationRevocation`] each have
//! `to_bytes` and `from_bytes`. JSON stays supported; this is the compact
//! form for a transport that carries bytes, and it has exactly one encoding
//! per value.
//!
//! # Layout
//!
//! The same for every type:
//!
//! ```text
//! type_tag   u8        0x01 Delegation, 0x02 LoginProof, 0x03 Approval,
//!                      0x04 DelegationRevocation
//! version    u8        0x01 (Delegation: 0x02 when it names approvers)
//! signer     u32 BE length ‖ bytes    the key the signature verifies under
//!                                     (Delegation: principal_key;
//!                                      LoginProof: public_key;
//!                                      Approval: approver_key;
//!                                      DelegationRevocation: principal_key)
//! signed     u32 BE length ‖ bytes    exactly `signing_input()`
//! signature  u32 BE length ‖ bytes
//! ```
//!
//! Version `0x02` is a [`Delegation`] that names approvers
//! ([`Bounds::approvers`]): its signed block is the version 1 bytes, then a
//! `u32` BE count and each approver length-prefixed. Content alone picks the
//! version, so the decoder refuses a header that disagrees with it: a
//! version 1 header on a delegation with approvers (bytes left in the signed
//! block) and a version 2 header with no approvers (not canonical) are both
//! [`AuthError::Malformed`]. Every other type reads and writes version 1
//! only, and any other tag or version is refused.
//!
//! The `signed` block is the type's own `signing_input()`, byte for byte, so
//! the bytes a signature covers are visible inside the encoding and nothing
//! about them changed for 0.4. `from_bytes` parses that block back into
//! fields using the same order and widths `signing_input()` writes.
//!
//! # Decoding is strict
//!
//! Every defect is [`AuthError::Malformed`]: trailing bytes after the
//! signature or inside the signed block, an unknown tag or version, a length
//! prefix past the end of the input, a nonce, digest or delegation id whose
//! length is not 32, a session commitment whose length is not 0 or 32, and an
//! optional-field flag other than 0 or 1.
//!
//! For any accepted input `b`, `to_bytes(from_bytes(b)) == b`, and for any
//! value `x`, `from_bytes(to_bytes(x)) == x`.
//!
//! Nothing a length prefix says is trusted for allocation: a prefix larger
//! than what remains of the input is refused before any buffer is made, and
//! a delegation's action count is capped the same way.
//!
//! **A signature is not checked here.** `from_bytes` checks structure only.
//! Verification stays in `verify_delegation`, `verify_login`,
//! `verify_login_for_request` and `check_approval`, and a value read with
//! `from_bytes` must go through them like any other.

use crate::approval::Approval;
use crate::delegation::{Bounds, Delegation};
use crate::error::AuthError;
use crate::proof::{push_len_prefixed, LoginProof};
use crate::statements::DelegationRevocation;

/// Type tag of an encoded [`Delegation`].
pub const TAG_DELEGATION: u8 = 0x01;
/// Type tag of an encoded [`LoginProof`].
pub const TAG_LOGIN_PROOF: u8 = 0x02;
/// Type tag of an encoded [`Approval`].
pub const TAG_APPROVAL: u8 = 0x03;
/// Type tag of an encoded [`DelegationRevocation`].
pub const TAG_DELEGATION_REVOCATION: u8 = 0x04;
/// The wire version of every statement, and of a [`Delegation`] with no
/// approvers.
pub const WIRE_VERSION_1: u8 = 0x01;
/// The wire version of a [`Delegation`] that names approvers.
pub const WIRE_VERSION_2: u8 = 0x02;

/// A cursor over untrusted bytes. Every read is bounds-checked first.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Reader { rest: bytes }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], AuthError> {
        if n > self.rest.len() {
            return Err(AuthError::Malformed);
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, AuthError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, AuthError> {
        let mut b = [0u8; 4];
        b.copy_from_slice(self.take(4)?);
        Ok(u32::from_be_bytes(b))
    }

    fn u64(&mut self) -> Result<u64, AuthError> {
        let mut b = [0u8; 8];
        b.copy_from_slice(self.take(8)?);
        Ok(u64::from_be_bytes(b))
    }

    fn u128(&mut self) -> Result<u128, AuthError> {
        let mut b = [0u8; 16];
        b.copy_from_slice(self.take(16)?);
        Ok(u128::from_be_bytes(b))
    }

    /// A `u32` BE length, then that many bytes. The length is checked against
    /// what is left before anything is returned or allocated.
    fn lp(&mut self) -> Result<&'a [u8], AuthError> {
        let n = self.u32()? as usize;
        self.take(n)
    }

    /// A length-prefixed field that must be exactly 32 bytes.
    fn lp32(&mut self) -> Result<[u8; 32], AuthError> {
        let mut out = [0u8; 32];
        let b = self.lp()?;
        if b.len() != 32 {
            return Err(AuthError::Malformed);
        }
        out.copy_from_slice(b);
        Ok(out)
    }

    /// A flag byte that must be 0 or 1.
    fn flag(&mut self) -> Result<bool, AuthError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(AuthError::Malformed),
        }
    }

    fn opt_u128(&mut self) -> Result<Option<u128>, AuthError> {
        if self.flag()? {
            Ok(Some(self.u128()?))
        } else {
            Ok(None)
        }
    }

    fn opt_u64(&mut self) -> Result<Option<u64>, AuthError> {
        if self.flag()? {
            Ok(Some(self.u64()?))
        } else {
            Ok(None)
        }
    }

    fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    fn finish(self) -> Result<(), AuthError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(AuthError::Malformed)
        }
    }
}

/// The three outer fields, after the tag and version are checked.
struct Envelope<'a> {
    version: u8,
    signer: &'a [u8],
    signed: &'a [u8],
    signature: &'a [u8],
}

/// Read the outer fields. `max_version` is the highest version this type
/// has: 1 for every type but [`Delegation`], which has 2.
fn read_envelope(bytes: &[u8], tag: u8, max_version: u8) -> Result<Envelope<'_>, AuthError> {
    let mut r = Reader::new(bytes);
    if r.u8()? != tag {
        return Err(AuthError::Malformed);
    }
    let version = r.u8()?;
    if version < WIRE_VERSION_1 || version > max_version {
        return Err(AuthError::Malformed);
    }
    let signer = r.lp()?;
    let signed = r.lp()?;
    let signature = r.lp()?;
    r.finish()?;
    Ok(Envelope {
        version,
        signer,
        signed,
        signature,
    })
}

fn write_envelope(tag: u8, version: u8, signer: &[u8], signed: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 12 + signer.len() + signed.len() + signature.len());
    out.push(tag);
    out.push(version);
    push_len_prefixed(&mut out, signer);
    push_len_prefixed(&mut out, signed);
    push_len_prefixed(&mut out, signature);
    out
}

impl Delegation {
    /// The canonical binary encoding: tag `0x01`, version `0x01` (`0x02`
    /// when the delegation names approvers), the principal key,
    /// [`Delegation::signing_input`] and the signature, each length-prefixed.
    /// See [`crate::wire`] for the layout.
    pub fn to_bytes(&self) -> Vec<u8> {
        write_envelope(
            TAG_DELEGATION,
            if self.is_v2() {
                WIRE_VERSION_2
            } else {
                WIRE_VERSION_1
            },
            &self.principal_key,
            &self.signing_input(),
            &self.signature,
        )
    }

    /// Read a delegation from its canonical binary encoding.
    ///
    /// Returns [`AuthError::Malformed`] for any defect; see [`crate::wire`]
    /// for the list. **This checks structure only, never the signature.**
    /// Pass the result to [`crate::verify_delegation`] or
    /// [`crate::authorise`] before relying on it. The approver limits
    /// ([`Bounds::approvers`]) are `verify_delegation`'s to check, not this
    /// function's; only the structure and the version/content match are.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AuthError> {
        let env = read_envelope(bytes, TAG_DELEGATION, WIRE_VERSION_2)?;
        let mut s = Reader::new(env.signed);
        let delegate_key = s.lp()?.to_vec();
        let audience = s.lp()?.to_vec();
        let not_before = s.u64()?;
        let expires_at = s.u64()?;

        // Each action needs at least its 4-byte length, so a count larger
        // than that can never be satisfied. Refusing it here keeps the
        // allocation below proportional to the input, not to a claimed count.
        let count = s.u32()? as usize;
        if count > s.rest.len() / 4 {
            return Err(AuthError::Malformed);
        }
        let mut actions = Vec::with_capacity(count);
        for _ in 0..count {
            actions.push(s.lp()?.to_vec());
        }

        let max_per_invocation = s.opt_u128()?;
        let max_total = s.opt_u128()?;
        let approval_required_above = s.opt_u128()?;
        let window_secs = s.opt_u64()?;

        // Version 2 continues with the approvers; version 1 ends here, so
        // approvers under a version 1 header are bytes left in the block.
        // The same size argument as the actions bounds the allocation.
        let mut approvers = Vec::new();
        if env.version == WIRE_VERSION_2 {
            let count = s.u32()? as usize;
            if count > s.rest.len() / 4 {
                return Err(AuthError::Malformed);
            }
            approvers.reserve(count);
            for _ in 0..count {
                approvers.push(s.lp()?.to_vec());
            }
            // Content picks the version: version 2 with no approvers would be
            // a second encoding of a version 1 delegation.
            if approvers.is_empty() {
                return Err(AuthError::Malformed);
            }
        }
        s.finish()?;

        Ok(Delegation {
            principal_key: env.signer.to_vec(),
            delegate_key,
            audience,
            bounds: Bounds {
                actions,
                max_per_invocation,
                max_total,
                window_secs,
                approval_required_above,
                approvers,
            },
            not_before,
            expires_at,
            signature: env.signature.to_vec(),
        })
    }
}

impl LoginProof {
    /// The canonical binary encoding: tag `0x02`, version `0x01`, the public
    /// key, [`LoginProof::signing_input`] and the signature, each
    /// length-prefixed. See [`crate::wire`] for the layout.
    pub fn to_bytes(&self) -> Vec<u8> {
        write_envelope(
            TAG_LOGIN_PROOF,
            WIRE_VERSION_1,
            &self.public_key,
            &self.signing_input(),
            &self.signature,
        )
    }

    /// Read a login proof from its canonical binary encoding.
    ///
    /// Returns [`AuthError::Malformed`] for any defect; see [`crate::wire`]
    /// for the list. The request digest is present if and only if bytes
    /// remain in the signed block after the session commitment, and then it
    /// must be a length-prefixed 32 bytes. **This checks structure only,
    /// never the signature.** Pass the result to [`crate::verify_login`] or
    /// [`crate::verify_login_for_request`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AuthError> {
        let env = read_envelope(bytes, TAG_LOGIN_PROOF, WIRE_VERSION_1)?;
        let mut s = Reader::new(env.signed);
        let audience = s.lp()?.to_vec();
        let issued_at = s.u64()?;
        let expires_at = s.u64()?;
        let nonce = s.lp32()?;

        let commitment = s.lp()?;
        let session_commitment = match commitment.len() {
            0 => None,
            32 => {
                let mut c = [0u8; 32];
                c.copy_from_slice(commitment);
                Some(c)
            }
            _ => return Err(AuthError::Malformed),
        };

        let request_digest = if s.is_empty() {
            None
        } else {
            Some(s.lp32()?)
        };
        s.finish()?;

        Ok(LoginProof {
            public_key: env.signer.to_vec(),
            audience,
            nonce,
            issued_at,
            expires_at,
            session_commitment,
            request_digest,
            signature: env.signature.to_vec(),
        })
    }
}

impl Approval {
    /// The canonical binary encoding: tag `0x03`, version `0x01`, the
    /// approver key, [`Approval::signing_input`] and the signature, each
    /// length-prefixed. See [`crate::wire`] for the layout.
    pub fn to_bytes(&self) -> Vec<u8> {
        write_envelope(
            TAG_APPROVAL,
            WIRE_VERSION_1,
            &self.approver_key,
            &self.signing_input(),
            &self.signature,
        )
    }

    /// Read an approval from its canonical binary encoding.
    ///
    /// Returns [`AuthError::Malformed`] for any defect; see [`crate::wire`]
    /// for the list. **This checks structure only, never the signature.**
    /// Pass the result to [`crate::check_approval`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AuthError> {
        let env = read_envelope(bytes, TAG_APPROVAL, WIRE_VERSION_1)?;
        let mut s = Reader::new(env.signed);
        let audience = s.lp()?.to_vec();
        let issued_at = s.u64()?;
        let expires_at = s.u64()?;
        let nonce = s.lp32()?;
        let delegation_id = s.lp32()?;
        let request_digest = s.lp32()?;
        let action = s.lp()?.to_vec();
        let amount = s.u128()?;
        s.finish()?;

        Ok(Approval {
            approver_key: env.signer.to_vec(),
            audience,
            delegation_id,
            request_digest,
            action,
            amount,
            nonce,
            issued_at,
            expires_at,
            signature: env.signature.to_vec(),
        })
    }
}

impl DelegationRevocation {
    /// The canonical binary encoding: tag `0x04`, version `0x01`, the
    /// principal key, [`DelegationRevocation::signing_input`] and the
    /// signature, each length-prefixed. See [`crate::wire`] for the layout.
    pub fn to_bytes(&self) -> Vec<u8> {
        write_envelope(
            TAG_DELEGATION_REVOCATION,
            WIRE_VERSION_1,
            &self.principal_key,
            &self.signing_input(),
            &self.signature,
        )
    }

    /// Read a delegation revocation from its canonical binary encoding.
    ///
    /// Returns [`AuthError::Malformed`] for any defect; see [`crate::wire`]
    /// for the list. **This checks structure only, never the signature.**
    /// Pass the result to [`crate::verify_delegation_revocation`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AuthError> {
        let env = read_envelope(bytes, TAG_DELEGATION_REVOCATION, WIRE_VERSION_1)?;
        let mut s = Reader::new(env.signed);
        let audience = s.lp()?.to_vec();
        let delegation_id = s.lp32()?;
        let issued_at = s.u64()?;
        s.finish()?;

        Ok(DelegationRevocation {
            principal_key: env.signer.to_vec(),
            audience,
            delegation_id,
            issued_at,
            signature: env.signature.to_vec(),
        })
    }
}
