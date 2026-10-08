//! The on-disk identity, and the audience it is bound to.
//!
//! # One file, one relying party
//!
//! The audience lives **in the file**, and every command reads it from there
//! rather than taking it as an argument. Acting at a second relying party
//! means making a second identity, because there is no flag that would let one
//! file serve two.
//!
//! That is the whole mechanism behind the per-relying-party rule. The crate
//! can document it and the `Holder` type can encourage it; only the tool a
//! person actually runs can make the wrong thing impossible to type.

use zeroize::Zeroizing;
use std::path::Path;

use aethel_core::signing::Identity;
use argon2::Argon2;
use serde::{Deserialize, Serialize};

use crate::CliError;

/// Bytes of key material `export_sealed` wants. Its own minimum is 32.
const SEAL_KEY_LEN: usize = 32;

/// Argon2id parameters.
///
/// The `argon2` crate's defaults, which follow the OWASP recommendation:
/// 19 MiB, two passes, one lane. Recorded in the file rather than assumed, so
/// a file written today still opens after the defaults are raised — a holder
/// whose identity became unopenable because the tool got more cautious would
/// have lost it as surely as by forgetting the passphrase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub salt: String,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    fn fresh(salt: [u8; 16]) -> Self {
        let d = argon2::Params::DEFAULT_M_COST;
        KdfParams {
            salt: hex::encode(salt),
            m_cost: d,
            t_cost: argon2::Params::DEFAULT_T_COST,
            p_cost: argon2::Params::DEFAULT_P_COST,
        }
    }

    fn derive(&self, passphrase: &[u8]) -> Result<Zeroizing<[u8; SEAL_KEY_LEN]>, CliError> {
        let salt = hex::decode(&self.salt).map_err(|_| CliError::Corrupt("kdf salt"))?;
        let params = argon2::Params::new(self.m_cost, self.t_cost, self.p_cost, Some(SEAL_KEY_LEN))
            .map_err(|_| CliError::Corrupt("kdf parameters"))?;
        let argon = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        let mut key = Zeroizing::new([0u8; SEAL_KEY_LEN]);
        argon
            .hash_password_into(passphrase, &salt, &mut key[..])
            .map_err(|_| CliError::Corrupt("kdf"))?;
        Ok(key)
    }
}

/// A sealed identity, bound to one audience.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityFile {
    pub version: u8,
    /// The relying party this identity acts at, and only this one.
    pub audience: String,
    /// Published so a holder can read it off without unsealing, and so the
    /// relying party can be told which key to expect.
    pub public_key: String,
    /// `Identity::export_sealed` output. Contains the entropy, encrypted.
    pub sealed: String,
    pub kdf: KdfParams,
    /// Set when recovery shares were produced at creation. Records only
    /// *that* they exist and the root needed to verify them — never a share.
    pub recovery: Option<RecoveryRecord>,
}

/// What the holder needs to know about their own recovery arrangement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryRecord {
    /// The Merkle root of the share set.
    ///
    /// Kept here **and** printed at creation, because reconstruction needs it
    /// and the shares deliberately do not carry it. `aethel-core` is explicit
    /// that a root travelling with the shares "authenticates shares to each
    /// other but not to an attacker who controls the whole blob".
    ///
    /// Storing it beside the sealed identity is not circular: someone
    /// recovering has lost the *passphrase* or the key, not necessarily this
    /// file. A holder who may lose the file too must keep the root elsewhere,
    /// which is why creation prints it.
    pub root: String,
    pub shares_issued: u8,
    pub threshold: u8,
}

impl IdentityFile {
    /// Generate a fresh identity for `audience`, sealed under `passphrase`.
    ///
    /// Returns the file and the raw entropy, because the caller may want to
    /// split it for recovery. **That is the only moment it can**: `entropy` is
    /// a private field on `Identity` with no accessor, and `import_sealed`
    /// zeroizes it after deriving the identity. Once this function returns and
    /// the entropy is dropped, no recovery arrangement can be made for this
    /// identity ever again, short of regenerating it and re-enrolling
    /// everywhere it is known.
    pub fn create(
        audience: &str,
        passphrase: &[u8],
    ) -> Result<(Self, Zeroizing<[u8; 32]>), CliError> {
        use rand::RngCore;

        let mut entropy = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut entropy[..]);
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);

        let identity = Identity::generate(&entropy[..]).map_err(|_| CliError::Crypto("generate"))?;
        let kdf = KdfParams::fresh(salt);
        let key = kdf.derive(passphrase)?;
        let sealed = identity
            .export_sealed(&key[..])
            .map_err(|_| CliError::Crypto("seal"))?;

        Ok((
            IdentityFile {
                version: 1,
                audience: audience.to_string(),
                public_key: hex::encode(identity.public_key()),
                sealed: hex::encode(sealed),
                kdf,
                recovery: None,
            },
            entropy,
        ))
    }

    /// Rebuild a file from recovered entropy.
    ///
    /// Carries no recovery record: the shares that produced this entropy are
    /// still valid, so the holder already has an arrangement, and writing a
    /// fresh root here would claim a second one that does not exist.
    pub fn from_entropy(
        audience: &str,
        entropy: &[u8],
        passphrase: &[u8],
    ) -> Result<Self, CliError> {
        use rand::RngCore;

        let identity = Identity::generate(entropy).map_err(|_| CliError::Crypto("generate"))?;
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let kdf = KdfParams::fresh(salt);
        let key = kdf.derive(passphrase)?;
        let sealed = identity
            .export_sealed(&key[..])
            .map_err(|_| CliError::Crypto("seal"))?;

        Ok(IdentityFile {
            version: 1,
            audience: audience.to_string(),
            public_key: hex::encode(identity.public_key()),
            sealed: hex::encode(sealed),
            kdf,
            recovery: None,
        })
    }

    /// Rebuild the identity from a passphrase.
    pub fn open(&self, passphrase: &[u8]) -> Result<Identity, CliError> {
        if self.version != 1 {
            return Err(CliError::Corrupt("unsupported file version"));
        }
        let key = self.kdf.derive(passphrase)?;
        let sealed = hex::decode(&self.sealed).map_err(|_| CliError::Corrupt("sealed blob"))?;

        let identity =
            Identity::import_sealed(&sealed, &key[..]).map_err(|_| CliError::WrongPassphrase)?;

        // The file's own claim about which key it holds must match what came
        // out. A mismatch means the file was edited, and signing with a key
        // the holder does not expect is worse than refusing.
        if hex::encode(identity.public_key()) != self.public_key {
            return Err(CliError::Corrupt("public key does not match the sealed identity"));
        }

        Ok(identity)
    }

    pub fn read(path: &Path) -> Result<Self, CliError> {
        let text = std::fs::read_to_string(path).map_err(|e| CliError::Io(e.to_string()))?;
        serde_json::from_str(&text).map_err(|_| CliError::Corrupt("identity file"))
    }

    pub fn write(&self, path: &Path) -> Result<(), CliError> {
        let text = serde_json::to_string_pretty(self).map_err(|_| CliError::Crypto("encode"))?;
        std::fs::write(path, text).map_err(|e| CliError::Io(e.to_string()))
    }

    /// Short, comparable name for this identity's key.
    pub fn fingerprint(&self) -> Result<String, CliError> {
        let key = hex::decode(&self.public_key).map_err(|_| CliError::Corrupt("public key"))?;
        Ok(aethel_auth::key_fingerprint(&key))
    }

    pub fn audience_bytes(&self) -> Vec<u8> {
        self.audience.as_bytes().to_vec()
    }
}
