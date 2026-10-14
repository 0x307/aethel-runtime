//! HTSS social recovery: one file per share, root kept apart.
//!
//! # Why one file per share
//!
//! `aethel-core` offers `split_key_material_bytes`, which returns every share
//! in a single blob. Convenient, and **useless for social recovery**: whoever
//! holds that blob holds the secret, so handing it to five people is handing
//! the identity to five people.
//!
//! So this uses the lower-level `split_key_material` and writes each share
//! separately, because the point of splitting is that the pieces live apart.
//!
//! # Why the root is not in the shares
//!
//! `aethel-core`'s own documentation says a root travelling with the shares
//! "authenticates shares to each other but not to an attacker who controls the
//! whole blob", and that a caller needing that guarantee "keeps the root out
//! of band".
//!
//! So `combine` requires it as an argument. It is recorded in the identity
//! file and printed at creation, and a holder who may lose that file too
//! should write it down somewhere else.
//!
//! # The constraint that shapes all of this
//!
//! Shares can only be made **when the identity is created**. `Identity`'s
//! entropy is private, and `import_sealed` zeroizes it after deriving the
//! identity, so there is no way to split an identity that already exists.
//!
//! A holder who seals an identity and decides later to arrange recovery
//! cannot. They would have to generate a new identity and re-enrol everywhere
//! the old one is known. That is why `identity new` arranges recovery by
//! default and opting out takes a flag.

use std::path::Path;
use zeroize::Zeroizing;

use aethel_core::htss::{HtssShare, SecretSharer};
use serde::{Deserialize, Serialize};

use crate::CliError;

/// One share, as written to disk and handed to one person.
///
/// Carries no root, by design. See the module docs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareFile {
    pub version: u8,
    /// Which relying party the identity this recovers belongs to. Not secret,
    /// and a holder with five share files from three identities needs to know
    /// which is which.
    pub audience: String,
    pub index: u8,
    pub value: String,
    pub path: String,
}

/// Split `entropy` into shares. The threshold is the scheme's own 3-of-5.
pub fn split(entropy: &[u8], audience: &str) -> Result<(Vec<ShareFile>, String), CliError> {
    // Fresh randomness for the sharing. Reconstruction does not take it —
    // it feeds the split's own polynomial sampling — so it is not stored.
    use rand::RngCore;
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let (shares, root) = SecretSharer::split_key_material(entropy, &nonce)
        .map_err(|_| CliError::Crypto("htss split"))?;

    let files = shares
        .iter()
        .map(|s| ShareFile {
            version: 1,
            audience: audience.to_string(),
            index: s.index,
            value: hex::encode(&s.value),
            path: hex::encode(&s.path),
        })
        .collect();

    Ok((files, hex::encode(root)))
}

/// Reconstruct entropy from at least the threshold number of shares.
pub fn combine(files: &[ShareFile], root_hex: &str) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let root_bytes = hex::decode(root_hex).map_err(|_| CliError::Corrupt("root"))?;
    let root: [u8; 32] = root_bytes
        .try_into()
        .map_err(|_| CliError::Corrupt("root is not 32 bytes"))?;

    let shares: Vec<HtssShare> = files
        .iter()
        .map(|f| {
            Ok(HtssShare {
                index: f.index,
                value: hex::decode(&f.value).map_err(|_| CliError::Corrupt("share value"))?,
                path: hex::decode(&f.path).map_err(|_| CliError::Corrupt("share path"))?,
            })
        })
        .collect::<Result<_, CliError>>()?;

    SecretSharer::reconstruct_key_material(&shares, &root)
        .map(Zeroizing::new)
        .map_err(|e| match e {
            aethel_core::IdentityError::ThresholdNotMet => CliError::NotEnoughShares,
            _ => CliError::Crypto("htss reconstruct"),
        })
}

pub fn read_share(path: &Path) -> Result<ShareFile, CliError> {
    let text = std::fs::read_to_string(path).map_err(|e| CliError::Io(e.to_string()))?;
    serde_json::from_str(&text).map_err(|_| CliError::Corrupt("share file"))
}

pub fn write_share(share: &ShareFile, path: &Path) -> Result<(), CliError> {
    let text = serde_json::to_string_pretty(share).map_err(|_| CliError::Crypto("encode"))?;
    std::fs::write(path, text).map_err(|e| CliError::Io(e.to_string()))
}
