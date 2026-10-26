//! Byte fields as base64url text on the wire.
//!
//! serde's default for `Vec<u8>` is a JSON array of numbers, which makes a
//! login proof (a 1,952-byte key and a 3,309-byte signature) about 19 KB of
//! JSON. The first consumer pastes proofs into a browser, and the browser
//! client already speaks base64url, so the statement types serialise their
//! bytes that way: roughly a third of the size, and text a person can copy.
//!
//! **Decoding is strict: one spelling per value.** Only canonical base64url is
//! accepted: no padding, and no set bits after the last byte. A verifier stores
//! and compares keys, and signatures cover the *decoded* bytes, so a decoder
//! that accepted several spellings of one key would let a revoked key come back
//! under another spelling, past any store that compares text. (Found by the
//! Aethel Verify review, 2026-10-14.) The old number-array shape is behind the
//! `legacy-number-arrays` feature, off by default; arrays have one spelling per
//! byte, so they don't reopen the problem, but nothing needs them by default.
//! Only the JSON shape is affected; the signed bytes (`signing_input`) never
//! depended on it.
//!
//! Hand-rolled rather than a dependency: the default build is what a verifier
//! hosts, and twenty lines of encoding do not justify growing it.

use core::fmt;

use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserializer, Serializer};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        let symbols = chunk.len() + 1;
        for i in 0..symbols {
            out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

/// Strict: returns bytes only for the canonical spelling, the one `encode`
/// produces. Padding, non-zero trailing bits and anything else are refused.
fn decode(text: &str) -> Option<Vec<u8>> {
    let out = decode_any(text)?;
    (encode(&out) == text).then_some(out)
}

fn decode_any(text: &str) -> Option<Vec<u8>> {
    let value = |c: u8| ALPHABET.iter().position(|&a| a == c).map(|p| p as u32);
    let text = text.as_bytes();
    if text.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    for chunk in text.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= value(c)? << (18 - 6 * i);
        }
        for i in 0..chunk.len() - 1 {
            out.push((n >> (16 - 8 * i)) as u8);
        }
    }
    Some(out)
}

/// Accepts base64url text or a sequence of byte values.
struct BytesVisitor;

impl<'de> Visitor<'de> for BytesVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("canonical base64url text (no padding, zero trailing bits)")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<u8>, E> {
        decode(v).ok_or_else(|| E::custom("not canonical base64url"))
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
        Ok(v.to_vec())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
        if !cfg!(feature = "legacy-number-arrays") {
            return Err(de::Error::custom(
                "byte arrays are not accepted; use base64url (or enable legacy-number-arrays)",
            ));
        }
        let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
        while let Some(b) = seq.next_element::<u8>()? {
            out.push(b);
        }
        Ok(out)
    }
}

fn to_array<E: de::Error>(bytes: Vec<u8>) -> Result<[u8; 32], E> {
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| E::invalid_length(v.len(), &"32 bytes"))
}

/// `Vec<u8>`.
pub mod bytes {
    use super::*;

    pub fn serialize<S: Serializer>(value: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&encode(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        d.deserialize_any(BytesVisitor)
    }
}

/// `[u8; 32]`.
pub mod array32 {
    use super::*;

    pub fn serialize<S: Serializer>(value: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&encode(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        to_array(d.deserialize_any(BytesVisitor)?)
    }
}

/// `Option<[u8; 32]>`.
pub mod opt_array32 {
    use super::*;
    use serde::Deserialize;

    pub fn serialize<S: Serializer>(value: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match value {
            Some(v) => s.serialize_some(&encode(v)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        #[derive(Deserialize)]
        struct Wrapped(#[serde(with = "super::array32")] [u8; 32]);
        Ok(Option::<Wrapped>::deserialize(d)?.map(|w| w.0))
    }
}

/// `Vec<Vec<u8>>`.
pub mod vec_bytes {
    use super::*;
    use serde::ser::SerializeSeq;
    use serde::Deserialize;

    pub fn serialize<S: Serializer>(value: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(value.len()))?;
        for item in value {
            seq.serialize_element(&encode(item))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        #[derive(Deserialize)]
        struct Wrapped(#[serde(with = "super::bytes")] Vec<u8>);
        Ok(Vec::<Wrapped>::deserialize(d)?
            .into_iter()
            .map(|w| w.0)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_length() {
        for len in 0..70 {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(
                decode(&encode(&bytes)).as_deref(),
                Some(bytes.as_slice()),
                "length {len}"
            );
        }
    }

    #[test]
    fn matches_the_standard_alphabet_without_padding() {
        assert_eq!(encode(b"\xfb\xff"), "-_8");
        assert_eq!(encode(b"hello"), "aGVsbG8");
        assert!(decode("a").is_none() && decode("a*bc").is_none());
    }

    /// One spelling per value: anything but the canonical form is refused.
    #[test]
    fn refuses_every_non_canonical_spelling() {
        // Control: the canonical spelling reads.
        assert_eq!(decode("aGVsbG8").unwrap(), b"hello");
        // Padding.
        assert!(decode("aGVsbG8=").is_none());
        assert!(decode("aGVsbG8==").is_none());
        // Non-zero trailing bits: "aGVsbG8" ends in '8' (index 60); '9' (61)
        // sets a bit the 5-byte value doesn't use.
        assert!(
            decode_any("aGVsbG9").is_some(),
            "the lenient decoder would accept it"
        );
        assert!(decode("aGVsbG9").is_none());
        // A two-byte tail: "-_8" is canonical, "-_9" sets a trailing bit.
        assert!(decode("-_8").is_some() && decode("-_9").is_none());
    }

    /// Every length, every possible trailing-bit pattern: only one decodes.
    #[test]
    fn exactly_one_spelling_per_value_at_every_length() {
        for len in 1..40 {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 53 + 7) as u8).collect();
            let canonical = encode(&bytes);
            let last = canonical.as_bytes()[canonical.len() - 1];
            let idx = ALPHABET.iter().position(|&a| a == last).unwrap();
            let mut accepted = 0;
            for (alt, &ch) in ALPHABET.iter().enumerate() {
                // Same high bits as the canonical last character, any low bits.
                let unused = match len % 3 {
                    1 => 4,
                    2 => 2,
                    _ => 0,
                };
                if alt >> unused != idx >> unused {
                    continue;
                }
                let mut s = canonical.clone();
                s.pop();
                s.push(ch as char);
                if let Some(d) = decode(&s) {
                    assert_eq!(d, bytes);
                    accepted += 1;
                }
            }
            assert_eq!(accepted, 1, "length {len}");
        }
    }
}
