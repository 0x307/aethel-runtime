//! Values built from fixed seeds, shared by `wire_binary.rs` and the
//! generator in `gen_vectors.rs`, so the committed vectors and the test that
//! checks them cannot describe different values.

#![allow(dead_code)]

use aethel_auth::{Approval, Bounds, Delegation, Holder, LoginProof};
use aethel_core::signing::Identity;

pub const AUDIENCE: &[u8] = b"https://pay.example.com";

pub fn identity(seed: u8) -> Identity {
    Identity::generate(&[seed; 32]).expect("32 bytes of entropy")
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

pub enum Value {
    Delegation(Delegation),
    Login(LoginProof),
    Approval(Approval),
}

impl Value {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Value::Delegation(v) => v.to_bytes(),
            Value::Login(v) => v.to_bytes(),
            Value::Approval(v) => v.to_bytes(),
        }
    }

    /// Decode `bytes` as this value's type and compare with `self`.
    pub fn decodes_from(&self, bytes: &[u8]) -> bool {
        match self {
            Value::Delegation(v) => Delegation::from_bytes(bytes).as_ref() == Ok(v),
            Value::Login(v) => LoginProof::from_bytes(bytes).as_ref() == Ok(v),
            Value::Approval(v) => Approval::from_bytes(bytes).as_ref() == Ok(v),
        }
    }
}

/// Two values per type: one minimal, one with every optional field set.
pub fn values() -> Vec<(&'static str, &'static str, Value)> {
    let principal = identity(0x11);
    let delegate = identity(0x22);
    let holder = Holder::new(&principal, AUDIENCE);
    let (nb, exp) = (1_800_000_000, 1_800_003_600);

    let d_min = holder.delegate_to(delegate.public_key(), Bounds::default(), nb, exp);
    let d_full = holder.delegate_to(
        delegate.public_key(),
        Bounds {
            actions: vec![b"pay".to_vec(), b"refund".to_vec(), b"read".to_vec()],
            max_per_invocation: Some(10_000),
            max_total: Some(20_000),
            window_secs: Some(86_400),
            approval_required_above: Some(100),
        },
        nb,
        exp,
    );

    let l_min = holder.login([0x31; 32], nb, 60);
    let mut l_full = holder.login_for_request([0x32; 32], nb, 60, [0x33; 32]);
    // Not re-signed: wire vectors check encoding, not the signature.
    l_full.session_commitment = Some([0x34; 32]);

    let a_min = holder.approve(&d_min, &[0x41; 32], b"pay", 0, [0x42; 32], nb, 60);
    let a_full = holder.approve(
        &d_full,
        &[0x43; 32],
        b"refund-large",
        u128::MAX,
        [0x44; 32],
        nb,
        60,
    );

    vec![
        ("delegation_minimal", "delegation", Value::Delegation(d_min)),
        ("delegation_full", "delegation", Value::Delegation(d_full)),
        ("login_minimal", "login_proof", Value::Login(l_min)),
        ("login_full", "login_proof", Value::Login(l_full)),
        ("approval_minimal", "approval", Value::Approval(a_min)),
        ("approval_full", "approval", Value::Approval(a_full)),
    ]
}
