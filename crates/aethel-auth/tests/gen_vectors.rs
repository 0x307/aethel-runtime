//! Test-only generator for the committed fixtures in `tests/vectors/`.
//!
//! Ignored by default: the fixtures are committed, and the tests that read
//! them must never regenerate them. Run on purpose, and review the diff:
//!
//! ```text
//! cargo test -p aethel-auth --all-features --test gen_vectors -- --ignored
//! ```
//!
//! `v0_3_delegations.json` was produced by the 0.3.1 code, before any 0.4
//! change, so it records what 0.3 signed. Do not regenerate it from 0.4 code.

use aethel_auth::{Bounds, Holder};
use aethel_core::signing::Identity;

const AUDIENCE: &[u8] = b"https://pay.example.com";
const NOT_BEFORE: u64 = 1_800_000_000;
const EXPIRES_AT: u64 = 1_800_003_600;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn identity(seed: u8) -> Identity {
    Identity::generate(&[seed; 32]).expect("32 bytes of entropy")
}

#[test]
#[ignore = "writes tests/vectors/v0_3_delegations.json; run on purpose"]
fn generate_v0_3_delegations() {
    let principal = identity(0x11);
    let delegate = identity(0x22);
    let holder = Holder::new(&principal, AUDIENCE);

    let cases: Vec<(&str, Bounds)> = vec![
        ("no_bounds", Bounds::default()),
        (
            "every_bound_set",
            Bounds {
                actions: vec![b"pay".to_vec()],
                max_per_invocation: Some(10_000),
                max_total: Some(20_000),
                window_secs: Some(86_400),
                approval_required_above: Some(100),
            },
        ),
        (
            "explicit_some_zero",
            Bounds {
                actions: vec![b"pay".to_vec()],
                max_per_invocation: Some(0),
                max_total: Some(0),
                window_secs: Some(0),
                approval_required_above: Some(0),
            },
        ),
        (
            "three_actions",
            Bounds {
                actions: vec![b"pay".to_vec(), b"refund".to_vec(), b"read".to_vec()],
                max_per_invocation: Some(500),
                max_total: None,
                window_secs: None,
                approval_required_above: None,
            },
        ),
    ];

    let entries: Vec<serde_json::Value> = cases
        .into_iter()
        .map(|(name, bounds)| {
            let d = holder.delegate_to(delegate.public_key(), bounds, NOT_BEFORE, EXPIRES_AT);
            serde_json::json!({
                "name": name,
                "json": serde_json::to_value(&d).unwrap(),
                "signing_input_hex": hex(&d.signing_input()),
                "id_hex": hex(&d.id()),
                "signature_hex": hex(&d.signature),
            })
        })
        .collect();

    let doc = serde_json::json!({
        "made_at": "aethel-auth 0.3.1 (edward/rel-aethel-auth-0.3.1), before any 0.4 change",
        "principal_seed_byte": "0x11 repeated 32 times",
        "delegate_seed_byte": "0x22 repeated 32 times",
        "audience": String::from_utf8(AUDIENCE.to_vec()).unwrap(),
        "verify_at": NOT_BEFORE + 10,
        "delegations": entries,
    });

    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/v0_3_delegations.json");
    std::fs::write(path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
}
