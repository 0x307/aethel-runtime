//! The TypeScript client's output, checked by this crate's verifier.
//!
//! Two implementations of one byte format will agree right up until they do
//! not, and the failure is silent in the worst way: every request stops
//! verifying at once, in production, with the cryptography looking guilty.
//!
//! So this does not compare the two encoders. It runs the real browser client
//! on real WebCrypto, takes the headers a server would receive, rebuilds the
//! binding from Rust's own copy of the case, and calls
//! [`verify_request`]. Nothing is accepted on the TypeScript's word: the
//! cases are defined here, the expectations are computed here, and the MAC
//! either verifies against bytes Rust built or the test fails.
//!
//! Requires `node` (22.6 or newer, for `--experimental-strip-types`). There
//! is deliberately no skip path — a cross-language test that quietly does not
//! run is worse than no test, because the gate still reports green.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use aethel_auth::{
    sha256_32, verify_request, AuthError, AuthStrength, InMemoryNonceStore, InMemorySessionStore,
    RequestBinding, Session, SessionSecret, SessionStore, SessionToken,
};

const AUDIENCE: &str = "https://console.example.com";
const NOW: u64 = 1_758_000_000;
const MAX_AGE: u64 = 300;
const SECRET: [u8; 32] = [9u8; 32];
const TOKEN: [u8; 32] = [7u8; 32];

fn block_on<F: core::future::Future>(f: F) -> F::Output {
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn noop(_: *const ()) {}
    fn clone(p: *const ()) -> RawWaker {
        RawWaker::new(p, &VTABLE)
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut f = Box::pin(f);
    match f.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("future parked; these stores do not yield"),
    }
}

/// One case, in both the form the client is given and the form a server sees.
///
/// `path_sent` and `path_bound` differ only where the URL parser normalises,
/// which is a documented property of the format rather than an accident.
struct Case {
    what: &'static str,
    method: &'static str,
    path_sent: &'static str,
    path_bound: &'static str,
    query: &'static str,
    body: Option<&'static str>,
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            what: "a plain GET",
            method: "GET",
            path_sent: "/profile",
            path_bound: "/profile",
            query: "",
            body: None,
        },
        Case {
            what: "a query string",
            method: "GET",
            path_sent: "/search",
            path_bound: "/search",
            query: "q=aethel&page=2",
            body: None,
        },
        Case {
            what: "a JSON body",
            method: "POST",
            path_sent: "/transfer",
            path_bound: "/transfer",
            query: "",
            body: Some(r#"{"amount":1,"to":"alice"}"#),
        },
        Case {
            what: "a POST with an empty body, which is not the same as no body \
                   at the HTTP level but hashes identically",
            method: "POST",
            path_sent: "/ping",
            path_bound: "/ping",
            query: "",
            body: Some(""),
        },
        Case {
            what: "a lowercase method, which both sides uppercase",
            method: "delete",
            path_sent: "/session",
            path_bound: "/session",
            query: "",
            body: None,
        },
        Case {
            what: "percent-encoding, which must survive unchanged rather than \
                   being decoded by either side",
            method: "GET",
            path_sent: "/files/a%2Fb",
            path_bound: "/files/a%2Fb",
            query: "",
            body: None,
        },
        Case {
            what: "non-ASCII, to pin that both sides encode UTF-8 and count \
                   bytes rather than characters",
            method: "GET",
            path_sent: "/search",
            path_bound: "/search",
            query: "q=%C3%A9t%C3%A9&name=Ed",
            body: Some("{\"note\":\"café ☕\"}"),
        },
        Case {
            // The browser binds what fetch will actually send, which is the
            // normalised path. A server reading the request line sees the
            // same thing, so the two agree; a reader expecting the literal
            // string would not.
            what: "a path the URL parser normalises before it reaches the wire",
            method: "GET",
            path_sent: "/a/./b",
            path_bound: "/a/b",
            query: "",
            body: None,
        },
        Case {
            what: "a repeat of the first case, so a constant nonce in the \
                   client would show up as a replay rather than passing",
            method: "GET",
            path_sent: "/profile",
            path_bound: "/profile",
            query: "",
            body: None,
        },
    ]
}

/// base64url without padding, as the headers carry it.
fn b64url_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        let take = chunk.len() + 1;
        for i in 0..take {
            out.push(ALPHABET[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
        }
    }
    out
}

/// What a server does with the headers it receives.
fn b64url_decode(text: &str) -> Vec<u8> {
    let value = |c: u8| -> u32 {
        match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a') as u32 + 26,
            b'0'..=b'9' => (c - b'0') as u32 + 52,
            b'-' => 62,
            b'_' => 63,
            _ => panic!("not base64url: {}", c as char),
        }
    };
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= value(c) << (18 - 6 * i);
        }
        let produced = chunk.len() - 1;
        for i in 0..produced {
            out.push(((n >> (16 - 8 * i)) & 0xff) as u8);
        }
    }
    out
}

/// Run the TypeScript client over every case and hand back its headers.
fn run_harness(cases: &[Case]) -> Vec<std::collections::HashMap<String, String>> {
    let harness = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../clients/browser-session/test/harness.ts");
    assert!(
        harness.exists(),
        "the browser client's harness is missing at {}",
        harness.display()
    );

    let case_json: Vec<String> = cases
        .iter()
        .map(|c| {
            let body = match c.body {
                Some(b) => format!("\"{}\"", escape_json(b)),
                None => "null".to_string(),
            };
            format!(
                r#"{{"method":"{}","path":"{}","query":"{}","body":{}}}"#,
                c.method, c.path_sent, c.query, body
            )
        })
        .collect();

    let input = format!(
        r#"{{"audience":"{}","token":"{}","secret":"{}","expiresAt":{},"now":{},"cases":[{}]}}"#,
        AUDIENCE,
        b64url_encode(&TOKEN),
        b64url_encode(&SECRET),
        NOW + 3600,
        NOW,
        case_json.join(",")
    );

    let node = std::env::var("NODE").unwrap_or_else(|_| "node".to_string());
    let mut child = Command::new(&node)
        .arg("--experimental-strip-types")
        .arg("--no-warnings")
        .arg(&harness)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| {
            panic!(
                "could not run `{node}`: {e}.\n\n\
                 This test proves the TypeScript client and this crate compute \
                 the same bytes, and there is no skip path on purpose: a \
                 cross-language check that quietly does not run still reports \
                 green. Install node 22.6 or newer, or point NODE at it."
            )
        });

    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write cases");

    let out = child.wait_with_output().expect("harness ran");
    assert!(
        out.status.success(),
        "the browser client failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    parse_results(&String::from_utf8_lossy(&out.stdout))
}

/// Read the harness's `{"results":[{...}]}`.
fn parse_results(json: &str) -> Vec<std::collections::HashMap<String, String>> {
    let parsed: serde_json::Value =
        serde_json::from_str(json).unwrap_or_else(|e| panic!("harness emitted invalid JSON: {e}\n{json}"));
    parsed["results"]
        .as_array()
        .expect("results is an array")
        .iter()
        .map(|entry| {
            entry
                .as_object()
                .expect("each result is an object")
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        v.as_str().expect("header values are strings").to_string(),
                    )
                })
                .collect()
        })
        .collect()
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[test]
fn the_base64url_helpers_round_trip() {
    // These two sit between the client and the verifier in every other test
    // here, so a bug in them would surface as a confusing crypto failure
    // rather than as itself.
    for len in [0usize, 1, 2, 3, 31, 32, 33] {
        let bytes: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
        assert_eq!(b64url_decode(&b64url_encode(&bytes)), bytes, "len {len}");
    }
    // Pinned against a known value, so the pair cannot be wrong in the same
    // direction and still agree with itself.
    assert_eq!(b64url_encode(b"aethel"), "YWV0aGVs");
    assert_eq!(b64url_decode("YWV0aGVs"), b"aethel");
}

#[test]
fn the_browser_client_and_this_crate_agree_byte_for_byte() {
    let cases = cases();
    let results = run_harness(&cases);
    assert_eq!(
        results.len(),
        cases.len(),
        "the harness returned {} results for {} cases",
        results.len(),
        cases.len()
    );

    let sessions = InMemorySessionStore::new();
    let nonces = InMemoryNonceStore::new();
    let token = SessionToken::from_bytes(TOKEN);
    block_on(sessions.create(Session::new(
        &token,
        SessionSecret::from_bytes(SECRET),
        1u32,
        AUDIENCE.as_bytes().to_vec(),
        AuthStrength::Proven,
        0,
        NOW,
        NOW + 3600,
    )))
    .expect("create");

    for (case, headers) in cases.iter().zip(results.iter()) {
        let presented_token =
            SessionToken::from_client_value(&b64url_decode(&headers["Aethel-Session"]));
        let nonce: [u8; 32] = b64url_decode(&headers["Aethel-Nonce"])
            .try_into()
            .unwrap_or_else(|_| panic!("{}: nonce is not 32 bytes", case.what));
        let mac = b64url_decode(&headers["Aethel-Mac"]);
        let timestamp: u64 = headers["Aethel-Timestamp"]
            .parse()
            .unwrap_or_else(|_| panic!("{}: timestamp is not a number", case.what));

        // Built from Rust's own copy of the case. The TypeScript supplied the
        // nonce, the timestamp and the MAC, and nothing else.
        let binding = RequestBinding {
            audience: AUDIENCE.as_bytes(),
            method: case.method,
            path: case.path_bound,
            query: case.query,
            body_sha256: sha256_32(case.body.unwrap_or("").as_bytes()),
            timestamp,
            nonce,
        };

        block_on(verify_request(
            &sessions,
            &nonces,
            &presented_token,
            &binding,
            &mac,
            NOW,
            MAX_AGE,
            0,
        ))
        .unwrap_or_else(|e| {
            panic!(
                "{}: the Rust verifier rejected what the browser client \
                 produced ({e:?}).\nThis means the two encoders disagree. \
                 Compare crates/aethel-auth/src/binding.rs against \
                 clients/browser-session/src/binding.ts.",
                case.what
            )
        });
    }
}

#[test]
fn the_client_uses_a_fresh_nonce_for_every_request() {
    // The repeated case above would already fail as a replay, but this says
    // so directly, because a constant nonce is the single most likely way for
    // this client to be wrong while looking correct.
    let cases = cases();
    let results = run_harness(&cases);

    let mut seen = std::collections::HashSet::new();
    for (case, headers) in cases.iter().zip(results.iter()) {
        let nonce = headers["Aethel-Nonce"].clone();
        assert!(
            seen.insert(nonce),
            "{}: the client reused a nonce, so every request it makes can be \
             replayed for the life of the session",
            case.what
        );
    }
}

#[test]
fn a_mac_from_the_client_does_not_verify_for_a_different_request() {
    // The client's MAC is not a blanket session credential. Proven against
    // real output rather than against a Rust-made MAC, because the question
    // is whether the client actually bound the request it was given.
    let cases = cases();
    let results = run_harness(&cases);

    let sessions = InMemorySessionStore::new();
    let nonces = InMemoryNonceStore::new();
    let token = SessionToken::from_bytes(TOKEN);
    block_on(sessions.create(Session::new(
        &token,
        SessionSecret::from_bytes(SECRET),
        1u32,
        AUDIENCE.as_bytes().to_vec(),
        AuthStrength::Proven,
        0,
        NOW,
        NOW + 3600,
    )))
    .expect("create");

    let headers = &results[0];
    let nonce: [u8; 32] = b64url_decode(&headers["Aethel-Nonce"]).try_into().unwrap();
    let mac = b64url_decode(&headers["Aethel-Mac"]);
    let timestamp: u64 = headers["Aethel-Timestamp"].parse().unwrap();

    // The MAC the client made for `GET /profile`, moved onto `DELETE /account`.
    let attacked = RequestBinding {
        audience: AUDIENCE.as_bytes(),
        method: "DELETE",
        path: "/account",
        query: "",
        body_sha256: sha256_32(b""),
        timestamp,
        nonce,
    };

    let out = block_on(verify_request(
        &sessions, &nonces, &token, &attacked, &mac, NOW, MAX_AGE, 0,
    ));
    assert!(
        matches!(out, Err(AuthError::BadMac)),
        "a MAC for one request must not authorise another, got {out:?}"
    );
}
