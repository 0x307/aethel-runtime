//! The CLI's output, checked by the shipped verifier.
//!
//! Shells out to the real binary rather than calling its internals, because
//! the thing worth testing is what a person actually runs: argument parsing,
//! the identity file, JSON encoding and all. A test that bypassed those would
//! prove the library works, which `aethel-auth`'s own tests already do.

use std::path::PathBuf;
use std::process::Command;

use aethel_auth::{verify_enrolment, verify_login, AuthStrength, EnrolmentProof, InMemoryInviteStore, InMemoryNonceStore, LoginProof, VerifyParams};

const AUDIENCE: &str = "https://console.example.com";

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
        Poll::Pending => panic!("future parked"),
    }
}

struct Workspace {
    dir: PathBuf,
}

impl Workspace {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("aethel-cli-test-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(dir.join("pass"), b"a passphrase with enough in it").expect("passphrase");
        Workspace { dir }
    }

    fn run(&self, args: &[&str]) -> (String, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_aethel-auth-cli"))
            .current_dir(&self.dir)
            .args(args)
            .output()
            .expect("run cli");
        assert!(
            out.status.success(),
            "cli failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn create_identity(&self) {
        self.run(&[
            "new",
            "--audience",
            AUDIENCE,
            "--out",
            "id.json",
            "--passphrase-file",
            "pass",
        ]);
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn params() -> VerifyParams<'static> {
    VerifyParams {
        expected_audience: AUDIENCE.as_bytes(),
        now: now(),
        max_age_secs: 300,
    }
}

#[test]
fn a_login_proof_from_the_cli_verifies() {
    let ws = Workspace::new("login");
    ws.create_identity();

    let (stdout, _) = ws.run(&["login", "--identity", "id.json", "--passphrase-file", "pass"]);
    let proof: LoginProof = serde_json::from_str(&stdout).expect("cli emits a LoginProof");

    let out = block_on(verify_login(&proof, params(), &InMemoryNonceStore::new()))
        .expect("the shipped verifier accepts what the shipped signer produced");

    assert_eq!(out.strength, AuthStrength::Proven);
    assert!(
        out.session_commitment.is_none(),
        "no --session was asked for"
    );
}

#[test]
fn a_session_login_commits_to_the_secret_the_cli_printed() {
    let ws = Workspace::new("session");
    ws.create_identity();

    let (stdout, stderr) = ws.run(&[
        "login",
        "--identity",
        "id.json",
        "--passphrase-file",
        "pass",
        "--session",
    ]);
    let proof: LoginProof = serde_json::from_str(&stdout).expect("a LoginProof");

    // The secret goes to stderr, never into the proof: the signed bytes may be
    // logged, so only a commitment belongs there.
    let secret_hex = stderr
        .lines()
        .find_map(|l| l.strip_prefix("session secret: "))
        .expect("the secret is printed for the browser");
    let raw: [u8; 32] = hex::decode(secret_hex.trim())
        .expect("hex")
        .try_into()
        .expect("32 bytes");

    assert!(
        !stdout.contains(secret_hex.trim()),
        "the raw secret must never appear in the proof itself"
    );

    let out = block_on(verify_login(&proof, params(), &InMemoryNonceStore::new())).expect("verify");
    assert_eq!(
        out.session_commitment.expect("a session was requested"),
        aethel_auth::SessionSecret::from_bytes(raw).commitment(),
        "the proof must commit to the secret the holder was handed"
    );
}

#[test]
fn an_enrolment_from_the_cli_redeems_a_real_invite() {
    let ws = Workspace::new("enrol");
    ws.create_identity();

    let (stdout, _) = ws.run(&[
        "enrol",
        "--identity",
        "id.json",
        "--passphrase-file",
        "pass",
        "--invite",
        "invite-xyz",
    ]);
    let proof: EnrolmentProof = serde_json::from_str(&stdout).expect("an EnrolmentProof");

    let invites = InMemoryInviteStore::new();
    invites.issue(b"invite-xyz".to_vec(), now() + 3600);

    let enrolled = block_on(verify_enrolment(&proof, params(), &invites)).expect("enrol");
    assert!(invites.is_empty(), "the invite is spent");
    assert_eq!(enrolled.audience, AUDIENCE.as_bytes());
}

#[test]
fn recovery_shares_rebuild_the_same_identity() {
    let ws = Workspace::new("recover");
    ws.create_identity();

    let original: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(ws.dir.join("id.json")).unwrap()).unwrap();
    let root = original["recovery"]["root"].as_str().expect("a root");

    // Three of five, and not the first three, so this is not accidentally
    // depending on share order.
    ws.run(&[
        "recover",
        "--share",
        "shares/share-2.json",
        "--share",
        "shares/share-4.json",
        "--share",
        "shares/share-5.json",
        "--root",
        root,
        "--audience",
        AUDIENCE,
        "--out",
        "rebuilt.json",
        "--passphrase-file",
        "pass",
    ]);

    let rebuilt: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(ws.dir.join("rebuilt.json")).unwrap())
            .unwrap();

    assert_eq!(
        original["public_key"], rebuilt["public_key"],
        "3 of 5 shares must rebuild the very same identity, or recovery is \
         not recovery"
    );
}

#[test]
fn two_shares_are_not_enough() {
    let ws = Workspace::new("threshold");
    ws.create_identity();

    let original: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(ws.dir.join("id.json")).unwrap()).unwrap();
    let root = original["recovery"]["root"].as_str().unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_aethel-auth-cli"))
        .current_dir(&ws.dir)
        .args([
            "recover",
            "--share",
            "shares/share-1.json",
            "--share",
            "shares/share-2.json",
            "--root",
            root,
            "--audience",
            AUDIENCE,
            "--out",
            "nope.json",
            "--passphrase-file",
            "pass",
        ])
        .output()
        .expect("run");

    assert!(!out.status.success(), "two shares must not reconstruct");
    assert!(!ws.dir.join("nope.json").exists(), "and nothing is written");
}

#[test]
fn an_identity_is_bound_to_one_audience() {
    let ws = Workspace::new("audience");
    ws.create_identity();

    let (stdout, stderr) = ws.run(&["login", "--identity", "id.json", "--passphrase-file", "pass"]);
    let proof: LoginProof = serde_json::from_str(&stdout).unwrap();

    assert!(
        stderr.contains(AUDIENCE),
        "the holder is always told which relying party they are acting at"
    );

    let elsewhere = VerifyParams {
        expected_audience: b"https://gateway.example.com",
        now: now(),
        max_age_secs: 300,
    };
    assert!(
        block_on(verify_login(&proof, elsewhere, &InMemoryNonceStore::new())).is_err(),
        "there is no flag that would let one identity act at a second service"
    );
}

#[test]
fn the_wrong_passphrase_is_refused() {
    let ws = Workspace::new("passphrase");
    ws.create_identity();
    std::fs::write(ws.dir.join("wrong"), b"not the passphrase").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_aethel-auth-cli"))
        .current_dir(&ws.dir)
        .args(["login", "--identity", "id.json", "--passphrase-file", "wrong"])
        .output()
        .expect("run");

    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("could not unseal"));
}
