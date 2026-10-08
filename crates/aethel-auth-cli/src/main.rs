//! Terminal signer for `aethel-auth`.
//!
//! A browser cannot hold an ML-DSA signer, and an ML-DSA-65 signature is 3,309
//! bytes. So signing happens where the key actually lives: here.
//!
//! # What this tool refuses to do
//!
//! - **Act at more than one relying party from one identity.** The audience is
//!   in the identity file, not on the command line, so there is no flag that
//!   would let one key reach two services.
//! - **Sign something it will not show you.** A step-up binds an action
//!   digest; consenting to an opaque 32 bytes is consenting to nothing, so the
//!   audience and the action are printed before any signature is produced.
//! - **Put a passphrase in your shell history.** Passphrases come from a file
//!   or standard input, never an argument.

use std::io::Read;
use std::path::{Path, PathBuf};

use aethel_auth::{revoke_as_authority, Bounds, Holder};
use clap::{Parser, Subcommand};
use rand::RngCore;
use zeroize::Zeroizing;

mod identity_file;
mod recovery;

use identity_file::{IdentityFile, RecoveryRecord};

#[derive(Debug)]
pub enum CliError {
    Io(String),
    Corrupt(&'static str),
    Crypto(&'static str),
    WrongPassphrase,
    NotEnoughShares,
    Usage(String),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::Io(e) => write!(f, "{e}"),
            CliError::Corrupt(what) => write!(f, "{what} is malformed"),
            CliError::Crypto(what) => write!(f, "{what} failed"),
            CliError::WrongPassphrase => write!(
                f,
                "could not unseal: wrong passphrase, or the file was altered"
            ),
            CliError::NotEnoughShares => write!(
                f,
                "not enough shares to reconstruct; the scheme needs 3 of 5"
            ),
            CliError::Usage(m) => write!(f, "{m}"),
        }
    }
}

#[derive(Parser)]
#[command(
    name = "aethel-auth",
    about = "Terminal signer for aethel-auth",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create an identity, bound to one relying party.
    New {
        /// The relying party this identity will act at, and only this one.
        #[arg(long)]
        audience: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        passphrase_file: PathBuf,
        /// Where to write recovery shares. One file each.
        #[arg(long, default_value = "shares")]
        shares_dir: PathBuf,
        /// Skip recovery. **This cannot be undone**: shares can only be made
        /// now, while the entropy still exists.
        #[arg(long)]
        no_recovery: bool,
    },
    /// Print what an identity file holds, without unsealing it.
    Show {
        #[arg(long)]
        identity: PathBuf,
    },
    /// Produce a login proof.
    Login {
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        passphrase_file: PathBuf,
        #[arg(long, default_value_t = 60)]
        valid_for: u64,
    },
    /// Re-prove control for one specific action.
    StepUp {
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        passphrase_file: PathBuf,
        /// 32-byte digest, hex. The relying party supplies it.
        #[arg(long)]
        action_digest: String,
        /// What that digest means, in words. Printed before signing, because
        /// consenting to an opaque digest is consenting to nothing.
        #[arg(long)]
        action_says: String,
        #[arg(long, default_value_t = 60)]
        valid_for: u64,
    },
    /// Grant another key bounded authority to act for this one.
    Delegate {
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        passphrase_file: PathBuf,
        /// The delegate's public key, hex. It needs its own identity at this
        /// same relying party.
        #[arg(long)]
        to: String,
        /// An action the delegate may perform. Repeatable. No actions means
        /// no authority.
        #[arg(long = "action")]
        actions: Vec<String>,
        #[arg(long)]
        max_per_invocation: Option<u128>,
        /// Ceiling on the sum over --window-secs. The relying party keeps the
        /// running total and enforces it. Requires --window-secs.
        #[arg(long)]
        max_total: Option<u128>,
        /// The window --max-total applies over, in seconds. Requires
        /// --max-total.
        #[arg(long)]
        window_secs: Option<u64>,
        #[arg(long)]
        approval_required_above: Option<u128>,
        #[arg(long, default_value_t = 86_400)]
        valid_for: u64,
    },
    /// End an identity's authority at its relying party: this one's own, or,
    /// with --subject, another key's, signing as an authority the relying
    /// party recognises. Only ever removes authority.
    Revoke {
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        passphrase_file: PathBuf,
        /// The public key to revoke, hex. Omit to revoke this identity itself.
        #[arg(long)]
        subject: Option<String>,
    },
    /// Name the key that continues this identity's authority.
    Succeed {
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        passphrase_file: PathBuf,
        /// The successor's public key, hex.
        #[arg(long)]
        to: String,
    },
    /// Reconstruct an identity from recovery shares.
    Recover {
        /// A share file. Repeatable; the scheme needs 3 of 5.
        #[arg(long = "share")]
        shares: Vec<PathBuf>,
        /// The Merkle root, printed when the shares were created. The shares
        /// deliberately do not carry it.
        #[arg(long)]
        root: String,
        #[arg(long)]
        audience: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        passphrase_file: PathBuf,
    },
}

fn read_passphrase(path: &Path) -> Result<Zeroizing<Vec<u8>>, CliError> {
    if path.as_os_str() == "-" {
        let mut buf = Zeroizing::new(Vec::new());
        std::io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| CliError::Io(e.to_string()))?;
        while buf.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
            buf.pop();
        }
        return Ok(buf);
    }
    let mut buf = Zeroizing::new(std::fs::read(path).map_err(|e| CliError::Io(e.to_string()))?);
    while buf.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        buf.pop();
    }
    if buf.is_empty() {
        return Err(CliError::Usage("the passphrase is empty".into()));
    }
    Ok(buf)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs()
}

fn fresh_nonce() -> [u8; 32] {
    let mut n = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut n);
    n
}

/// Load an identity and announce which relying party it is about to act at.
///
/// Printed every time, not only for step-up. Binding the audience is what
/// defeats a relayed proof, and a holder who never sees it cannot notice when
/// it is wrong.
fn open_identity(
    path: &Path,
    passphrase_file: &Path,
) -> Result<(IdentityFile, aethel_core::signing::Identity), CliError> {
    let file = IdentityFile::read(path)?;
    let passphrase = read_passphrase(passphrase_file)?;
    let identity = file.open(&passphrase)?;
    eprintln!("acting at: {}", file.audience);
    Ok((file, identity))
}

fn emit<T: serde::Serialize>(value: &T) -> Result<(), CliError> {
    let text = serde_json::to_string_pretty(value).map_err(|_| CliError::Crypto("encode"))?;
    println!("{text}");
    Ok(())
}

fn decode_key(hex_str: &str, what: &'static str) -> Result<Vec<u8>, CliError> {
    hex::decode(hex_str).map_err(|_| CliError::Corrupt(what))
}

fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::New {
            audience,
            out,
            passphrase_file,
            shares_dir,
            no_recovery,
        } => {
            let passphrase = read_passphrase(&passphrase_file)?;
            let (mut file, entropy) = IdentityFile::create(&audience, &passphrase)?;

            if no_recovery {
                eprintln!(
                    "\nWARNING: no recovery shares were made.\n\
                     Shares can only be created now, while the entropy exists. Once this\n\
                     identity is sealed the entropy is gone, and losing the passphrase means\n\
                     losing this relationship. There is no operator who can restore it.\n"
                );
            } else {
                let (shares, root) = recovery::split(&entropy[..], &audience)?;
                std::fs::create_dir_all(&shares_dir).map_err(|e| CliError::Io(e.to_string()))?;
                for share in &shares {
                    let p = shares_dir.join(format!("share-{}.json", share.index));
                    recovery::write_share(share, &p)?;
                }
                file.recovery = Some(RecoveryRecord {
                    root: root.clone(),
                    shares_issued: shares.len() as u8,
                    threshold: 3,
                });
                eprintln!(
                    "\n{} recovery shares written to {}.\n\
                     Give them to people you trust, separately. Any 3 can rebuild this identity.\n\n\
                     Recovery root: {}\n\
                     Record that somewhere other than this machine. Reconstruction needs it and\n\
                     the shares deliberately do not carry it.\n",
                    shares.len(),
                    shares_dir.display(),
                    root
                );
            }

            file.write(&out)?;
            eprintln!("identity written to {}", out.display());
            eprintln!("key: {}", file.fingerprint()?);
            Ok(())
        }

        Command::Show { identity } => {
            let file = IdentityFile::read(&identity)?;
            println!("audience:   {}", file.audience);
            println!("key:        {}", file.fingerprint()?);
            println!("full key:   {}", file.public_key);
            match &file.recovery {
                Some(r) => println!(
                    "recovery:   {} shares, {} needed, root {}",
                    r.shares_issued, r.threshold, r.root
                ),
                None => println!("recovery:   NONE. This identity cannot be recovered."),
            }
            Ok(())
        }

        Command::Login {
            identity,
            passphrase_file,
            valid_for,
        } => {
            let (file, id) = open_identity(&identity, &passphrase_file)?;
            let holder = Holder::new(&id, file.audience_bytes());
            emit(&holder.login(fresh_nonce(), now(), valid_for))
        }

        Command::StepUp {
            identity,
            passphrase_file,
            action_digest,
            action_says,
            valid_for,
        } => {
            let digest = decode_key(&action_digest, "action digest")?;
            let digest: [u8; 32] = digest
                .try_into()
                .map_err(|_| CliError::Corrupt("action digest is not 32 bytes"))?;

            let (file, id) = open_identity(&identity, &passphrase_file)?;
            eprintln!("you are authorising: {action_says}");

            let holder = Holder::new(&id, file.audience_bytes());
            emit(&holder.step_up(fresh_nonce(), now(), valid_for, digest))
        }

        Command::Delegate {
            identity,
            passphrase_file,
            to,
            actions,
            max_per_invocation,
            max_total,
            window_secs,
            approval_required_above,
            valid_for,
        } => {
            if max_total.is_some() != window_secs.is_some() {
                return Err(CliError::Usage(
                    "--max-total and --window-secs go together: a total needs the window it applies over"
                        .into(),
                ));
            }
            if actions.is_empty() {
                return Err(CliError::Usage(
                    "no --action given, which would grant nothing; say what the delegate may do"
                        .into(),
                ));
            }
            let delegate_key = decode_key(&to, "delegate public key")?;
            let (file, id) = open_identity(&identity, &passphrase_file)?;

            eprintln!("delegating to: {to}");
            for a in &actions {
                eprintln!("  may: {a}");
            }

            let holder = Holder::new(&id, file.audience_bytes());
            let start = now();
            emit(&holder.delegate_to(
                delegate_key,
                Bounds {
                    actions: actions.into_iter().map(String::into_bytes).collect(),
                    max_per_invocation,
                    max_total,
                    window_secs,
                    approval_required_above,
                },
                start,
                start + valid_for,
            ))
        }

        Command::Revoke {
            identity,
            passphrase_file,
            subject,
        } => {
            let (file, id) = open_identity(&identity, &passphrase_file)?;
            match subject {
                None => emit(&Holder::new(&id, file.audience_bytes()).revoke_self(now())),
                Some(hex_key) => {
                    let subject = decode_key(&hex_key, "subject public key")?;
                    emit(&revoke_as_authority(
                        &id,
                        subject,
                        file.audience_bytes(),
                        now(),
                    ))
                }
            }
        }

        Command::Succeed {
            identity,
            passphrase_file,
            to,
        } => {
            let successor = decode_key(&to, "successor public key")?;
            let (file, id) = open_identity(&identity, &passphrase_file)?;
            let holder = Holder::new(&id, file.audience_bytes());
            emit(&holder.name_successor(successor, now()))
        }

        Command::Recover {
            shares,
            root,
            audience,
            out,
            passphrase_file,
        } => {
            if shares.len() < 3 {
                return Err(CliError::NotEnoughShares);
            }
            let files = shares
                .iter()
                .map(|p| recovery::read_share(p))
                .collect::<Result<Vec<_>, _>>()?;

            if let Some(mismatched) = files.iter().find(|f| f.audience != audience) {
                return Err(CliError::Usage(format!(
                    "share {} is for {}, not {audience}",
                    mismatched.index, mismatched.audience
                )));
            }

            let entropy = recovery::combine(&files, &root)?;
            let passphrase = read_passphrase(&passphrase_file)?;
            let file = IdentityFile::from_entropy(&audience, &entropy, &passphrase)?;
            file.write(&out)?;

            eprintln!("identity rebuilt at {}", out.display());
            eprintln!("key: {}", file.fingerprint()?);
            eprintln!(
                "\nCheck that fingerprint against the one the relying party knows. If it differs,\n\
                 these shares belong to a different identity.\n"
            );
            Ok(())
        }
    }
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
