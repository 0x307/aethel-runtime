# Security Policy

## Reporting a vulnerability

Email **security@0x307.com**. This address is monitored and routes to a human — not a
mailing list nobody reads.

Please do not open a public GitHub issue for a suspected vulnerability. Include as much
detail as you can: affected version, reproduction steps, and impact if known.

## Response window

Reports are acknowledged within **5 business days**. This is a best-effort
project with a single maintainer and no on-call rotation — see
[`STABILITY.md`](./STABILITY.md) for the full support posture. The response window above is
the one committed number in that posture; everything else is best-effort.

## Supported versions

This project ships `0.x`. Security fixes land on the latest published minor version. Older
`0.x` minors are not backported to, consistent with the stated stability policy.

## What this crate does and does not protect

- **Settlement signatures are secp256k1, and they are yours.** EIP-3009 transfers are
  authorized with the ECDSA key behind the `SettlementSigner` you supply. This crate contains
  no ECDSA code and never holds that key. What it adds is a spend policy enforced before your
  signer is asked, and an ML-DSA-65 record of each authorization, signed with an
  `aethel-core` identity.
- **Known issues in `aethel-core`.** This crate uses `aethel-core`'s `plp`, `signing` and
  `wire` modules. It does not use the `credential` module, so the open credential-commitment
  finding in [`aethel-core`'s SECURITY.md](https://github.com/0x307/aethel-core/blob/main/SECURITY.md)
  does not reach it.
- **Not independently audited.** No third-party security review has been done, and there is no
  CMVP / FIPS 140-3 validation.
