# @aethel/browser-session

The browser half of an Aethel session. It holds one symmetric secret as a
non-extractable WebCrypto key and MACs each request with it.

It does **not** sign. There is no ML-DSA signer in a browser, which is the
entire reason sessions exist in a protocol that otherwise re-proves authority
on every request. Logging in, stepping up to a sensitive action and naming a
successor all happen in the terminal signer (`aethel-auth-cli`).

## Using it

```ts
import { AethelSession } from "@aethel/browser-session";

// What the terminal signer printed at login, delivered once.
const session = await AethelSession.open({
  audience: "https://console.example.com",
  token: "...",      // base64url
  secret: "...",     // base64url, 32 bytes, consumed and discarded
  expiresAt: 1758003600,
});

const res = await session.fetch("/api/profile");
```

`session.fetch` attaches four headers:

| Header | Contents |
|---|---|
| `Aethel-Session` | the opaque session token |
| `Aethel-Nonce` | 32 fresh random bytes, base64url |
| `Aethel-Timestamp` | unix seconds |
| `Aethel-Mac` | HMAC-SHA-256 over the canonical binding |

When the session lapses, `fetch` throws `SessionExpiredError`. There is no
renewal path: extending a session without a fresh signature would extend
authority nobody re-asserted. Catch it and send the person back to the
terminal signer.

## Rules this client is built on

**The secret is never persisted.** Not `localStorage`, not `sessionStorage`,
not a cookie, not a log. It is imported as a `CryptoKey` with
`extractable: false` and the raw bytes are dropped. A reload means logging in
again, which is the correct trade.

Non-extractability is the whole argument. If JavaScript could read the key, an
XSS would take it and the MAC would add nothing over a bearer token, which is
the one thing this design exists to beat.

**HMAC-SHA-256, not SHAKE.** WebCrypto offers HMAC over SHA-2 and has no SHA-3
or SHAKE. Computing SHAKE in JavaScript would mean JavaScript holding the raw
key, defeating the non-extractable key entirely. Both are symmetric, so the
all-post-quantum position is unaffected: Grover costs a square root, leaving
128 bits on a 256-bit key. Server-only hashes stay on SHAKE-256.

**Bodies it cannot hash, it refuses.** `FormData`, `Blob`, `URLSearchParams`
and streams serialise somewhere this client cannot observe, so the bytes it
hashed would not be the bytes sent. It throws `UnsupportedBodyError` rather
than MAC something else, because a MAC over the wrong body is worse than no
MAC: it looks like protection.

## The binding

`src/binding.ts` is the second implementation of one byte format. The first,
and the specification, is `crates/aethel-auth/src/binding.rs`. **A change to
one is a change to both**, and they must produce identical bytes or nothing
verifies.

They are not trusted to agree. `crates/aethel-auth/tests/binding_cross_language.rs`
runs this client on real WebCrypto, takes the headers a server would receive,
rebuilds the binding from Rust's own copy of each case and verifies the MAC.
Nine cases cover percent-encoding, UTF-8, an empty body, a lowercase method
and a path the URL parser normalises.

Two things are worth knowing before debugging a MAC failure:

- **Path and query are bound exactly as transmitted.** A proxy that rewrites
  `//a` to `/a`, or decodes `%2F`, changes what the server sees and every MAC
  fails. That is the correct direction to fail, and it is the first thing to
  check.
- **The client binds the post-normalisation path**, because that is what
  `fetch` actually sends and therefore what the server reads off the request
  line.

## Development

```bash
npm install && npm run typecheck
```

The install is only for `tsc`. The cross-language test needs nothing but node
22.6 or newer, which it uses to run the TypeScript directly:

```bash
cargo test -p aethel-auth --test binding_cross_language
```
