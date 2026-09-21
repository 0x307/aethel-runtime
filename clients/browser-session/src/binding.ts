/**
 * The canonical request binding, in the browser.
 *
 * This is the second implementation of one format. The first, and the
 * specification, is `crates/aethel-auth/src/binding.rs`. Read that before
 * changing anything here: the two must produce identical bytes or nothing
 * verifies, and a change to one is a change to both.
 *
 * The layout, where `LP(x)` is `x` prefixed with its length as four
 * big-endian bytes:
 *
 *     LP("aethel-auth/session-binding/v1")
 *     LP(audience)
 *     LP(method)              uppercase ASCII, normalised
 *     LP(path)                exactly as sent
 *     LP(query)               without '?', may be empty
 *     LP(sha256(body))        32 bytes, of zero bytes when there is no body
 *     u64 timestamp           unix seconds, 8 bytes big-endian
 *     LP(nonce)               32 bytes
 */

/** Domain separator. Must match `SESSION_BINDING_V1` in the Rust crate. */
export const SESSION_BINDING_V1 = "aethel-auth/session-binding/v1";

const utf8 = new TextEncoder();

export interface RequestBinding {
  /** The relying party, identical to the audience the session was opened for. */
  audience: string;
  /** HTTP method. Case is normalised, so `get` and `GET` agree. */
  method: string;
  /** Path exactly as it will be transmitted. */
  path: string;
  /** Query without its leading `?`. Empty when there is none. */
  query: string;
  /** SHA-256 of the body, or of the empty string when there is no body. */
  bodySha256: Uint8Array;
  /** Unix seconds. */
  timestamp: number;
  /** 32 bytes from `crypto.getRandomValues`. */
  nonce: Uint8Array;
}

/**
 * SHA-256, via WebCrypto.
 *
 * WebCrypto offers SHA-2 and has no SHA-3 or SHAKE, which is why this format
 * uses SHA-256 for the body hash and HMAC-SHA-256 for the MAC while the
 * server-only hashes stay on SHAKE-256. Symmetric throughout, so the
 * all-post-quantum position holds: Grover costs a square root, leaving 128
 * bits on a 256-bit key.
 */
export async function sha256(input: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", input as BufferSource);
  return new Uint8Array(digest);
}

/** Append `bytes` prefixed with its length as four big-endian bytes. */
function pushLenPrefixed(parts: Uint8Array[], bytes: Uint8Array): void {
  const len = new Uint8Array(4);
  new DataView(len.buffer).setUint32(0, bytes.length, false);
  parts.push(len, bytes);
}

/**
 * The exact bytes the MAC covers.
 *
 * Mirrors `RequestBinding::encode` in Rust. The method is the only field
 * normalised, and it is normalised on both sides: a deterministic transform
 * applied twice cannot drift, whereas a convention two codebases are asked to
 * follow can.
 */
export function encodeBinding(b: RequestBinding): Uint8Array {
  const parts: Uint8Array[] = [];

  pushLenPrefixed(parts, utf8.encode(SESSION_BINDING_V1));
  pushLenPrefixed(parts, utf8.encode(b.audience));
  pushLenPrefixed(parts, utf8.encode(b.method.toUpperCase()));
  pushLenPrefixed(parts, utf8.encode(b.path));
  pushLenPrefixed(parts, utf8.encode(b.query));
  pushLenPrefixed(parts, b.bodySha256);

  // Unprefixed: the width is fixed at eight bytes. BigInt rather than
  // `setUint32` twice, so this keeps working past 2038 without a second look.
  const ts = new Uint8Array(8);
  new DataView(ts.buffer).setBigUint64(0, BigInt(b.timestamp), false);
  parts.push(ts);

  pushLenPrefixed(parts, b.nonce);

  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** base64url without padding, the form every header here uses. */
export function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Inverse of {@link toBase64Url}. */
export function fromBase64Url(text: string): Uint8Array {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}
