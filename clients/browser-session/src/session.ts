/**
 * The browser half of an Aethel session.
 *
 * # What this does, and what it deliberately cannot
 *
 * The browser does **not** sign. It has no ML-DSA signer, which is the entire
 * reason sessions exist in a protocol that otherwise re-proves authority on
 * every request. This client holds one symmetric secret and MACs requests
 * with it. Anything needing a real signature — logging in, stepping up to a
 * sensitive action, naming a successor — happens in the terminal signer
 * (`aethel-auth-cli`) and cannot happen here.
 *
 * # The key is non-extractable, and that is the whole point
 *
 * The session secret is imported with `extractable: false`, so the page can
 * use it and cannot read it. If JavaScript could read it, an XSS would take
 * it, and the MAC would add nothing over a bearer token — which is the one
 * thing this design exists to beat.
 *
 * That constraint also decides the algorithm. WebCrypto offers HMAC over
 * SHA-2 and has no SHA-3 or SHAKE, so the MAC is HMAC-SHA-256 even though
 * SHAKE-256 is this family's house hash everywhere else. Computing SHAKE in
 * JavaScript would mean JavaScript holding the raw key, defeating the
 * non-extractable key entirely. Both are symmetric, so the all-post-quantum
 * position is unaffected.
 *
 * # Where the secret must never go
 *
 * Not `localStorage`, not `sessionStorage`, not a cookie, not a log. Import
 * it and let the raw bytes go. A `CryptoKey` lives as long as the page does;
 * a reload means logging in again, which is the correct trade and not a
 * limitation to engineer around.
 */

import {
  encodeBinding,
  fromBase64Url,
  sha256,
  toBase64Url,
  type RequestBinding,
} from "./binding.ts";

/** Headers carrying the session and its per-request proof. */
export const HEADER_SESSION = "Aethel-Session";
export const HEADER_NONCE = "Aethel-Nonce";
export const HEADER_TIMESTAMP = "Aethel-Timestamp";
export const HEADER_MAC = "Aethel-Mac";

/**
 * The session ended. Log in again through the terminal signer.
 *
 * There is no renewal path, deliberately: extending a session without a fresh
 * signature would extend authority nobody re-asserted.
 */
export class SessionExpiredError extends Error {
  constructor() {
    super("the Aethel session has expired; re-authenticate with the terminal signer");
    this.name = "SessionExpiredError";
  }
}

/** A body this client cannot hash, so it refuses rather than MAC nothing. */
export class UnsupportedBodyError extends Error {
  constructor(kind: string) {
    super(
      `cannot bind a ${kind} body: it is not readable twice, so the MAC could ` +
        `not cover what is actually sent. Serialise it to a string or a ` +
        `Uint8Array first.`,
    );
    this.name = "UnsupportedBodyError";
  }
}

/** What the terminal signer hands the browser, once, at login. */
export interface SessionMaterial {
  /** The relying party, identical to the audience the login proof named. */
  audience: string;
  /** The opaque session token, base64url, as issued. */
  token: string;
  /** The 32-byte session secret, base64url. Consumed and discarded. */
  secret: string;
  /** Unix seconds the session stops being valid. */
  expiresAt: number;
}

/** The headers proving one request came from this session. */
export interface SignedHeaders {
  [HEADER_SESSION]: string;
  [HEADER_NONCE]: string;
  [HEADER_TIMESTAMP]: string;
  [HEADER_MAC]: string;
}

const utf8 = new TextEncoder();

/** Hash whatever the caller is about to send, or refuse to guess. */
async function hashBody(body: BodyInit | null | undefined): Promise<Uint8Array> {
  if (body === null || body === undefined) return sha256(new Uint8Array(0));
  if (typeof body === "string") return sha256(utf8.encode(body));
  if (body instanceof Uint8Array) return sha256(body);
  if (body instanceof ArrayBuffer) return sha256(new Uint8Array(body));
  if (ArrayBuffer.isView(body)) {
    return sha256(new Uint8Array(body.buffer, body.byteOffset, body.byteLength));
  }
  // FormData, URLSearchParams, Blob and ReadableStream all serialise somewhere
  // this client cannot observe, so the bytes it hashed would not be the bytes
  // sent. Refusing is the only honest option: a MAC over the wrong body is
  // worse than no MAC, because it looks like protection.
  if (body instanceof ReadableStream) throw new UnsupportedBodyError("streaming");
  if (typeof FormData !== "undefined" && body instanceof FormData) {
    throw new UnsupportedBodyError("FormData");
  }
  if (typeof Blob !== "undefined" && body instanceof Blob) {
    throw new UnsupportedBodyError("Blob");
  }
  throw new UnsupportedBodyError("non-serialisable");
}

export class AethelSession {
  readonly audience: string;
  readonly expiresAt: number;

  readonly #key: CryptoKey;
  readonly #token: string;

  private constructor(audience: string, expiresAt: number, key: CryptoKey, token: string) {
    this.audience = audience;
    this.expiresAt = expiresAt;
    this.#key = key;
    this.#token = token;
  }

  /**
   * Take the material the terminal signer produced and hold it as a key the
   * page cannot read back.
   *
   * The caller should not keep `material.secret` afterwards. This method
   * overwrites the copy it decoded, which is the most JavaScript allows: a
   * string is immutable and the engine may retain copies, so the real
   * guarantee comes from never persisting it rather than from erasing it.
   */
  static async open(material: SessionMaterial): Promise<AethelSession> {
    const raw = fromBase64Url(material.secret);
    if (raw.length !== 32) {
      throw new Error(`session secret must be 32 bytes, got ${raw.length}`);
    }

    const key = await crypto.subtle.importKey(
      "raw",
      raw as BufferSource,
      { name: "HMAC", hash: "SHA-256" },
      // Non-extractable. Everything above depends on this staying false.
      false,
      ["sign"],
    );

    raw.fill(0);

    return new AethelSession(material.audience, material.expiresAt, key, material.token);
  }

  /** Whether the session has lapsed as of `now` (unix seconds). */
  isExpired(now: number = Math.floor(Date.now() / 1000)): boolean {
    return now >= this.expiresAt;
  }

  /**
   * Produce the headers proving one request came from this session.
   *
   * Public because the fetch wrapper is a convenience and some callers have
   * their own transport. This is the method that must agree with the Rust
   * verifier, and it is the one the cross-language test exercises.
   */
  async signRequest(
    method: string,
    url: string | URL,
    body?: BodyInit | null,
    now: number = Math.floor(Date.now() / 1000),
  ): Promise<SignedHeaders> {
    if (this.isExpired(now)) throw new SessionExpiredError();

    // Resolve through URL so path and query are exactly what will go on the
    // wire. fetch applies the same normalisation, so reading it here rather
    // than from the caller's string is what keeps both ends agreeing.
    const resolved = url instanceof URL ? url : new URL(url, this.audience);

    const nonce = crypto.getRandomValues(new Uint8Array(32));
    const binding: RequestBinding = {
      audience: this.audience,
      method,
      path: resolved.pathname,
      query: resolved.search.startsWith("?") ? resolved.search.slice(1) : resolved.search,
      bodySha256: await hashBody(body),
      timestamp: now,
      nonce,
    };

    const mac = await crypto.subtle.sign(
      "HMAC",
      this.#key,
      encodeBinding(binding) as BufferSource,
    );

    return {
      [HEADER_SESSION]: this.#token,
      [HEADER_NONCE]: toBase64Url(nonce),
      [HEADER_TIMESTAMP]: String(now),
      [HEADER_MAC]: toBase64Url(new Uint8Array(mac)),
    };
  }

  /**
   * `fetch`, with this session's headers attached.
   *
   * Throws {@link SessionExpiredError} rather than renewing. A caller that
   * catches it should send the person back to the terminal signer.
   */
  async fetch(input: string | URL | Request, init: RequestInit = {}): Promise<Response> {
    const url = input instanceof Request ? input.url : input;
    const method = init.method ?? (input instanceof Request ? input.method : "GET");
    const body = init.body ?? null;

    const signed = await this.signRequest(method, url, body);

    const headers = new Headers(init.headers);
    for (const [name, value] of Object.entries(signed)) headers.set(name, value);

    return fetch(input, { ...init, method, headers });
  }
}
