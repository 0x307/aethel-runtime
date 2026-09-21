/**
 * The bridge the Rust cross-language test drives.
 *
 * Reads a batch of request descriptions on stdin, signs each one with the
 * real {@link AethelSession}, and writes the resulting headers to stdout as
 * JSON. It computes nothing itself — every byte it emits comes from the
 * shipped client, so a bug in the client is a failing Rust test rather than
 * something this file papers over.
 *
 * Requests arrive already split into method, path, query and body, which is
 * how a server sees them off the wire. Neither side tells the other what to
 * expect: both work from the same case definition, the Rust test builds its
 * binding from its own copy, and the MAC either verifies or it does not.
 *
 * Run by `crates/aethel-auth/tests/binding_cross_language.rs`. Needs only
 * node, no install step:
 *
 *     node --experimental-strip-types test/harness.ts < cases.json
 */

import { AethelSession } from "../src/session.ts";

interface Case {
  method: string;
  path: string;
  query: string;
  body: string | null;
}

interface Input {
  audience: string;
  token: string;
  secret: string;
  expiresAt: number;
  now: number;
  cases: Case[];
}

async function readStdin(): Promise<string> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Uint8Array);
  return Buffer.concat(chunks).toString("utf8");
}

const input: Input = JSON.parse(await readStdin());

const session = await AethelSession.open({
  audience: input.audience,
  token: input.token,
  secret: input.secret,
  expiresAt: input.expiresAt,
});

// Asserted here rather than assumed, because every claim this client makes
// about a stolen cookie rests on it and nothing else in the pipeline checks.
const probe = await crypto.subtle
  .importKey("raw", new Uint8Array(32), { name: "HMAC", hash: "SHA-256" }, false, ["sign"])
  .then((k) => k.extractable);
if (probe !== false) {
  throw new Error("WebCrypto returned an extractable key where false was asked for");
}

const results = [];
for (const c of input.cases) {
  const url = input.audience + c.path + (c.query ? "?" + c.query : "");
  const headers = await session.signRequest(c.method, url, c.body, input.now);
  results.push(headers);
}

process.stdout.write(JSON.stringify({ results }));
