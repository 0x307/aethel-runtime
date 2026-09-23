#!/usr/bin/env node
// Generate BENCHMARKS.md from a criterion run.
//
// The table is generated, never written by hand, because a published number
// and the harness that produced it must not be able to drift apart. If you
// want to change what the table says, change what gets measured.
//
//   cargo bench -p aethel-auth --features holder --bench authority
//   node scripts/bench-report.mjs > BENCHMARKS.md
//
// Reads criterion's own estimates.json rather than parsing its console output:
// the JSON carries the median and a 95% confidence interval, so the table can
// report spread instead of a single number pretending to be exact.
//
// Requires node. Generating the report is a maintainer task; running the
// benchmarks is not, and needs nothing but cargo.

import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { execSync } from "node:child_process";
import { join } from "node:path";

const ROOT = new URL("..", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
const CRIT = join(ROOT, "target", "criterion");

function sh(cmd, fallback = "unknown") {
  try {
    return execSync(cmd, { cwd: ROOT, stdio: ["ignore", "pipe", "ignore"] })
      .toString()
      .trim();
  } catch {
    return fallback;
  }
}

/** Nanoseconds to a human figure, with the unit chosen per value. */
function fmt(ns) {
  if (ns < 1_000) return `${ns.toFixed(1)} ns`;
  if (ns < 1_000_000) return `${(ns / 1_000).toFixed(1)} µs`;
  if (ns < 1_000_000_000) return `${(ns / 1_000_000).toFixed(2)} ms`;
  return `${(ns / 1_000_000_000).toFixed(2)} s`;
}

/** Walk target/criterion/<group>/<bench>/new/estimates.json. */
function collect() {
  if (!existsSync(CRIT)) return [];
  const out = [];
  for (const group of readdirSync(CRIT)) {
    const gdir = join(CRIT, group);
    if (!statSync(gdir).isDirectory() || group === "report") continue;
    for (const bench of readdirSync(gdir)) {
      const est = join(gdir, bench, "new", "estimates.json");
      if (!existsSync(est)) continue;
      const j = JSON.parse(readFileSync(est, "utf8"));

      // Criterion also records how far this run moved from the previous one,
      // as a fraction, in change/estimates.json. That number is the whole
      // stability story: the confidence interval above measures noise *within*
      // a run and is blind to the machine getting hotter between them.
      let drift = null;
      const chg = join(gdir, bench, "change", "estimates.json");
      if (existsSync(chg)) {
        try {
          drift = JSON.parse(readFileSync(chg, "utf8")).median.point_estimate;
        } catch {
          drift = null;
        }
      }

      out.push({
        group,
        bench,
        median: j.median.point_estimate,
        lo: j.median.confidence_interval.lower_bound,
        hi: j.median.confidence_interval.upper_bound,
        drift,
        mtime: statSync(est).mtimeMs,
      });
    }
  }
  return out;
}

// ── Only publish what this run measured ──────────────────────────────────────
//
// criterion never deletes results. A benchmark that is removed, renamed, or
// put behind a feature leaves its last numbers in target/criterion forever,
// and a naive reader of that directory publishes them as though they were
// measured today.
//
// That is not hypothetical: gating the hybrid behind a feature (0X3-194) left
// three stale entries that the first regenerated table published, dated the
// previous afternoon, for a group the run had not executed.
//
// Benchmarks within one run finish seconds apart. Two hours is far wider than
// any suite here takes and far narrower than the gap to a previous session.
//
// The limit of this heuristic, stated rather than discovered: two runs with
// *different feature sets* minutes apart are not distinguishable by mtime, so
// switching features and regenerating can still publish the earlier set.
// Clear `target/criterion` when changing which benchmarks exist. Whatever is
// excluded is printed to stderr, so the failure is at least visible.
const STALE_AFTER_MS = 2 * 60 * 60 * 1000;
const all = collect();
const newest = all.length ? Math.max(...all.map((r) => r.mtime)) : 0;
const stale = all.filter((r) => newest - r.mtime > STALE_AFTER_MS);
const rows = all.filter((r) => newest - r.mtime <= STALE_AFTER_MS);

if (stale.length) {
  // Loud, on stderr, because a silently dropped benchmark is the same class
  // of problem as a silently published one.
  console.error(
    `note: ignoring ${stale.length} stale result(s) from an earlier run:\n` +
      stale.map((r) => `  ${r.group}/${r.bench}`).join("\n")
  );
}

if (rows.length === 0) {
  console.error(
    "No criterion results found under target/criterion.\n" +
      "Run `cargo bench -p aethel-auth --features holder --bench authority` first."
  );
  process.exit(1);
}

// Absent session results mean the run did not measure the per-request path,
// which is the one operation this layer exists to make cheap. A table without
// it describes everything except the point. Refuse rather than emit it.
if (!rows.some((r) => r.group === "session")) {
  console.error(
    "No session results found, so this run did not measure the per-request\n" +
      "path. Re-run `cargo bench -p aethel-auth --features holder --bench authority`."
  );
  process.exit(1);
}

const version = (readFileSync(join(ROOT, "Cargo.toml"), "utf8").match(
  /^version\s*=\s*"([^"]+)"/m
) || [, "unknown"])[1];

const commit = sh("git rev-parse --short HEAD");
const dirty = sh("git status --porcelain") !== "" ? " (working tree dirty)" : "";
const rustc = sh("rustc --version");
const date = new Date().toISOString().slice(0, 10);

let cpu = "unknown";
if (process.platform === "win32") {
  // Not `wmic`: it is deprecated and absent on current Windows, and returns
  // an empty string rather than failing, so the report would have quietly
  // said "unknown" forever.
  cpu =
    sh(
      'powershell -NoProfile -Command "(Get-CimInstance Win32_Processor).Name"',
      ""
    ).trim() || "unknown";
} else if (process.platform === "linux") {
  cpu = sh("grep -m1 'model name' /proc/cpuinfo", "").split(":").slice(1).join(":").trim();
} else if (process.platform === "darwin") {
  cpu = sh("sysctl -n machdep.cpu.brand_string");
}

const groups = [...new Set(rows.map((r) => r.group))].sort();

// ── Measurement stability ────────────────────────────────────────────────────
//
// A benchmark that moved between two runs of unchanged code measured the
// machine, not the code. This is the check that makes that visible in the
// document instead of only in whoever happened to run it twice.
//
// 5% is the threshold below which a figure is worth quoting. Above it, the
// number is a property of the conditions as much as of the code.
const DRIFT_LIMIT = 0.05;
const withDrift = rows.filter((r) => r.drift !== null);
const drifted = withDrift.filter((r) => Math.abs(r.drift) > DRIFT_LIMIT);
const worst = withDrift.length
  ? withDrift.reduce((a, b) => (Math.abs(b.drift) > Math.abs(a.drift) ? b : a))
  : null;
// A third of the suite moving is not a code change, it is the environment.
const UNSTABLE_RATIO = 0.33;
const unstable = withDrift.length > 0 && drifted.length / withDrift.length > UNSTABLE_RATIO;
const pct = (d) => `${d >= 0 ? "+" : ""}${(d * 100).toFixed(1)}%`;

let md = `# Benchmarks
${
  unstable
    ? `
> [!WARNING]
> **These figures are not stable on the machine that produced them.**
> ${drifted.length} of ${withDrift.length} benchmarks moved more than
> ${(DRIFT_LIMIT * 100).toFixed(0)}% against the previous run of the same code,
> the worst by **${pct(worst.drift)}** (\`${worst.group}/${worst.bench}\`).
>
> Treat the absolute numbers below as indicative only. Comparisons *within* a
> single run remain meaningful, because every operation throttles together —
> so "A is twice B" survives what "A is 29.8 ms" does not.
>
> See **Measurement stability** below.
`
    : ""
}

Generated by \`scripts/bench-report.mjs\` from a criterion run. **Do not edit
by hand** — a published number and the harness that produced it must not be
able to drift apart.

Reproduce:

\`\`\`bash
cargo bench -p aethel-auth --features holder --bench authority
node scripts/bench-report.mjs > BENCHMARKS.md
\`\`\`

## Provenance

| | |
|---|---|
| Crate version | \`${version}\` |
| Commit | \`${commit}\`${dirty} |
| Date | ${date} |
| Toolchain | ${rustc} |
| CPU | ${cpu} |
| Profile | \`[profile.bench]\`: \`opt-level = 3\`, \`lto = true\`, \`codegen-units = 1\` |
| Harness | [\`crates/aethel-auth/benches/authority.rs\`](crates/aethel-auth/benches/authority.rs) |

**The profile matters.** This crate's \`[profile.release]\` is \`opt-level = "z"\`,
because what it ships is size-constrained. Benchmarks use a separate
\`[profile.bench]\` at \`opt-level = 3\`. A figure measured under \`"z"\` describes
a build nobody benchmarks for, and \`pqc-sig\` published exactly that before its
profile was split out.

\`overflow-checks = false\` matches release, so the numbers describe what ships.
Worth recording that \`aethel-core\` makes the opposite choice and keeps them on
"for safety" — two crates in one family disagreeing about whether release
arithmetic is checked, and this crate is the one that authorises spending.

## What these are

Times are the **median** with a 95% confidence interval.

### The ratio is the point

| Path | Frequency | Cost driver |
|---|---|---|
| \`session/verify_request\` | every request | HMAC-SHA-256 and a store lookup |
| \`login/verify_login\` | once per session | ML-DSA-65 verification |
| \`statements/*\` | rarely | ML-DSA-65 verification |

A session exists to buy the first row being much cheaper than the second. If
that gap ever closes, the session stops paying for the deviation it represents
— it departs from per-interaction unlinkability, and cost is the entire
justification. This table is how that stays checked rather than assumed.

### Nonces are cycled, for the same reason messages are elsewhere

Every operation that claims a nonce is benched over 64 distinct ones. A
replayed nonce takes the refusal path, which is cheaper and is not what the
operation costs. \`pqc-sig\` learned this the other way round: a fixed message
froze a rejection loop and produced a stable, repeatable, wrong number.

### Requires the \`holder\` feature

Verifying a statement means having one, and building one is the holder's job.
Declared as \`required-features\` on the bench target, so an attempt without it
fails to select the target rather than measuring a subset and reporting
success.

## Results

`;

for (const g of groups) {
  md += `### ${g}\n\n| Operation | Median | 95% CI |\n|---|---:|---|\n`;
  for (const r of rows.filter((x) => x.group === g).sort((a, b) => a.bench.localeCompare(b.bench))) {
    md += `| \`${r.bench}\` | ${fmt(r.median)} | ${fmt(r.lo)} – ${fmt(r.hi)} |\n`;
  }
  md += "\n";
}

md += `## One result that needs explaining

At ML-DSA-65 and -87, \`sign_ctx_deterministic\` is faster than
\`sign_deterministic\` — about 35% at 65. Adding a context cannot make signing
cheaper, so the figure looks wrong, and the explanation is that the two are
not the same code path:

\`\`\`rust
sign_deterministic:     self.signing_key.try_sign(message)
sign_ctx_deterministic: self.signing_key.expanded_key().sign_deterministic(message, ctx)
\`\`\`

The context variant goes through \`expanded_key()\` and the plain one does not.
So the gap is an artifact of which underlying API each wrapper reaches for,
and \`sign_deterministic\` is leaving time on the table rather than
\`sign_ctx_deterministic\` performing magic. ML-DSA-44 shows no such gap.

This is recorded rather than quietly smoothed over because it is the kind of
number a reader is right to distrust, and because it is a real finding: it was
invisible until these benchmarks existed.
`;

md += `## Measurement stability

Criterion's confidence intervals above measure variation **within** a run.
They say nothing about variation **between** runs, which on a thermally
constrained machine is much larger — and which looks identical to a real
regression.

This section reports the shift against the previous run of this suite. If the
code did not change in between, everything here is measurement noise by
definition.

${
  withDrift.length === 0
    ? "No previous run to compare against. Run `cargo bench` twice to populate this."
    : unstable
      ? `**Unstable.** ${drifted.length} of ${withDrift.length} benchmarks moved more than ${(DRIFT_LIMIT * 100).toFixed(0)}% against the previous run.

| Benchmark | Shift |
|---|---:|
${drifted
  .sort((a, b) => Math.abs(b.drift) - Math.abs(a.drift))
  .slice(0, 12)
  .map((r) => `| \`${r.group}/${r.bench}\` | ${pct(r.drift)} |`)
  .join("\n")}

A laptop under sustained benchmark load throttles, and the effect compounds
across a long suite: the operations measured last are measured on the hottest
silicon. Publishing an absolute figure taken this way states a property of the
afternoon rather than of the code.

**For figures intended to be quoted**, regenerate on a machine with a stable
clock: a desktop or server part with thermal headroom, idle, with frequency
scaling pinned. The numbers will differ, and they will mean something.`
      : drifted.length === 0
        ? `**Stable.** No benchmark moved more than ${(DRIFT_LIMIT * 100).toFixed(0)}% against the previous run${worst ? `; the largest shift was ${pct(worst.drift)} (\`${worst.group}/${worst.bench}\`)` : ""}.`
        : `**Mixed.** ${drifted.length} of ${withDrift.length} benchmarks moved more than ${(DRIFT_LIMIT * 100).toFixed(0)}% against the previous run, the worst by **${pct(worst.drift)}** (\`${worst.group}/${worst.bench}\`). That is below the ${(UNSTABLE_RATIO * 100).toFixed(0)}% of the suite it would take to call the whole run unstable, but it is not nothing.

| Benchmark | Shift |
|---|---:|
${drifted
  .sort((a, b) => Math.abs(b.drift) - Math.abs(a.drift))
  .slice(0, 12)
  .map((r) => `| \`${r.group}/${r.bench}\` | ${pct(r.drift)} |`)
  .join("\n")}

With the code unchanged between runs, shifts of this size come from the
machine or from the harness, not from the crate. Read these rows as this
suite's resolution limit rather than as results.`
}

## What is not measured

Stated so the absence is not mistaken for a result.

- **\`aethel-vault\`.** The other half of this workspace — the agent-held
  spending vault — has no benchmarks. This table covers \`aethel-auth\` only.
- **The browser client.** \`clients/browser-session/\` computes the same
  canonical binding in TypeScript on WebCrypto. Its cost is a different
  runtime's problem and is not measured here; the cross-language test proves
  the two agree on bytes, not on time.
- **Store latency.** Every figure uses the in-process store, which is a test
  double. A real deployment puts a network round trip inside
  \`verify_request\` and \`verify_login\`, and that will dominate everything in
  this table. These numbers are the *floor*, not the budget.
- **Contention.** Single-threaded throughout. The nonce store's atomic
  test-and-set is the obvious contention point under concurrency and is not
  exercised.
- **WASM.** Every figure is native. The shipped \`opt-level = "z"\` build will
  be slower, and by how much this suite does not say.
- **Constant-time behaviour.** A median and a confidence interval say nothing
  about whether timing varies with secret data. The MAC comparison is
  constant-time by construction (\`subtle\`); establishing that needs a
  different tool than this table.
- **Comparison against anything.** No classical baseline, no aggregate. An
  aggregate hides which operation moved.
`;

process.stdout.write(md);
console.error(`ok: ${rows.length} benchmarks across ${groups.length} groups`);
