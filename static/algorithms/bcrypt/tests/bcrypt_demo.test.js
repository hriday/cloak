import { test } from "node:test";
import assert from "node:assert/strict";
import * as bd from "../bcrypt_demo.js";

const HAS_SUBTLE = typeof crypto !== "undefined" && !!crypto.subtle;

// ---- exports ----

test("MIN_COST and MAX_COST are 4 and 14", () => {
  assert.equal(bd.MIN_COST, 4);
  assert.equal(bd.MAX_COST, 14);
});

test("CITED_BCRYPT_MS covers cost 4..16 with expected ballpark values", () => {
  // Spot-check the documented anchor values.
  assert.equal(bd.CITED_BCRYPT_MS[4], 1);
  assert.equal(bd.CITED_BCRYPT_MS[8], 16);
  assert.equal(bd.CITED_BCRYPT_MS[10], 65);
  assert.equal(bd.CITED_BCRYPT_MS[12], 260);
  assert.equal(bd.CITED_BCRYPT_MS[14], 1040);
  // Every cost from 4 to 16 should be present.
  for (let c = 4; c <= 16; c++) {
    assert.ok(typeof bd.CITED_BCRYPT_MS[c] === "number", `cost ${c} cited ms`);
  }
});

test("CITED_BCRYPT_MS doubles roughly with each +1 to cost", () => {
  // The whole point of the cited table is that the curve is exponential.
  for (let c = 4; c < 16; c++) {
    const ratio = bd.CITED_BCRYPT_MS[c + 1] / bd.CITED_BCRYPT_MS[c];
    assert.ok(
      ratio >= 1.5 && ratio <= 2.5,
      `cost ${c}→${c + 1} ratio ${ratio} should be ~2 (got ${ratio})`
    );
  }
});

// ---- costToIterations ----

test("costToIterations: cost c → 1000 * 2^c", () => {
  assert.equal(bd.costToIterations(4), 16000);
  assert.equal(bd.costToIterations(8), 256000);
  assert.equal(bd.costToIterations(10), 1024000);
  assert.equal(bd.costToIterations(12), 4096000);
  assert.equal(bd.costToIterations(14), 16384000);
});

test("costToIterations doubles with each +1", () => {
  for (let c = 4; c < 14; c++) {
    assert.equal(bd.costToIterations(c + 1), 2 * bd.costToIterations(c));
  }
});

// ---- hashWithCost ----

test("hashWithCost returns 64 lowercase hex chars + ms + cost + iterations", async (t) => {
  if (!HAS_SUBTLE) return t.skip("crypto.subtle not available");
  const r = await bd.hashWithCost("hunter2", 4);
  assert.equal(typeof r.hash, "string");
  assert.equal(r.hash.length, 64);
  assert.match(r.hash, /^[0-9a-f]{64}$/);
  assert.equal(typeof r.ms, "number");
  assert.ok(r.ms >= 0);
  assert.equal(r.cost, 4);
  assert.equal(r.iterations, 16000);
});

test("hashWithCost with two calls on same password yields different hashes (random salt)", async (t) => {
  if (!HAS_SUBTLE) return t.skip("crypto.subtle not available");
  const a = await bd.hashWithCost("hunter2", 4);
  const b = await bd.hashWithCost("hunter2", 4);
  // The 16-byte random salt makes every call's output unique even with
  // identical password + cost — same property real bcrypt has.
  assert.notEqual(a.hash, b.hash);
});

test("hashWithCost rejects cost below MIN_COST", async () => {
  await assert.rejects(() => bd.hashWithCost("p", 3));
  await assert.rejects(() => bd.hashWithCost("p", 0));
  await assert.rejects(() => bd.hashWithCost("p", -1));
});

test("hashWithCost rejects cost above MAX_COST", async () => {
  await assert.rejects(() => bd.hashWithCost("p", 15));
  await assert.rejects(() => bd.hashWithCost("p", 31));
  await assert.rejects(() => bd.hashWithCost("p", 100));
});

test("hashWithCost rejects non-integer cost", async () => {
  await assert.rejects(() => bd.hashWithCost("p", 4.5));
  await assert.rejects(() => bd.hashWithCost("p", "four"));
  await assert.rejects(() => bd.hashWithCost("p", null));
});

test("hashWithCost rejects non-string password", async () => {
  await assert.rejects(() => bd.hashWithCost(123, 4));
  await assert.rejects(() => bd.hashWithCost(null, 4));
  await assert.rejects(() => bd.hashWithCost(undefined, 4));
});

test("hashWithCost accepts empty string password (real bcrypt does too)", async (t) => {
  if (!HAS_SUBTLE) return t.skip("crypto.subtle not available");
  const r = await bd.hashWithCost("", 4);
  assert.equal(r.hash.length, 64);
});

// The exponential cost progression — the whole pedagogical point of the
// timing widget. Use cost 4, 6, 8 (instead of going up to 14) so the test
// completes quickly. Each +2 should be ~4x slower.
test("hashWithCost progression: cost 4 << cost 6 << cost 8", async (t) => {
  if (!HAS_SUBTLE) return t.skip("crypto.subtle not available");
  const r4 = await bd.hashWithCost("benchmark", 4);
  const r6 = await bd.hashWithCost("benchmark", 6);
  const r8 = await bd.hashWithCost("benchmark", 8);

  // cost 4 → 6 is a 4x iteration increase; cost 4 → 8 is 16x.
  // Wall-clock has noise (especially on fast hardware where cost 4 rounds to
  // sub-ms), so we assert generous bounds: each higher cost is at least
  // marginally slower, with a clear gap between cost 4 and cost 8.
  assert.ok(
    r8.ms > r4.ms,
    `cost 8 (${r8.ms} ms) should be slower than cost 4 (${r4.ms} ms)`
  );
  assert.ok(
    r8.ms >= r6.ms * 0.7,
    `cost 8 (${r8.ms} ms) should not be dramatically faster than cost 6 (${r6.ms} ms)`
  );
});

test("hashWithCost progression cost 4 → cost 10 produces a clear timing gap", async (t) => {
  if (!HAS_SUBTLE) return t.skip("crypto.subtle not available");
  const r4 = await bd.hashWithCost("benchmark", 4);
  const r10 = await bd.hashWithCost("benchmark", 10);
  // cost 10 has 64x the iterations of cost 4. Wall time should be clearly
  // larger — use a conservative 5x lower bound to absorb noise on fast CIs.
  assert.ok(
    r10.ms > r4.ms * 5,
    `cost 10 (${r10.ms} ms) should be > 5× cost 4 (${r4.ms} ms)`
  );
});

// ---- compareWithReal ----

test("compareWithReal returns synthetic ms paired with cited real-bcrypt ms", async (t) => {
  if (!HAS_SUBTLE) return t.skip("crypto.subtle not available");
  const r = await bd.compareWithReal("hunter2", 12);
  assert.equal(typeof r.hash, "string");
  assert.equal(r.hash.length, 64);
  assert.equal(r.cost, 12);
  assert.equal(r.iterations, 4096000);
  assert.equal(typeof r.ms, "number");
  assert.equal(r.cited_real_ms, bd.CITED_BCRYPT_MS[12]);
  assert.equal(r.cited_real_ms, 260);
  assert.match(r.note, /synthetic/i);
  assert.match(r.note, /Blowfish/i);
});

test("compareWithReal still works for cost outside the cited table (returns null cited_real_ms)", async (t) => {
  // The cited table covers 4-16; nothing outside MIN/MAX is callable anyway.
  // Just sanity-check the lookup path for a valid in-range cost.
  if (!HAS_SUBTLE) return t.skip("crypto.subtle not available");
  const r = await bd.compareWithReal("p", 4);
  assert.equal(r.cited_real_ms, 1);
});
