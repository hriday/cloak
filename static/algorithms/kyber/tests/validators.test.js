import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

// The canonical answer derived from the shared frozen vectors.
const ANSWER = v._CANONICAL_V0;

// ---- encap_coefficient ----------------------------------------------------

test("encap_coefficient is pinned to v[0] = 180 (lesson seed cloak-kyber-v1, bit=1)", () => {
  // If this fails, the toy_vectors drifted — update the lesson prose with
  // the new number and check no other expectations regressed.
  assert.equal(ANSWER, 180);
});

test("encap_coefficient accepts the canonical answer as integer", () => {
  const r = v.encap_coefficient(ANSWER, {});
  assert.equal(r.ok, true);
  assert.deepEqual(r.value, { kyber_v_coeff: ANSWER });
});

test("encap_coefficient accepts the canonical answer as string", () => {
  const r = v.encap_coefficient(String(ANSWER), {});
  assert.equal(r.ok, true);
});

test("encap_coefficient accepts the canonical answer with surrounding whitespace", () => {
  const r = v.encap_coefficient("  " + ANSWER + "  ", {});
  assert.equal(r.ok, true);
});

test("encap_coefficient rejects empty input with an integer-prompt hint", () => {
  const r = v.encap_coefficient("", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /integer/i);
});

test("encap_coefficient rejects unparseable 'abc'", () => {
  const r = v.encap_coefficient("abc", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /integer/i);
});

test("encap_coefficient rejects floats like '180.0'", () => {
  const r = v.encap_coefficient("180.0", {});
  assert.equal(r.ok, false);
});

test("encap_coefficient rejects -1 (out of range, below 0)", () => {
  const r = v.encap_coefficient("-1", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /0 to 256|0–256/);
});

test("encap_coefficient rejects 257 (out of range, equals q)", () => {
  const r = v.encap_coefficient("257", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /0 to 256|0–256/);
});

test("encap_coefficient rejects 500 with the out-of-range hint", () => {
  const r = v.encap_coefficient("500", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /0 to 256|0–256/);
});

test("encap_coefficient rejects a value off-by-one with the dot-product walkthrough hint", () => {
  const r = v.encap_coefficient(String(ANSWER - 1), {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /t/);
  assert.match(r.hint, /r/);
  assert.match(r.hint, /128/);
  // Hint reveals the expected answer.
  assert.match(r.hint, new RegExp("Expected: " + ANSWER));
});

test("encap_coefficient rejects a value off-by-q (180 + 257 - 257 = 180, but +q wraps)", () => {
  // The user might submit (180 + 257) mod 257 = 180; already covered by happy path.
  // More relevant: a user who forgot to reduce mod q sends a different
  // value entirely. Use a deliberate wrong: 0.
  const r = v.encap_coefficient("0", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /Expected/);
});

test("encap_coefficient accepts integer input 180 (numeric type)", () => {
  const r = v.encap_coefficient(180, {});
  assert.equal(r.ok, true);
});

test("encap_coefficient accepts null/undefined input by treating as empty", () => {
  assert.equal(v.encap_coefficient(null, {}).ok, false);
  assert.equal(v.encap_coefficient(undefined, {}).ok, false);
});

// ---- info -----------------------------------------------------------------

test("info always ok with empty value", () => {
  assert.deepEqual(v.info("anything", {}), { ok: true, value: {} });
  assert.deepEqual(v.info(null, {}), { ok: true, value: {} });
});

// ---- walkthroughs ---------------------------------------------------------

test("walkthroughs.encap_coefficient returns 3 non-empty string rungs", () => {
  assert.equal(typeof v.walkthroughs.encap_coefficient, "function");
  const rungs = v.walkthroughs.encap_coefficient({});
  assert.equal(rungs.length, 3);
  rungs.forEach((rung) => {
    assert.equal(typeof rung, "string");
    assert.ok(rung.length > 0);
  });
});

test("walkthroughs.encap_coefficient rungs mention 128 (the message coefficient)", () => {
  const rungs = v.walkthroughs.encap_coefficient({});
  const all = rungs.join("\n");
  assert.match(all, /128/);
});

test("walkthroughs.encap_coefficient rungs reveal the expected answer in the last rung", () => {
  const rungs = v.walkthroughs.encap_coefficient({});
  assert.match(rungs[2], new RegExp(String(ANSWER)));
});

test("walkthroughs.encap_coefficient rungs reference both t and r in rung 2", () => {
  const rungs = v.walkthroughs.encap_coefficient({});
  assert.match(rungs[1], /t/);
  assert.match(rungs[1], /r/);
});
