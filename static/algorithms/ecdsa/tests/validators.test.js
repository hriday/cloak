import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

test("recover_k accepts 3 (canonical k)", () => {
  const r = v.recover_k("3", {});
  assert.equal(r.ok, true);
  assert.equal(r.value.ecdsa_recovered_k, 3);
  assert.equal(r.value.ecdsa_recovered_d, 7);
});

test("recover_k accepts 16 (= 3 + 13)", () => {
  const r = v.recover_k("16", {});
  assert.equal(r.ok, true);
  assert.equal(r.value.ecdsa_recovered_k, 3);
  assert.equal(r.value.ecdsa_recovered_d, 7);
});

test("recover_k accepts -10 (≡ 3 mod 13)", () => {
  const r = v.recover_k("-10", {});
  assert.equal(r.ok, true);
  assert.equal(r.value.ecdsa_recovered_k, 3);
  assert.equal(r.value.ecdsa_recovered_d, 7);
});

test("recover_k accepts 29 (= 3 + 2·13)", () => {
  const r = v.recover_k("29", {});
  assert.equal(r.ok, true);
  assert.equal(r.value.ecdsa_recovered_k, 3);
});

test("recover_k rejects 0 with a 'no modular inverse' hint", () => {
  const r = v.recover_k("0", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /modular inverse|0/i);
});

test("recover_k rejects 13 (≡ 0 mod 13) with the same hint", () => {
  const r = v.recover_k("13", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /modular inverse|0/i);
});

test("recover_k rejects 4 (wrong residue) with a useful hint", () => {
  const r = v.recover_k("4", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /e₁|e1|reduce|mod/i);
});

test("recover_k rejects empty string", () => {
  const r = v.recover_k("", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /integer/i);
});

test("recover_k rejects non-integer string", () => {
  const r = v.recover_k("foo", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /integer/i);
});

test("recover_k rejects a decimal", () => {
  const r = v.recover_k("3.5", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /integer/i);
});

test("recover_k rejects null/undefined", () => {
  assert.equal(v.recover_k(null, {}).ok, false);
  assert.equal(v.recover_k(undefined, {}).ok, false);
});

test("recover_k writes both k and d into state", () => {
  const r = v.recover_k("3", {});
  assert.deepEqual(r.value, { ecdsa_recovered_k: 3, ecdsa_recovered_d: 7 });
});

test("SCENARIO constants match the spec", () => {
  assert.equal(v.SCENARIO.d, 7);
  assert.equal(v.SCENARIO.k, 3);
  assert.equal(v.SCENARIO.r, 8);
  assert.equal(v.SCENARIO.e1, 4);
  assert.equal(v.SCENARIO.s1, 7);
  assert.equal(v.SCENARIO.e2, 10);
  assert.equal(v.SCENARIO.s2, 9);
  assert.equal(v.SCENARIO.n, 13);
});

test("info always ok", () => {
  assert.deepEqual(v.info("anything", {}), { ok: true, value: {} });
});

test("walkthroughs.recover_k returns 3 non-empty string rungs", () => {
  assert.equal(typeof v.walkthroughs.recover_k, "function");
  const rungs = v.walkthroughs.recover_k({});
  assert.ok(Array.isArray(rungs));
  assert.equal(rungs.length, 3);
  rungs.forEach((r) => {
    assert.equal(typeof r, "string");
    assert.ok(r.length > 0);
  });
});

test("walkthroughs.recover_k final rung reveals k=3 and d=7", () => {
  const rungs = v.walkthroughs.recover_k({});
  assert.match(rungs[2], /k = 3/);
  assert.match(rungs[2], /d = 7/);
});

test("walkthroughs.recover_k middle rung walks the modular arithmetic", () => {
  const rungs = v.walkthroughs.recover_k({});
  // Middle rung must mention reducing e₁ − e₂ and s₁ − s₂ mod 13, plus the
  // inverse step. Don't be too prescriptive about formatting.
  assert.match(rungs[1], /7/);   // e1 - e2 reduced
  assert.match(rungs[1], /11/);  // s1 - s2 reduced
  assert.match(rungs[1], /6/);   // 11^{-1}
});
