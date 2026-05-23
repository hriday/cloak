import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";
import * as m from "../math.js";

test("pick_pq happy", () => {
  assert.deepEqual(v.pick_pq({ p: "61", q: "53" }, {}), { ok: true, value: { p: 61, q: 53 } });
});

test("pick_pq rejects non-prime", () => {
  const r = v.pick_pq({ p: "60", q: "53" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /prime/i);
});

test("pick_pq rejects (2,3) — phi too small for any e", () => {
  const r = v.pick_pq({ p: "2", q: "3" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /too small|larger primes|φ|phi/i);
});

test("compute_phi wrong", () => {
  const r = v.compute_phi("3000", { p: 61, q: 53 });
  assert.equal(r.ok, false);
});

test("pick_e accepts any coprime", () => {
  assert.deepEqual(v.pick_e("17", { phi: 3120 }), { ok: true, value: { e: 17 } });
});

test("pick_e rejects non-coprime", () => {
  const r = v.pick_e("6", { phi: 3120 });
  assert.equal(r.ok, false);
});

test("decrypt happy", () => {
  const c = Number(2790n);  // pow(65, 17, 3233)
  const r = v.decrypt("65", { c, d: 2753, n: 3233 });
  assert.deepEqual(r, { ok: true, value: { m_decrypted: 65 } });
});

test("pick_pq_big happy", () => {
  const r = v.pick_pq_big({ p: "17", q: "19" }, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.p2, 17);
  assert.equal(r.value.q2, 19);
  assert.equal(r.value.n2, 323);
  assert.equal(r.value.phi2, 288);
  assert.equal(r.value.e2, 5);
  assert.equal(r.value.d2, 173);
});

test("pick_pq_big rejects p<17", () => {
  const r = v.pick_pq_big({ p: "11", q: "19" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /at least 17/);
});

test("pick_pq_big rejects p==q", () => {
  const r = v.pick_pq_big({ p: "17", q: "17" }, {});
  assert.equal(r.ok, false);
});

test("pick_pq_big rejects non-prime", () => {
  const r = v.pick_pq_big({ p: "17", q: "21" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /21.*prime|prime.*21/);
});

test("pick_sentence happy", () => {
  const r = v.pick_sentence("Hello, world!", {});
  assert.equal(r.ok, true);
  assert.equal(r.value.sentence, "Hello, world!");
  assert.equal(r.value.first_char, "H");
  assert.equal(r.value.first_code, 72);
});

test("pick_sentence rejects empty", () => {
  const r = v.pick_sentence("", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /at least one/);
});

test("pick_sentence rejects > 500 chars", () => {
  const r = v.pick_sentence("a".repeat(501), {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /500/);
});

test("pick_sentence rejects non-ASCII", () => {
  const r = v.pick_sentence("Hi 🦊", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /ASCII/i);
});

test("pick_sentence rejects newline", () => {
  const r = v.pick_sentence("Line1\nLine2", {});
  assert.equal(r.ok, false);
});

test("encrypt_sentence_head happy", () => {
  const state = { sentence: "Hi", e2: 5, n2: 323, d2: 173 };
  // 72^5 mod 323
  const expectedFirst = Number(m.modPow(72n, 5n, 323n));
  const r = v.encrypt_sentence_head(String(expectedFirst), state);
  assert.equal(r.ok, true);
  assert.equal(r.value.encrypted.length, 2);
  assert.equal(r.value.encrypted[0], expectedFirst);
});

test("encrypt_sentence_head wrong", () => {
  const state = { sentence: "Hi", e2: 5, n2: 323, d2: 173 };
  const r = v.encrypt_sentence_head("999", state);
  assert.equal(r.ok, false);
  assert.match(r.hint, /72/);
  assert.match(r.hint, /323/);
});

test("cheatState returns target step 12 with full toy + big keypair", () => {
  const { targetStepOrder, state } = v.cheatState();
  assert.equal(targetStepOrder, 12);
  // toy
  assert.equal(state.p, 3); assert.equal(state.q, 5); assert.equal(state.n, 15);
  assert.equal(state.phi, 8); assert.equal(state.e, 7); assert.equal(state.d, 7);
  assert.equal(state.m, 2); assert.equal(state.c, 8); assert.equal(state.m_decrypted, 2);
  // big keypair
  assert.equal(state.p2, 17); assert.equal(state.q2, 19); assert.equal(state.n2, 323);
  assert.equal(state.phi2, 288); assert.equal(state.e2, 5); assert.equal(state.d2, 173);
});

test("walkthroughs has entries for new actionable steps", () => {
  assert.equal(typeof v.walkthroughs.pick_pq_big, "function");
  assert.equal(typeof v.walkthroughs.encrypt_sentence_head, "function");
});

test("pick_pq_big walkthrough returns 3 string rungs", () => {
  const rungs = v.walkthroughs.pick_pq_big({});
  assert.equal(rungs.length, 3);
  rungs.forEach((r) => assert.equal(typeof r, "string"));
  // final rung must mention a concrete prime pair
  assert.match(rungs[2], /17.*19|19.*17/);
});

test("encrypt_sentence_head walkthrough computes the answer", () => {
  const state = { sentence: "Hi", e2: 5, n2: 323 };
  const rungs = v.walkthroughs.encrypt_sentence_head(state);
  assert.equal(rungs.length, 3);
  // 72^5 mod 323 — verify the final rung includes the computed value
  const expected = Number(m.modPow(72n, 5n, 323n));
  assert.match(rungs[2], new RegExp(String(expected)));
});
