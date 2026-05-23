import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

test("pick_pq happy", () => {
  assert.deepEqual(v.pick_pq({ p: "61", q: "53" }, {}), { ok: true, value: { p: 61, q: 53 } });
});

test("pick_pq rejects non-prime", () => {
  const r = v.pick_pq({ p: "60", q: "53" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /prime/i);
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
