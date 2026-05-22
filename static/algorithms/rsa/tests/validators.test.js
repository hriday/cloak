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
