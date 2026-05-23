import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

test("pick_sym_key happy", () => {
  assert.deepEqual(v.pick_sym_key("42", {}), { ok: true, value: { h_sym_key: 42 } });
});

test("pick_sym_key rejects non-integer", () => {
  const r = v.pick_sym_key("abc", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /whole number/i);
});

test("pick_sym_key rejects negative", () => {
  const r = v.pick_sym_key("-1", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /0 to 127/);
});

test("pick_sym_key rejects > 127", () => {
  const r = v.pick_sym_key("128", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /0 to 127/);
});

test("wrap_key happy — 42^7 mod 143 = 81", () => {
  const r = v.wrap_key("81", { h_sym_key: 42 });
  assert.equal(r.ok, true);
  assert.equal(r.value.h_wrapped_key, 81);
});

test("wrap_key wrong value mentions m/e/n", () => {
  const r = v.wrap_key("999", { h_sym_key: 42 });
  assert.equal(r.ok, false);
  assert.match(r.hint, /42/);   // m
  assert.match(r.hint, /\b7\b/); // e
  assert.match(r.hint, /143/);  // n
});
