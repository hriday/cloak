import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

test("dh_compute happy: accepts 2", () => {
  const r = v.dh_compute("2", {});
  assert.equal(r.ok, true);
  assert.deepEqual(r.value, { dh_alice_secret: 6, dh_bob_secret: 15, dh_shared: 2 });
});

test("dh_compute happy: accepts numeric 2", () => {
  const r = v.dh_compute(2, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.dh_shared, 2);
});

test("dh_compute happy: trims whitespace", () => {
  const r = v.dh_compute("  2  ", {});
  assert.equal(r.ok, true);
  assert.equal(r.value.dh_shared, 2);
});

test("dh_compute rejects empty", () => {
  const r = v.dh_compute("", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /whole number/i);
});

test("dh_compute rejects non-integer string", () => {
  const r = v.dh_compute("abc", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /whole number/i);
});

test("dh_compute rejects wrong value with hinted walk", () => {
  const r = v.dh_compute("3", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /19\^6 mod 23/);
});

test("dh_compute rejects negative with range hint", () => {
  const r = v.dh_compute("-1", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /\[0, 22\]/);
});

test("dh_compute rejects out-of-range value", () => {
  const r = v.dh_compute("23", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /\[0, 22\]/);
});

test("dh_compute writes all three state keys", () => {
  const r = v.dh_compute("2", {});
  assert.equal(r.ok, true);
  assert.ok("dh_alice_secret" in r.value);
  assert.ok("dh_bob_secret" in r.value);
  assert.ok("dh_shared" in r.value);
});

test("info validator is a pass-through", () => {
  const r = v.info("anything", { foo: "bar" });
  assert.deepEqual(r, { ok: true, value: {} });
});

test("walkthroughs has dh_compute entry returning 3 rungs", () => {
  assert.equal(typeof v.walkthroughs.dh_compute, "function");
  const rungs = v.walkthroughs.dh_compute({});
  assert.equal(rungs.length, 3);
  rungs.forEach((r) => assert.equal(typeof r, "string"));
});

test("walkthrough final rung contains the answer 2", () => {
  const rungs = v.walkthroughs.dh_compute({});
  assert.match(rungs[2], /\b2\b/);
});

test("walkthrough middle rung shows the modular-exponentiation work", () => {
  const rungs = v.walkthroughs.dh_compute({});
  // intermediates 16 (19² mod 23) and 3 (19⁴ mod 23) must appear
  assert.match(rungs[1], /16/);
  assert.match(rungs[1], /\b3\b/);
});
