import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

const PT = 0x42, CT = 0x72;  // toyEncrypt(0x42, 0x10, 0x20) = 0x72

test("mitm_attack happy — canonical (0x10, 0x20)", () => {
  const r = v.mitm_attack({ k1: "0x10", k2: "0x20" }, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.td_k1, 0x10);
  assert.equal(r.value.td_k2, 0x20);
});

test("mitm_attack happy — alternative valid pair", () => {
  // toyEncrypt(0x42, 0x00, 0x32) = (0x42 ^ 0 ^ 0x32) = 0x70. Not 0x72. Find one that works:
  // K1 ^ K2 must equal 0x10 ^ 0x20 = 0x30. So (0x01, 0x31) is valid.
  const r = v.mitm_attack({ k1: "0x01", k2: "0x31" }, {});
  assert.equal(r.ok, true);
});

test("mitm_attack accepts decimal", () => {
  // 16 = 0x10, 32 = 0x20
  const r = v.mitm_attack({ k1: "16", k2: "32" }, {});
  assert.equal(r.ok, true);
});

test("mitm_attack rejects wrong pair", () => {
  const r = v.mitm_attack({ k1: "0x00", k2: "0x00" }, {});
  assert.equal(r.ok, false);
  // Hint should mention what to find
  assert.match(r.hint, /k1|K1|XOR|attack/i);
});

test("mitm_attack rejects garbage", () => {
  const r = v.mitm_attack({ k1: "foo", k2: "0x10" }, {});
  assert.equal(r.ok, false);
});

test("mitm_attack rejects out of range", () => {
  const r = v.mitm_attack({ k1: "999", k2: "0x10" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /0.*255/);
});

test("pick_3des_message happy", () => {
  const r = v.pick_3des_message("hi", {});
  assert.equal(r.ok, true);
  assert.equal(r.value.td_message, "hi");
});

test("pick_3des_message rejects empty", () => {
  const r = v.pick_3des_message("", {});
  assert.equal(r.ok, false);
});

test("pick_3des_message rejects >500", () => {
  const r = v.pick_3des_message("a".repeat(501), {});
  assert.equal(r.ok, false);
});

test("pick_3des_message rejects non-ASCII", () => {
  const r = v.pick_3des_message("hi 🦊", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /ASCII/i);
});

test("info always ok", () => {
  assert.deepEqual(v.info("anything", {}), { ok: true, value: {} });
});

test("walkthroughs.mitm_attack returns 3 string rungs ending in a valid pair", () => {
  const rungs = v.walkthroughs.mitm_attack({});
  assert.equal(rungs.length, 3);
  rungs.forEach((r) => assert.equal(typeof r, "string"));
  // Final rung should mention SOME valid pair like (0x10, 0x20) or similar
  assert.match(rungs[2], /0x[0-9A-Fa-f]{2}/);
});
