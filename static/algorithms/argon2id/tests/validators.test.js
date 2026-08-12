import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

test("info always ok", () => {
  assert.deepEqual(v.info(null, {}), { ok: true, value: {} });
});

test("memory_cost happy path writes a2_* keys with argon2id cited ms", () => {
  const r = v.memory_cost({ password: "hunter2", memoryMiB: 1 }, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.a2_password, "hunter2");
  assert.equal(r.value.a2_memory_mib, 1);
  assert.equal(r.value.a2_blocks, 1024);
  assert.match(r.value.a2_digest, /^[0-9a-f]{32}$/);
  assert.equal(r.value.a2_cited_real_ms, 6);
});

test("memory_cost rejects bad password and bad memory size", () => {
  assert.equal(v.memory_cost({ password: "", memoryMiB: 1 }, {}).ok, false);
  assert.equal(v.memory_cost({ password: "x", memoryMiB: 5 }, {}).ok, false);
});

test("tuning_math: 64 is correct", () => {
  const r = v.tuning_math("64", {});
  assert.equal(r.ok, true);
  assert.equal(r.value.a2_tuning_mib, 64);
});

test("tuning_math: 65536 gets the KiB-vs-MiB hint", () => {
  const r = v.tuning_math("65536", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /KiB/);
});

test("tuning_math: other numbers get the division hint; junk gets a number hint", () => {
  assert.match(v.tuning_math("128", {}).hint, /1024/);
  assert.match(v.tuning_math("banana", {}).hint, /number/i);
});

test("walkthroughs cover memory_cost and tuning_math", () => {
  assert.ok(v.walkthroughs.memory_cost({}).length >= 2);
  assert.ok(v.walkthroughs.tuning_math({}).length >= 1);
});
