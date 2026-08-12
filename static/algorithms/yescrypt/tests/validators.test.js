import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

test("info always ok with empty value", () => {
  assert.deepEqual(v.info(null, {}), { ok: true, value: {} });
});

test("memory_cost rejects empty password", () => {
  const r = v.memory_cost({ password: "", memoryMiB: 1 }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /password/i);
});

test("memory_cost rejects non-printable-ASCII password", () => {
  const r = v.memory_cost({ password: "pässwörd", memoryMiB: 1 }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /ASCII/);
});

test("memory_cost rejects memory size not in the allowed list", () => {
  const r = v.memory_cost({ password: "hunter2", memoryMiB: 3 }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /1, 4, 16, 64/);
});

test("memory_cost happy path writes ys_* state keys", () => {
  const r = v.memory_cost({ password: "hunter2", memoryMiB: 1 }, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.ys_password, "hunter2");
  assert.equal(r.value.ys_memory_mib, 1);
  assert.equal(r.value.ys_blocks, 1024);
  assert.equal(r.value.ys_bytes_touched, 2 * 1024 * 1024);
  assert.match(r.value.ys_digest, /^[0-9a-f]{32}$/);
  assert.equal(typeof r.value.ys_ms, "number");
  assert.equal(r.value.ys_cited_real_ms, 3);
});

test("walkthroughs cover memory_cost", () => {
  const lines = v.walkthroughs.memory_cost({});
  assert.ok(Array.isArray(lines) && lines.length >= 2);
});
