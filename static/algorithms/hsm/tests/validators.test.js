import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

test("hsm_operation rejects missing op", async () => {
  const r = await v.hsm_operation({ message: "hi" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /sign|verify/i);
});

test("hsm_operation rejects empty message", async () => {
  const r = await v.hsm_operation({ op: "sign", message: "" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /at least one|empty/i);
});

test("hsm_operation rejects verify without signature", async () => {
  const r = await v.hsm_operation({ op: "verify", message: "hi" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /signature/i);
});

test("hsm_operation sign happy (in node: validates but encryption may be skipped)", async () => {
  const r = await v.hsm_operation({ op: "sign", message: "hi" }, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.hsm_last_op, "sign");
  assert.equal(r.value.hsm_last_input, "hi");
  // hsm_last_output may be a hex sig OR an error message — both are okay
});

test("pick_hsm_message rejects empty", async () => {
  const r = await v.pick_hsm_message("", {});
  assert.equal(r.ok, false);
});

test("info always ok", () => {
  assert.deepEqual(v.info("anything", {}), { ok: true, value: {} });
});

test("walkthroughs has entries for hsm_operation", () => {
  assert.equal(typeof v.walkthroughs.hsm_operation, "function");
  const rungs = v.walkthroughs.hsm_operation({});
  assert.equal(rungs.length, 3);
  rungs.forEach((r) => assert.equal(typeof r, "string"));
});
