import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

test("info always ok", () => {
  assert.deepEqual(v.info(null, {}), { ok: true, value: {} });
});

test("spot_difference rejects empty input", () => {
  const r = v.spot_difference("", {});
  assert.equal(r.ok, false);
});

test("spot_difference: 'salt' is wrong, hint teaches why", () => {
  const r = v.spot_difference("salt", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /salt/i);
});

test("spot_difference: 'params' is wrong, hint teaches why", () => {
  const r = v.spot_difference("params", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /j9T|param/i);
});

test("spot_difference: 'prefix-and-hash' is correct", () => {
  const r = v.spot_difference("prefix-and-hash", {});
  assert.equal(r.ok, true);
  assert.equal(r.value.gy_choice, "prefix-and-hash");
});
