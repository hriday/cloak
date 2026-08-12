import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

test("full_script loads libcrypt via ctypes and uses the $y$ prefix", () => {
  const out = c.full_script({});
  assert.match(out, /import ctypes/);
  assert.match(out, /libcrypt\.so\.1/);
  assert.match(out, /\$y\$j9T\$/);
});

test("full_script embeds the learner's password, defaulting when absent", () => {
  assert.match(c.full_script({ ys_password: "hunter2" }), /"hunter2"/);
  assert.match(c.full_script({}), /correct-horse-battery-staple/);
});

test("full_script verifies right and wrong passwords", () => {
  const out = c.full_script({});
  assert.match(out, /wrong-password/);
  assert.match(out, /verify/i);
});

test("full_script handles missing libcrypt and failed hashing", () => {
  const out = c.full_script({});
  assert.match(out, /except OSError/);
  assert.match(out, /startswith\("\*"\)/);
});
