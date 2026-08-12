import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

test("full_script uses the $gy$ prefix via ctypes", () => {
  const out = c.full_script({});
  assert.match(out, /import ctypes/);
  assert.match(out, /\$gy\$j9T\$/);
});

test("full_script explains a GOST-less libxcrypt instead of crashing", () => {
  const out = c.full_script({});
  assert.match(out, /GOST/);
  assert.match(out, /startswith\("\*"\)/);
});

test("full_script verifies right and wrong passwords", () => {
  const out = c.full_script({});
  assert.match(out, /wrong-password/);
});
