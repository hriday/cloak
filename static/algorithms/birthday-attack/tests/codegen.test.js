import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

// ---------- full_script ----------

test("full_script imports hashlib, math, secrets (stdlib, no install)", () => {
  const out = c.full_script({});
  assert.match(out, /^import hashlib$/m);
  assert.match(out, /^import math$/m);
  assert.match(out, /^import secrets$/m);
});

test("full_script defines truncated_sha256 and find_collision", () => {
  const out = c.full_script({});
  assert.match(out, /def truncated_sha256\(/);
  assert.match(out, /def find_collision\(/);
  assert.match(out, /def expected_attempts\(/);
});

test("full_script computes the birthday bound 1.18 * sqrt(2^hash_bits)", () => {
  const out = c.full_script({});
  assert.match(out, /1\.18 \* math\.sqrt\(2 \*\* hash_bits\)/);
});

test("full_script truncates SHA-256 (not full SHA-256) for the search", () => {
  const out = c.full_script({});
  assert.match(out, /hashlib\.sha256\(/);
  assert.match(out, /full\[:full_bytes\]/);
});

test("full_script embeds the user's collision data from state", () => {
  const state = {
    bday_collision_a: "abc12345",
    bday_collision_b: "xyz98765",
    bday_collision_hash: "dead",
    bday_attempts: 342,
    bday_hash_bits: 16,
  };
  const out = c.full_script(state);
  assert.match(out, /abc12345/);
  assert.match(out, /xyz98765/);
  assert.match(out, /dead/);
  assert.match(out, /342/);
});

test("full_script falls back to sensible defaults when state is empty", () => {
  const out = c.full_script({});
  // The state has no bday_collision_a, so we should see the fallback inputA.
  assert.match(out, /abcd1234/);
  assert.match(out, /wxyz5678/);
  assert.match(out, /attempts/i);
});

test("full_script sweeps hash sizes 8, 16, 24 in the demo", () => {
  const out = c.full_script({});
  // The demo loop runs find_collision at multiple hash sizes.
  assert.match(out, /\(8, 16, 24\)/);
});

test("full_script prints a reference table of real-world hash sizes", () => {
  const out = c.full_script({});
  // The table includes the headline sizes: MD5 (128), SHA-256 (256).
  assert.match(out, /128/);
  assert.match(out, /256/);
  assert.match(out, /MD5/);
  assert.match(out, /SHA-256/);
});

test("full_script ends with main() and __name__ guard", () => {
  const out = c.full_script({});
  assert.match(out, /def main\(\)/);
  assert.match(out, /if __name__ == '__main__':/);
  assert.match(out, /main\(\)\s*$/);
});

test("full_script comments warn this is FOR LEARNING ONLY", () => {
  const out = c.full_script({});
  assert.match(out, /FOR LEARNING ONLY/i);
});

test("full_script comments cite the headline MD5 result", () => {
  const out = c.full_script({});
  // Sanity: the script should at least mention MD5 and the headline
  // researcher (Marc Stevens) or the 2^64 work figure.
  assert.match(out, /MD5/);
  assert.match(out, /Stevens|2\^64/);
});

// ---------- per-step stubs ----------

test("per-step stubs return empty strings", () => {
  const keys = [
    "intro",
    "the_math",
    "find_a_collision",
    "more_bits_more_work",
    "hmac_and_other_defenses",
    "done",
    "info",
  ];
  for (const key of keys) {
    assert.equal(typeof c[key], "function", `${key} should be exported`);
    assert.equal(c[key]({}), "", `${key} should return ""`);
  }
});
