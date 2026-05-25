import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

test("full_script imports bcrypt", () => {
  const out = c.full_script({});
  assert.match(out, /^import bcrypt$/m);
});

test("full_script imports time for the wall-clock measurements", () => {
  const out = c.full_script({});
  assert.match(out, /^import time$/m);
});

test("full_script mentions pip install bcrypt", () => {
  const out = c.full_script({});
  assert.match(out, /pip install bcrypt/);
});

test("full_script uses bcrypt.hashpw", () => {
  const out = c.full_script({});
  assert.match(out, /bcrypt\.hashpw\(/);
});

test("full_script uses bcrypt.checkpw", () => {
  const out = c.full_script({});
  assert.match(out, /bcrypt\.checkpw\(/);
});

test("full_script uses bcrypt.gensalt(rounds=...)", () => {
  const out = c.full_script({});
  assert.match(out, /bcrypt\.gensalt\(rounds=/);
});

test("full_script defaults COST to 12 when state has no bcrypt_cost", () => {
  const out = c.full_script({});
  assert.match(out, /^COST = 12$/m);
});

test("full_script uses the cost from state.bcrypt_cost when supplied", () => {
  const out = c.full_script({ bcrypt_cost: 10 });
  assert.match(out, /^COST = 10$/m);
});

test("full_script ignores out-of-range cost from state and falls back to 12", () => {
  // cost factor 99 is invalid (bcrypt accepts 4-31). Don't propagate garbage
  // into the codegen — fall back to the documented default.
  const out = c.full_script({ bcrypt_cost: 99 });
  assert.match(out, /^COST = 12$/m);
});

test("full_script demonstrates that same password + same cost = different hashes", () => {
  const out = c.full_script({});
  // The script hashes twice and asserts hash_a != hash_b.
  assert.match(out, /hash_a = bcrypt\.hashpw/);
  assert.match(out, /hash_b = bcrypt\.hashpw/);
  assert.match(out, /assert hash_a != hash_b/);
});

test("full_script verifies BOTH hashes match the original password", () => {
  const out = c.full_script({});
  assert.match(out, /assert bcrypt\.checkpw\(PASSWORD, hash_a\) is True/);
  assert.match(out, /assert bcrypt\.checkpw\(PASSWORD, hash_b\) is True/);
});

test("full_script verifies that the wrong password is rejected (False, no exception)", () => {
  const out = c.full_script({});
  assert.match(out, /assert bcrypt\.checkpw\(WRONG, hash_a\) is False/);
});

test("full_script includes the demo password and a WRONG counterpart", () => {
  const out = c.full_script({});
  assert.match(out, /correct-horse-battery-staple/);
  assert.match(out, /WRONG\s*=/);
});

test("full_script demonstrates the exponential cost curve at multiple costs", () => {
  const out = c.full_script({});
  // The script loops over 4, 8, 10, 12.
  assert.match(out, /for c in \(4, 8, 10, 12\):/);
});

test("full_script measures wall time with time.perf_counter", () => {
  const out = c.full_script({});
  assert.match(out, /time\.perf_counter\(\)/);
});

test("full_script mentions Argon2id as the modern default in comments", () => {
  const out = c.full_script({});
  assert.match(out, /Argon2id/i);
});

test("full_script tolerates missing state object", () => {
  const out = c.full_script();
  assert.match(out, /import bcrypt/);
  assert.match(out, /^COST = 12$/m);
});

test("full_script tolerates null state", () => {
  const out = c.full_script(null);
  assert.match(out, /import bcrypt/);
});

test("per-step stubs return empty strings", () => {
  for (const key of [
    "intro",
    "the_blowfish_connection",
    "eksblowfish",
    "time_the_cost",
    "salt_and_format",
    "bcrypt_vs_argon2",
    "done",
    "info",
  ]) {
    assert.equal(typeof c[key], "function", `${key} should be exported`);
    assert.equal(c[key]({}), "", `${key} should return ""`);
  }
});
