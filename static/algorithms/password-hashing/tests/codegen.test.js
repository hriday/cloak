import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

test("full_script imports argon2 and bcrypt", () => {
  const out = c.full_script({});
  assert.match(out, /^import argon2$/m);
  assert.match(out, /from argon2 import PasswordHasher/);
  assert.match(out, /^import bcrypt$/m);
});

test("full_script mentions pip install argon2-cffi bcrypt", () => {
  const out = c.full_script({});
  assert.match(out, /pip install argon2-cffi bcrypt/);
});

test("full_script mentions passlib as the multi-algo alternative", () => {
  const out = c.full_script({});
  assert.match(out, /passlib/i);
});

test("full_script demonstrates Argon2id PasswordHasher().hash()", () => {
  const out = c.full_script({});
  assert.match(out, /PasswordHasher\(\)/);
  assert.match(out, /\.hash\(PASSWORD\)|\.hash\(/);
});

test("full_script demonstrates ph.verify success and failure", () => {
  const out = c.full_script({});
  assert.match(out, /ph\.verify\(argon2_hash, PASSWORD\)/);
  // Wrong-password verify-fail wrapped in try/except.
  assert.match(out, /VerifyMismatchError/);
  assert.match(out, /try:/);
});

test("full_script demonstrates bcrypt.hashpw + bcrypt.gensalt(rounds=12)", () => {
  const out = c.full_script({});
  assert.match(out, /bcrypt\.hashpw\(/);
  assert.match(out, /bcrypt\.gensalt\(rounds=12\)/);
});

test("full_script demonstrates bcrypt.checkpw success and failure", () => {
  const out = c.full_script({});
  // Success: True
  assert.match(out, /assert bcrypt\.checkpw\(pw_bytes, bcrypt_hash\) is True/);
  // Failure: False
  assert.match(out, /assert bcrypt\.checkpw\(WRONG\.encode\("utf-8"\), bcrypt_hash\) is False/);
});

test("full_script includes a sample password", () => {
  const out = c.full_script({});
  assert.match(out, /correct-horse-battery-staple/);
});

test("full_script includes a wrong-password constant for the failure cases", () => {
  const out = c.full_script({});
  assert.match(out, /WRONG\s*=/);
});

test("full_script uses 'utf-8' encoding for bcrypt bytes", () => {
  const out = c.full_script({});
  assert.match(out, /\.encode\("utf-8"\)/);
});

test("full_script tolerates missing state object", () => {
  const out = c.full_script();
  assert.match(out, /import argon2/);
  assert.match(out, /import bcrypt/);
});

test("full_script ends with the recommendation summary (Argon2id, bcrypt 12+, PBKDF2 600k)", () => {
  const out = c.full_script({});
  assert.match(out, /Argon2id/i);
  assert.match(out, /bcrypt/i);
  assert.match(out, /PBKDF2/);
  assert.match(out, /600k|600,000|600000/i);
});

test("per-step stubs return empty strings", () => {
  for (const key of [
    "intro",
    "naive_sha256_failure",
    "pbkdf2",
    "bcrypt",
    "argon2_construction",
    "compare_hashes",
    "which_to_use",
    "done",
    "info",
  ]) {
    assert.equal(typeof c[key], "function", `${key} should be exported`);
    assert.equal(c[key]({}), "", `${key} should return ""`);
  }
});
