import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

const EMPTY_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

test("full_script imports hashlib (stdlib, no install)", () => {
  const out = c.full_script({});
  assert.match(out, /^import hashlib$/m);
});

test("full_script calls hashlib.sha256(...) and .hexdigest()", () => {
  const out = c.full_script({});
  assert.match(out, /hashlib\.sha256\(/);
  assert.match(out, /\.hexdigest\(\)/);
});

test("full_script includes the user's message literal", () => {
  const out = c.full_script({ sha_message: "hello world" });
  assert.match(out, /message = b"hello world"/);
});

test("full_script falls back to a default message when state is empty", () => {
  const out = c.full_script({});
  assert.match(out, /message = b"hello, world"/);
});

test("full_script demonstrates the avalanche with 'hello' vs 'Hello'", () => {
  const out = c.full_script({});
  assert.match(out, /hashlib\.sha256\(b"hello"\)\.hexdigest\(\)/);
  assert.match(out, /hashlib\.sha256\(b"Hello"\)\.hexdigest\(\)/);
});

test("full_script embeds the canonical empty-string hash for grep-verification", () => {
  const out = c.full_script({ sha_message: "anything" });
  assert.match(out, new RegExp(EMPTY_HASH));
  assert.match(out, /assert empty ==/);
});

test("full_script comments reference TLS, file integrity, and PBKDF2", () => {
  const out = c.full_script({});
  assert.match(out, /TLS certificate/i);
  assert.match(out, /file integrity|integrity checksum/i);
  assert.match(out, /PBKDF2/);
});

test("full_script handles messages with special characters via JSON.stringify", () => {
  const out = c.full_script({ sha_message: 'she said "hi"' });
  // JSON.stringify escapes embedded quotes, keeping the Python literal valid.
  assert.match(out, /message = b"she said \\"hi\\""/);
});

test("per-step stubs return empty strings", () => {
  for (const key of ["intro", "preprocessing", "init_state", "compression",
                     "walk_empty", "avalanche", "hash_a_sentence", "done", "info"]) {
    assert.equal(typeof c[key], "function", `${key} should be exported`);
    assert.equal(c[key]({}), "", `${key} should return ""`);
  }
});
