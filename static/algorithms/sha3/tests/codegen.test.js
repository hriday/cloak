import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

const EMPTY_HASH = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";

test("full_script imports hashlib (stdlib, no install)", () => {
  const out = c.full_script({});
  assert.match(out, /^import hashlib$/m);
});

test("full_script calls hashlib.sha3_256(...) and .hexdigest()", () => {
  const out = c.full_script({});
  assert.match(out, /hashlib\.sha3_256\(/);
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

test("full_script compares SHA-256 and SHA3-256 side by side", () => {
  const out = c.full_script({});
  assert.match(out, /hashlib\.sha256\(/);
  assert.match(out, /hashlib\.sha3_256\(/);
});

test("full_script embeds the canonical empty-string SHA3-256 hash for grep-verification", () => {
  const out = c.full_script({ sha_message: "anything" });
  assert.match(out, new RegExp(EMPTY_HASH));
  assert.match(out, /assert empty ==/);
});

test("full_script comments warn about Ethereum's Keccak-vs-FIPS202 difference", () => {
  const out = c.full_script({});
  assert.match(out, /Ethereum/i);
  // Should mention either keccak or the padding-byte difference (0x01 vs 0x06).
  assert.match(out, /Keccak|0x01|0x06|padding/);
});

test("full_script handles messages with special characters via JSON.stringify", () => {
  const out = c.full_script({ sha_message: 'she said "hi"' });
  // JSON.stringify escapes embedded quotes, keeping the Python literal valid.
  assert.match(out, /message = b"she said \\"hi\\""/);
});

test("per-step stubs return empty strings", () => {
  for (const key of ["intro", "merkle_damgard_vs_sponge", "the_sponge_construction",
                     "keccak_f", "walk_empty", "hash_a_sentence", "done", "info"]) {
    assert.equal(typeof c[key], "function", `${key} should be exported`);
    assert.equal(c[key]({}), "", `${key} should return ""`);
  }
});
