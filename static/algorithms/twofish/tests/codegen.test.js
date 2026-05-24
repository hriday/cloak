import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

test("full_script imports Twofish from pycryptodome", () => {
  const out = c.full_script({ tf_message: "hi" });
  assert.match(out, /from Crypto\.Cipher import Twofish/);
});

test("full_script imports get_random_bytes", () => {
  const out = c.full_script({ tf_message: "hi" });
  assert.match(out, /from Crypto\.Random import get_random_bytes/);
});

test("full_script uses CBC mode", () => {
  const out = c.full_script({ tf_message: "hi" });
  assert.match(out, /Twofish\.MODE_CBC/);
});

test("full_script constructs cipher via Twofish.new(", () => {
  const out = c.full_script({ tf_message: "hi" });
  assert.match(out, /Twofish\.new\(/);
});

test("full_script asserts decrypted roundtrip", () => {
  const out = c.full_script({ tf_message: "hi" });
  assert.match(out, /assert pt == plaintext_bytes/);
});

test("full_script pads against the 16-byte Twofish block", () => {
  const out = c.full_script({ tf_message: "hi" });
  assert.match(out, /% 16/);
  assert.match(out, /bytes\(\[pad_len\]\)/);
});

test("full_script uses state.tf_message when provided", () => {
  const out = c.full_script({ tf_message: "test sentence" });
  assert.match(out, /plaintext_bytes = b"test sentence"/);
});

test("full_script falls back to a default message when state is empty", () => {
  const out = c.full_script({});
  assert.match(out, /plaintext_bytes = b"hello twofish"/);
});

test("intro returns empty string", () => {
  assert.equal(c.intro({}), "");
});

test("vs_aes returns empty string", () => {
  assert.equal(c.vs_aes({}), "");
});

test("key_dependent_sboxes returns empty string", () => {
  assert.equal(c.key_dependent_sboxes({}), "");
});

test("whitening returns empty string", () => {
  assert.equal(c.whitening({}), "");
});

test("encrypt_a_message returns empty string", () => {
  assert.equal(c.encrypt_a_message({}), "");
});

test("done returns empty string", () => {
  assert.equal(c.done({}), "");
});
