import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

test("full_script imports Cipher/algorithms/modes", () => {
  const out = c.full_script({ bf_message: "hi" });
  assert.match(out, /from cryptography\.hazmat\.primitives\.ciphers import Cipher, algorithms, modes/);
  assert.match(out, /algorithms\.Blowfish\(/);
});

test("full_script uses CBC + PKCS7(64) padding (64-bit block, not 128)", () => {
  const out = c.full_script({ bf_message: "hi" });
  assert.match(out, /modes\.CBC\(/);
  assert.match(out, /PKCS7\(64\)/);
  assert.doesNotMatch(out, /PKCS7\(128\)/);
});

test("full_script asserts decrypted roundtrip", () => {
  const out = c.full_script({ bf_message: "hi" });
  assert.match(out, /assert decrypted == message/);
});

test("full_script uses state.bf_message when provided", () => {
  const out = c.full_script({ bf_message: "test sentence" });
  assert.match(out, /message = b"test sentence"/);
});

test("full_script falls back to a default message when state is empty", () => {
  const out = c.full_script({});
  assert.match(out, /message = b"hello blowfish"/);
});

test("intro returns empty string", () => {
  assert.equal(c.intro({}), "");
});

test("feistel_structure returns empty string", () => {
  assert.equal(c.feistel_structure({}), "");
});

test("f_function returns empty string", () => {
  assert.equal(c.f_function({}), "");
});

test("one_round returns empty string", () => {
  assert.equal(c.one_round({}), "");
});

test("encrypt_a_message returns empty string", () => {
  assert.equal(c.encrypt_a_message({}), "");
});

test("done returns empty string", () => {
  assert.equal(c.done({}), "");
});
