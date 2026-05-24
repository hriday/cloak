import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

test("full_script imports cryptography.hazmat AESGCM", () => {
  const out = c.full_script({ a_message: "hi" });
  assert.match(out, /from cryptography\.hazmat\.primitives\.ciphers\.aead import AESGCM/);
});

test("full_script generates a 128-bit key", () => {
  const out = c.full_script({ a_message: "hi" });
  assert.match(out, /AESGCM\.generate_key\(bit_length=128\)/);
});

test("full_script includes the user's message and the roundtrip assert", () => {
  const out = c.full_script({ a_message: "hello world" });
  assert.match(out, /message = b"hello world"/);
  assert.match(out, /assert plaintext == message/);
});

test("info returns empty string", () => {
  assert.equal(c.info({}), "");
});
