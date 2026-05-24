import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

test("full_script imports TripleDES", () => {
  const out = c.full_script({ td_message: "hi" });
  assert.match(out, /from cryptography\.hazmat\.primitives\.ciphers import Cipher, algorithms, modes/);
  assert.match(out, /algorithms\.TripleDES/);
});

test("full_script uses CBC + PKCS7 padding", () => {
  const out = c.full_script({ td_message: "hi" });
  assert.match(out, /modes\.CBC/);
  assert.match(out, /PKCS7\(64\)/);
});

test("full_script includes the user's message and roundtrip assert", () => {
  const out = c.full_script({ td_message: "hello world" });
  assert.match(out, /message = b"hello world"/);
  assert.match(out, /assert plaintext == message/);
});

test("info returns empty string", () => {
  assert.equal(c.info({}), "");
});

test("mitm_attack returns empty string (no inline code panel)", () => {
  assert.equal(c.mitm_attack({}), "");
});

test("pick_3des_message returns empty string", () => {
  assert.equal(c.pick_3des_message({}), "");
});
