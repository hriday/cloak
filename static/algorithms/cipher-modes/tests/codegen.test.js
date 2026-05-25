import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

test("full_script imports the modes API", () => {
  const out = c.full_script({});
  assert.match(out, /from cryptography\.hazmat\.primitives\.ciphers import Cipher, algorithms, modes/);
});

test("full_script imports AESGCM for the GCM half", () => {
  const out = c.full_script({});
  assert.match(out, /from cryptography\.hazmat\.primitives\.ciphers\.aead import AESGCM/);
});

test("full_script uses modes.CBC", () => {
  const out = c.full_script({});
  assert.match(out, /modes\.CBC\(iv\)/);
});

test("full_script uses modes.CTR", () => {
  const out = c.full_script({});
  assert.match(out, /modes\.CTR\(nonce\)/);
});

test("full_script uses PKCS7 padding on the CBC branch", () => {
  const out = c.full_script({});
  assert.match(out, /padding\.PKCS7\(128\)/);
});

test("full_script asserts the roundtrip for each mode", () => {
  const out = c.full_script({});
  assert.match(out, /assert cbc_pt == message/);
  assert.match(out, /assert ctr_pt == message/);
  assert.match(out, /assert gcm_pt == message/);
});

test("full_script uses a 12-byte nonce for GCM", () => {
  const out = c.full_script({});
  assert.match(out, /os\.urandom\(12\)/);
});

test("full_script generates a 16-byte AES-128 key", () => {
  const out = c.full_script({});
  assert.match(out, /key = os\.urandom\(16\)/);
});

test("full_script is ignorant of state (no input variables to plug in)", () => {
  const a = c.full_script({});
  const b = c.full_script({ mode_iv_hex: "deadbeef" });
  assert.equal(a, b);
});

test("info returns empty string", () => {
  assert.equal(c.info({}), "");
});

test("cbc_walk step codegen returns empty string", () => {
  assert.equal(c.cbc_walk({}), "");
});

test("pick_a_mode step codegen returns empty string", () => {
  assert.equal(c.pick_a_mode({}), "");
});
