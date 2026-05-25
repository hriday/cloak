import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

test("full_script imports ChaCha20Poly1305 from cryptography.hazmat", () => {
  const out = c.full_script({ chap_message: "hi", chap_aad: "" });
  assert.match(out, /from cryptography\.hazmat\.primitives\.ciphers\.aead import ChaCha20Poly1305/);
});

test("full_script imports InvalidTag for the tamper branch", () => {
  const out = c.full_script({});
  assert.match(out, /from cryptography\.exceptions import InvalidTag/);
});

test("full_script generates a key + nonce", () => {
  const out = c.full_script({});
  assert.match(out, /ChaCha20Poly1305\.generate_key\(\)/);
  assert.match(out, /os\.urandom\(12\)/);
});

test("full_script includes encrypt + decrypt calls", () => {
  const out = c.full_script({});
  assert.match(out, /\.encrypt\(nonce, message, aad\)/);
  assert.match(out, /\.decrypt\(nonce, ct, aad\)/);
});

test("full_script asserts the roundtrip", () => {
  const out = c.full_script({});
  assert.match(out, /assert pt == message/);
});

test("full_script tamper block catches InvalidTag", () => {
  const out = c.full_script({});
  assert.match(out, /tampered\[0\] \^= 0x01/);
  assert.match(out, /except InvalidTag:/);
});

test("full_script embeds the user message", () => {
  const out = c.full_script({ chap_message: "hello world" });
  assert.match(out, /message = b"hello world"/);
});

test("full_script embeds the user aad", () => {
  const out = c.full_script({ chap_message: "hi", chap_aad: "v1-header" });
  assert.match(out, /aad = b"v1-header"/);
});

test("full_script defaults message when state is missing", () => {
  const out = c.full_script({});
  assert.match(out, /message = b"hello chacha"/);
});

test("info-style codegen returns empty strings", () => {
  assert.equal(c.info({}), "");
  assert.equal(c.arx_design({}), "");
  assert.equal(c.quarter_round({}), "");
  assert.equal(c.block_function({}), "");
  assert.equal(c.poly1305_construction({}), "");
  assert.equal(c.encrypt_a_message({}), "");
  assert.equal(c.done({}), "");
});
