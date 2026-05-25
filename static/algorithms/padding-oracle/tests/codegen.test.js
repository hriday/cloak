import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

test("full_script imports cryptography primitives", () => {
  const out = c.full_script({});
  assert.match(out, /from cryptography\.hazmat\.primitives\.ciphers import/);
  assert.match(out, /algorithms,? modes/);
});

test("full_script defines decrypt_or_error (the vulnerable oracle)", () => {
  const out = c.full_script({});
  assert.match(out, /def decrypt_or_error\(iv: bytes, ct: bytes\) -> str:/);
  assert.match(out, /"bad_padding"/);
  assert.match(out, /"ok"/);
});

test("full_script defines recover_byte and recover_block (the attack)", () => {
  const out = c.full_script({});
  assert.match(out, /def recover_byte\(/);
  assert.match(out, /def recover_block\(/);
});

test("full_script uses CBC mode", () => {
  const out = c.full_script({});
  assert.match(out, /modes\.CBC\(/);
});

test("full_script uses AES algorithm", () => {
  const out = c.full_script({});
  assert.match(out, /algorithms\.AES\(/);
});

test("full_script inlines po_target_block_hex from state", () => {
  const targetHex = "deadbeefcafebabe1122334455667788";
  const out = c.full_script({ po_target_block_hex: targetHex });
  assert.ok(out.includes(targetHex), "ct hex should appear in script");
  assert.match(out, /CT = bytes\.fromhex/);
});

test("full_script inlines po_target_iv_hex from state", () => {
  const ivHex = "0011223344556677aabbccddeeff0099";
  const out = c.full_script({ po_target_iv_hex: ivHex });
  assert.ok(out.includes(ivHex), "iv hex should appear in script");
  assert.match(out, /IV = bytes\.fromhex/);
});

test("full_script falls back to placeholder hex when state is empty", () => {
  const out = c.full_script({});
  // Default placeholder is well-known.
  assert.match(out, /00112233445566778899aabbccddeeff/);
});

test("full_script tolerates undefined state", () => {
  const out = c.full_script();
  assert.match(out, /def recover_block\(/);
});

test("full_script includes a provenance comment when po_plaintext is in state", () => {
  const out = c.full_script({ po_plaintext: "hello world!!!12" });
  assert.match(out, /Page recovered/);
  assert.match(out, /hello world!!!12/);
});

test("full_script includes total queries when po_total_queries is in state", () => {
  const out = c.full_script({ po_total_queries: 2049 });
  assert.match(out, /2049/);
  assert.match(out, /oracle queries/);
});

test("full_script begins with a 'for learning only' warning", () => {
  const out = c.full_script({});
  assert.match(out, /FOR LEARNING ONLY/i);
});

test("intro returns empty string", () => {
  assert.equal(c.intro({}), "");
});
test("pkcs7_recap returns empty string", () => {
  assert.equal(c.pkcs7_recap({}), "");
});
test("bit_flipping returns empty string", () => {
  assert.equal(c.bit_flipping({}), "");
});
test("attack_one_byte returns empty string", () => {
  assert.equal(c.attack_one_byte({}), "");
});
test("attack_full_block returns empty string", () => {
  assert.equal(c.attack_full_block({}), "");
});
test("defenses returns empty string", () => {
  assert.equal(c.defenses({}), "");
});
test("done returns empty string", () => {
  assert.equal(c.done({}), "");
});
