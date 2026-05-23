import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

test("pick_sym_key happy", () => {
  assert.deepEqual(v.pick_sym_key("42", {}), { ok: true, value: { h_sym_key: 42 } });
});

test("pick_sym_key rejects non-integer", () => {
  const r = v.pick_sym_key("abc", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /whole number/i);
});

test("pick_sym_key rejects negative", () => {
  const r = v.pick_sym_key("-1", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /0 to 127/);
});

test("pick_sym_key rejects > 127", () => {
  const r = v.pick_sym_key("128", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /0 to 127/);
});

test("wrap_key happy — 42^7 mod 143 = 81", () => {
  const r = v.wrap_key("81", { h_sym_key: 42 });
  assert.equal(r.ok, true);
  assert.equal(r.value.h_wrapped_key, 81);
});

test("wrap_key wrong value mentions m/e/n", () => {
  const r = v.wrap_key("999", { h_sym_key: 42 });
  assert.equal(r.ok, false);
  assert.match(r.hint, /42/);   // m
  assert.match(r.hint, /\b7\b/); // e
  assert.match(r.hint, /143/);  // n
});

test("type_message happy", () => {
  const r = v.type_message("hi", {});
  assert.equal(r.ok, true);
  assert.equal(r.value.h_message, "hi");
  assert.equal(r.value.h_first_char, "h");
  assert.equal(r.value.h_first_code, 104);
});

test("type_message rejects empty", () => {
  const r = v.type_message("", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /at least one/);
});

test("type_message rejects > 500 chars", () => {
  const r = v.type_message("a".repeat(501), {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /500/);
});

test("type_message rejects non-ASCII", () => {
  const r = v.type_message("Hi 🦊", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /ASCII/i);
});

test("xor_encrypt_head happy — first byte of 'hi' XOR 42 = 66", () => {
  const r = v.xor_encrypt_head("66", { h_message: "hi", h_sym_key: 42 });
  assert.equal(r.ok, true);
  assert.deepEqual(r.value.h_ciphertext, [66, 67]);
});

test("xor_encrypt_head wrong value mentions both operands", () => {
  const r = v.xor_encrypt_head("999", { h_message: "hi", h_sym_key: 42 });
  assert.equal(r.ok, false);
  assert.match(r.hint, /104/); // first_code
  assert.match(r.hint, /42/);  // sym_key
});

test("unwrap_key happy — 81^103 mod 143 = 42", () => {
  const r = v.unwrap_key("42", { h_wrapped_key: 81 });
  assert.equal(r.ok, true);
  assert.equal(r.value.h_recovered_key, 42);
});

test("unwrap_key wrong value mentions c/d/n", () => {
  const r = v.unwrap_key("999", { h_wrapped_key: 81 });
  assert.equal(r.ok, false);
  assert.match(r.hint, /81/);   // c
  assert.match(r.hint, /103/);  // d
  assert.match(r.hint, /143/);  // n
});

test("xor_decrypt_head happy — first byte 66 XOR recovered_key 42 = 104", () => {
  const r = v.xor_decrypt_head("104", { h_ciphertext: [66, 67], h_recovered_key: 42 });
  assert.equal(r.ok, true);
  assert.equal(r.value.h_recovered_message, "hi");
});

test("xor_decrypt_head wrong value mentions both operands", () => {
  const r = v.xor_decrypt_head("999", { h_ciphertext: [66, 67], h_recovered_key: 42 });
  assert.equal(r.ok, false);
  assert.match(r.hint, /66/);  // ciphertext[0]
  assert.match(r.hint, /42/);  // recovered_key
});

test("info always returns ok", () => {
  assert.deepEqual(v.info("anything", {}), { ok: true, value: {} });
});

test("walkthroughs exports has the 4 actionable keys", () => {
  assert.equal(typeof v.walkthroughs.wrap_key, "function");
  assert.equal(typeof v.walkthroughs.xor_encrypt_head, "function");
  assert.equal(typeof v.walkthroughs.unwrap_key, "function");
  assert.equal(typeof v.walkthroughs.xor_decrypt_head, "function");
});

test("wrap_key walkthrough computes the answer", () => {
  const rungs = v.walkthroughs.wrap_key({ h_sym_key: 42 });
  assert.equal(rungs.length, 3);
  rungs.forEach((r) => assert.equal(typeof r, "string"));
  assert.match(rungs[2], /\b81\b/); // 42^7 mod 143 = 81
});

test("xor_encrypt_head walkthrough computes the answer", () => {
  const rungs = v.walkthroughs.xor_encrypt_head({ h_message: "hi", h_sym_key: 42 });
  assert.equal(rungs.length, 3);
  assert.match(rungs[2], /\b66\b/); // 'h'(104) XOR 42 = 66
});

test("unwrap_key walkthrough computes the answer", () => {
  const rungs = v.walkthroughs.unwrap_key({ h_wrapped_key: 81 });
  assert.equal(rungs.length, 3);
  assert.match(rungs[2], /\b42\b/); // 81^103 mod 143 = 42
});

test("xor_decrypt_head walkthrough computes the answer", () => {
  const rungs = v.walkthroughs.xor_decrypt_head({ h_ciphertext: [66, 67], h_recovered_key: 42 });
  assert.equal(rungs.length, 3);
  assert.match(rungs[2], /\b104\b/); // 66 XOR 42 = 104
});
