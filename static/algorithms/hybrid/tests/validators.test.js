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
