import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

test("sub_byte accepts decimal", () => {
  const r = v.sub_byte("237", {});
  assert.equal(r.ok, true);
  assert.equal(r.value.a_sub_input, 0x53);
  assert.equal(r.value.a_sub_output, 0xED);
});

test("sub_byte accepts hex prefix", () => {
  const r = v.sub_byte("0xED", {});
  assert.equal(r.ok, true);
  assert.equal(r.value.a_sub_output, 0xED);
});

test("sub_byte accepts bare hex", () => {
  assert.equal(v.sub_byte("ED", {}).ok, true);
  assert.equal(v.sub_byte("ed", {}).ok, true);
});

test("sub_byte rejects wrong value", () => {
  const r = v.sub_byte("0xAA", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /0xED|237/);
});

test("sub_byte rejects out of range", () => {
  const r = v.sub_byte("999", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /0.*255/);
});

test("sub_byte rejects garbage", () => {
  const r = v.sub_byte("foo", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /byte value/);
});

test("add_round_key happy — 0xED XOR 0x2B = 0xC6", () => {
  const r = v.add_round_key("0xC6", {});
  assert.equal(r.ok, true);
  assert.equal(r.value.a_ark_output, 0xC6);
});

test("add_round_key accepts decimal", () => {
  assert.equal(v.add_round_key("198", {}).ok, true);
});

test("add_round_key wrong value mentions both operands", () => {
  const r = v.add_round_key("0", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /0xED|237/);
  assert.match(r.hint, /0x2B|43/);
});

test("shift_row happy", () => {
  // input row [0x09, 0xCF, 0x4F, 0x3C] shifts left by 1 → [0xCF, 0x4F, 0x3C, 0x09]
  const r = v.shift_row({ b0: "0xCF", b1: "0x4F", b2: "0x3C", b3: "0x09" }, {});
  assert.equal(r.ok, true);
  assert.deepEqual(r.value.a_shifted_row, [0xCF, 0x4F, 0x3C, 0x09]);
});

test("shift_row wrong order", () => {
  const r = v.shift_row({ b0: "0x09", b1: "0xCF", b2: "0x4F", b3: "0x3C" }, {});  // unshifted
  assert.equal(r.ok, false);
  assert.match(r.hint, /shifts left/);
});

test("shift_row rejects missing values", () => {
  const r = v.shift_row({ b0: "0xCF", b1: "", b2: "0x3C", b3: "0x09" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /4 bytes/);
});

test("shift_row rejects out-of-range", () => {
  const r = v.shift_row({ b0: "999", b1: "0x4F", b2: "0x3C", b3: "0x09" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /0.*255/);
});

test("pick_aes_message happy", () => {
  const r = v.pick_aes_message("hi", {});
  assert.equal(r.ok, true);
  assert.equal(r.value.a_message, "hi");
});

test("pick_aes_message rejects empty", () => {
  const r = v.pick_aes_message("", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /at least one/);
});

test("pick_aes_message rejects >500", () => {
  const r = v.pick_aes_message("a".repeat(501), {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /500/);
});

test("pick_aes_message rejects non-ASCII", () => {
  const r = v.pick_aes_message("hi 🦊", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /ASCII/i);
});

test("info always ok", () => {
  assert.deepEqual(v.info("anything", {}), { ok: true, value: {} });
});
