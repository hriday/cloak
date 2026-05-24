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
