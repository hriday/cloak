import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

const ANSWER_HEX = "0x5F";
const ANSWER_DEC = "95"; // 0x5F in decimal

test("whitening happy — accepts 0x5F", () => {
  const r = v.whitening(ANSWER_HEX, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.tf_whitening_output, ANSWER_HEX);
});

test("whitening accepts decimal 95", () => {
  const r = v.whitening(ANSWER_DEC, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.tf_whitening_output, ANSWER_HEX);
});

test("whitening accepts lowercase 0x5f", () => {
  const r = v.whitening("0x5f", {});
  assert.equal(r.ok, true);
});

test("whitening accepts hex without 0x prefix (5F)", () => {
  const r = v.whitening("5F", {});
  assert.equal(r.ok, true);
});

test("whitening accepts hex without 0x prefix, lowercase (5f)", () => {
  const r = v.whitening("5f", {});
  assert.equal(r.ok, true);
});

test("whitening rejects wrong value with bit-by-bit XOR hint", () => {
  const r = v.whitening("0x5E", {});
  assert.equal(r.ok, false);
  // Hint should walk through the XOR with both operands and the answer.
  assert.match(r.hint, /0x6A/);
  assert.match(r.hint, /0x35/);
  assert.match(r.hint, /0x5F/);
  assert.match(r.hint, /XOR/);
  // Binary representation of operands should appear.
  assert.match(r.hint, /01101010/);
  assert.match(r.hint, /00110101/);
});

test("whitening rejects garbage", () => {
  const r = v.whitening("not a number", {});
  assert.equal(r.ok, false);
});

test("whitening rejects empty", () => {
  const r = v.whitening("", {});
  assert.equal(r.ok, false);
});

test("whitening rejects out-of-range (0x100)", () => {
  const r = v.whitening("0x100", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /byte|0xFF|255/i);
});

test("whitening rejects out-of-range decimal (256)", () => {
  const r = v.whitening("256", {});
  assert.equal(r.ok, false);
});

test("pick_twofish_message happy", () => {
  const r = v.pick_twofish_message("hello twofish", {});
  assert.equal(r.ok, true);
  assert.equal(r.value.tf_message, "hello twofish");
});

test("pick_twofish_message rejects empty", () => {
  const r = v.pick_twofish_message("", {});
  assert.equal(r.ok, false);
});

test("pick_twofish_message rejects whitespace-only", () => {
  const r = v.pick_twofish_message("   ", {});
  assert.equal(r.ok, false);
});

test("pick_twofish_message rejects >500 chars", () => {
  const r = v.pick_twofish_message("a".repeat(501), {});
  assert.equal(r.ok, false);
});

test("pick_twofish_message rejects non-ASCII", () => {
  const r = v.pick_twofish_message("hi 🐟", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /ASCII/i);
});

test("info always ok", () => {
  assert.deepEqual(v.info("anything", {}), { ok: true, value: {} });
});

test("walkthroughs.whitening returns 3 string rungs", () => {
  const rungs = v.walkthroughs.whitening({});
  assert.equal(rungs.length, 3);
  rungs.forEach((r) => assert.equal(typeof r, "string"));
});

test("walkthroughs.whitening mentions both operands 0x6A and 0x35", () => {
  const rungs = v.walkthroughs.whitening({});
  const all = rungs.join("\n");
  assert.match(all, /0x6A/);
  assert.match(all, /0x35/);
});

test("walkthroughs.whitening final rung ends with the answer 0x5F", () => {
  const rungs = v.walkthroughs.whitening({});
  assert.match(rungs[2], /0x5F/);
});
