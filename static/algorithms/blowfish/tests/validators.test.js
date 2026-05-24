import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

const ANSWER_HEX = "0xD7F08FBE";
const ANSWER_DEC = "3622866878"; // 0xD7F08FBE in decimal

test("f_function happy — accepts 0xD7F08FBE", () => {
  const r = v.f_function(ANSWER_HEX, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.bf_f_output, ANSWER_HEX);
});

test("f_function accepts decimal 3622866878", () => {
  const r = v.f_function(ANSWER_DEC, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.bf_f_output, ANSWER_HEX);
});

test("f_function accepts lowercase 0xd7f08fbe", () => {
  const r = v.f_function("0xd7f08fbe", {});
  assert.equal(r.ok, true);
});

test("f_function accepts hex without 0x prefix (D7F08FBE)", () => {
  const r = v.f_function("D7F08FBE", {});
  assert.equal(r.ok, true);
});

test("f_function accepts hex without 0x prefix, lowercase (d7f08fbe)", () => {
  const r = v.f_function("d7f08fbe", {});
  assert.equal(r.ok, true);
});

test("f_function rejects wrong value with math-mentioning hint", () => {
  const r = v.f_function("0xDEADBEEF", {});
  assert.equal(r.ok, false);
  // Hint should reference the math (XOR / mod / one of the S-box values).
  assert.match(r.hint, /XOR|mod|0x[0-9A-Fa-f]/);
  assert.match(r.hint, /0xD7F08FBE/);
});

test("f_function rejects garbage", () => {
  const r = v.f_function("not a number", {});
  assert.equal(r.ok, false);
});

test("f_function rejects empty", () => {
  const r = v.f_function("", {});
  assert.equal(r.ok, false);
});

test("pick_blowfish_message happy", () => {
  const r = v.pick_blowfish_message("hello blowfish", {});
  assert.equal(r.ok, true);
  assert.equal(r.value.bf_message, "hello blowfish");
});

test("pick_blowfish_message rejects empty", () => {
  const r = v.pick_blowfish_message("", {});
  assert.equal(r.ok, false);
});

test("pick_blowfish_message rejects whitespace-only", () => {
  const r = v.pick_blowfish_message("   ", {});
  assert.equal(r.ok, false);
});

test("pick_blowfish_message rejects >500 chars", () => {
  const r = v.pick_blowfish_message("a".repeat(501), {});
  assert.equal(r.ok, false);
});

test("pick_blowfish_message rejects non-ASCII", () => {
  const r = v.pick_blowfish_message("hi 🐡", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /ASCII/i);
});

test("info always ok", () => {
  assert.deepEqual(v.info("anything", {}), { ok: true, value: {} });
});

test("walkthroughs.f_function returns 3 string rungs", () => {
  const rungs = v.walkthroughs.f_function({});
  assert.equal(rungs.length, 3);
  rungs.forEach((r) => assert.equal(typeof r, "string"));
});

test("walkthroughs.f_function mentions all four S-box values verbatim", () => {
  const rungs = v.walkthroughs.f_function({});
  const all = rungs.join("\n");
  assert.match(all, /0xD7CABA51/);
  assert.match(all, /0x4BCA8A93/);
  assert.match(all, /0x9A3FE5C1/);
  assert.match(all, /0x1E45EE99/);
});

test("walkthroughs.f_function final rung ends with the answer 0xD7F08FBE", () => {
  const rungs = v.walkthroughs.f_function({});
  assert.match(rungs[2], /0xD7F08FBE/);
});
