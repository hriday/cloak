import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

const EMPTY_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

// ---------- walk_empty_hash ----------

test("walk_empty_hash accepts the canonical hex string", () => {
  const r = v.walk_empty_hash(EMPTY_HASH, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.sha_empty_hex, EMPTY_HASH);
});

test("walk_empty_hash accepts {hex: ...} object form", () => {
  const r = v.walk_empty_hash({ hex: EMPTY_HASH }, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.sha_empty_hex, EMPTY_HASH);
});

test("walk_empty_hash accepts uppercase hex", () => {
  const r = v.walk_empty_hash(EMPTY_HASH.toUpperCase(), {});
  assert.equal(r.ok, true);
  assert.equal(r.value.sha_empty_hex, EMPTY_HASH);
});

test("walk_empty_hash tolerates surrounding whitespace", () => {
  const r = v.walk_empty_hash(`  ${EMPTY_HASH}\n`, {});
  assert.equal(r.ok, true);
});

test("walk_empty_hash rejects empty input with a Compute prompt", () => {
  const r = v.walk_empty_hash("", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /Compute/);
});

test("walk_empty_hash rejects null/undefined", () => {
  assert.equal(v.walk_empty_hash(null, {}).ok, false);
  assert.equal(v.walk_empty_hash(undefined, {}).ok, false);
});

test("walk_empty_hash rejects wrong-length input", () => {
  const r = v.walk_empty_hash("e3b0c442", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /64 hex/);
});

test("walk_empty_hash rejects non-hex characters", () => {
  const r = v.walk_empty_hash("z".repeat(64), {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /64 hex/);
});

test("walk_empty_hash rejects a valid-shape but wrong hash", () => {
  const wrong = "a".repeat(64);
  const r = v.walk_empty_hash(wrong, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /well-known/);
  assert.match(r.hint, /e3b0c442/);
});

// ---------- pick_sha_sentence ----------

test("pick_sha_sentence accepts a normal sentence", () => {
  const r = v.pick_sha_sentence("hello, world", {});
  assert.equal(r.ok, true);
  assert.equal(r.value.sha_message, "hello, world");
});

test("pick_sha_sentence accepts a single character", () => {
  const r = v.pick_sha_sentence("a", {});
  assert.equal(r.ok, true);
});

test("pick_sha_sentence accepts exactly 500 characters", () => {
  const r = v.pick_sha_sentence("a".repeat(500), {});
  assert.equal(r.ok, true);
});

test("pick_sha_sentence rejects empty", () => {
  const r = v.pick_sha_sentence("", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /printable ASCII/);
});

test("pick_sha_sentence rejects >500 chars", () => {
  const r = v.pick_sha_sentence("a".repeat(501), {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /500/);
});

test("pick_sha_sentence rejects non-ASCII (emoji)", () => {
  const r = v.pick_sha_sentence("hi 🦊", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /printable ASCII/i);
});

test("pick_sha_sentence rejects newlines", () => {
  const r = v.pick_sha_sentence("line one\nline two", {});
  assert.equal(r.ok, false);
});

test("pick_sha_sentence rejects tabs", () => {
  const r = v.pick_sha_sentence("col1\tcol2", {});
  assert.equal(r.ok, false);
});

// ---------- info ----------

test("info always ok", () => {
  assert.deepEqual(v.info("anything", {}), { ok: true, value: {} });
  assert.deepEqual(v.info(null, {}), { ok: true, value: {} });
});

// ---------- walkthroughs ----------

test("walkthroughs has walk_empty_hash with 3 rungs", () => {
  assert.equal(typeof v.walkthroughs.walk_empty_hash, "function");
  const rungs = v.walkthroughs.walk_empty_hash({});
  assert.equal(rungs.length, 3);
  rungs.forEach((r) => assert.equal(typeof r, "string"));
});

test("walk_empty_hash walkthrough final rung reveals the canonical hash", () => {
  const rungs = v.walkthroughs.walk_empty_hash({});
  assert.match(rungs[2], /e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855/);
});

test("walkthroughs does NOT define pick_sha_sentence (no right answer to walk to)", () => {
  assert.equal(v.walkthroughs.pick_sha_sentence, undefined);
});

test("SHA_EMPTY_HEX export matches the canonical value", () => {
  assert.equal(v.SHA_EMPTY_HEX, EMPTY_HASH);
});
