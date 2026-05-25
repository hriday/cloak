import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

const EMPTY_HASH = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";

// ---------- walk_empty_sha3 ----------

test("walk_empty_sha3 accepts the canonical hex string", () => {
  const r = v.walk_empty_sha3(EMPTY_HASH, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.sha3_empty_hex, EMPTY_HASH);
});

test("walk_empty_sha3 accepts {hex: ...} object form", () => {
  const r = v.walk_empty_sha3({ hex: EMPTY_HASH }, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.sha3_empty_hex, EMPTY_HASH);
});

test("walk_empty_sha3 accepts uppercase hex", () => {
  const r = v.walk_empty_sha3(EMPTY_HASH.toUpperCase(), {});
  assert.equal(r.ok, true);
  assert.equal(r.value.sha3_empty_hex, EMPTY_HASH);
});

test("walk_empty_sha3 tolerates surrounding whitespace", () => {
  const r = v.walk_empty_sha3(`  ${EMPTY_HASH}\n`, {});
  assert.equal(r.ok, true);
});

test("walk_empty_sha3 rejects empty input with a Compute prompt", () => {
  const r = v.walk_empty_sha3("", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /Compute/);
});

test("walk_empty_sha3 rejects null/undefined", () => {
  assert.equal(v.walk_empty_sha3(null, {}).ok, false);
  assert.equal(v.walk_empty_sha3(undefined, {}).ok, false);
});

test("walk_empty_sha3 rejects wrong-length input", () => {
  const r = v.walk_empty_sha3("a7ffc6f8", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /64 hex/);
});

test("walk_empty_sha3 rejects non-hex characters", () => {
  const r = v.walk_empty_sha3("z".repeat(64), {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /64 hex/);
});

test("walk_empty_sha3 rejects a valid-shape but wrong hash", () => {
  // Use the SHA-256 empty digest to make sure we don't accidentally accept it.
  const sha256Empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  const r = v.walk_empty_sha3(sha256Empty, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /well-known/);
  assert.match(r.hint, /a7ffc6f8/);
});

// ---------- pick_sha3_sentence ----------

test("pick_sha3_sentence accepts a normal sentence", () => {
  const r = v.pick_sha3_sentence("hello, world", {});
  assert.equal(r.ok, true);
  // Writes to state.sha_message — same key as the SHA-256 lesson so the
  // shared template branch (lesson.html line ~629) can render the result.
  assert.equal(r.value.sha_message, "hello, world");
});

test("pick_sha3_sentence accepts a single character", () => {
  const r = v.pick_sha3_sentence("a", {});
  assert.equal(r.ok, true);
});

test("pick_sha3_sentence accepts exactly 500 characters", () => {
  const r = v.pick_sha3_sentence("a".repeat(500), {});
  assert.equal(r.ok, true);
});

test("pick_sha3_sentence rejects empty", () => {
  const r = v.pick_sha3_sentence("", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /printable ASCII/);
});

test("pick_sha3_sentence rejects >500 chars", () => {
  const r = v.pick_sha3_sentence("a".repeat(501), {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /500/);
});

test("pick_sha3_sentence rejects non-ASCII (emoji)", () => {
  const r = v.pick_sha3_sentence("hi 🦊", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /printable ASCII/i);
});

test("pick_sha3_sentence rejects newlines", () => {
  const r = v.pick_sha3_sentence("line one\nline two", {});
  assert.equal(r.ok, false);
});

test("pick_sha3_sentence rejects tabs", () => {
  const r = v.pick_sha3_sentence("col1\tcol2", {});
  assert.equal(r.ok, false);
});

// ---------- info ----------

test("info always ok", () => {
  assert.deepEqual(v.info("anything", {}), { ok: true, value: {} });
  assert.deepEqual(v.info(null, {}), { ok: true, value: {} });
});

// ---------- walkthroughs ----------

test("walkthroughs has walk_empty_sha3 with 3 rungs", () => {
  assert.equal(typeof v.walkthroughs.walk_empty_sha3, "function");
  const rungs = v.walkthroughs.walk_empty_sha3({});
  assert.equal(rungs.length, 3);
  rungs.forEach((r) => assert.equal(typeof r, "string"));
});

test("walk_empty_sha3 walkthrough final rung reveals the canonical hash", () => {
  const rungs = v.walkthroughs.walk_empty_sha3({});
  assert.match(rungs[2], /a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a/);
});

test("walkthroughs does NOT define pick_sha3_sentence (no right answer to walk to)", () => {
  assert.equal(v.walkthroughs.pick_sha3_sentence, undefined);
});

test("SHA3_EMPTY_HEX export matches the canonical value", () => {
  assert.equal(v.SHA3_EMPTY_HEX, EMPTY_HASH);
});
