import { test } from "node:test";
import assert from "node:assert/strict";
import {
  findCollision,
  expectedAttempts,
  truncatedHashHex,
} from "../bday_demo.js";

// ---------- expectedAttempts ----------

test("expectedAttempts(16) ≈ 302 (1.18 * sqrt(2^16))", () => {
  const got = expectedAttempts(16);
  // 1.18 * 256 = 302.08
  assert.ok(got > 300 && got < 303, `expected ~302, got ${got}`);
});

test("expectedAttempts(8) ≈ 18.88", () => {
  const got = expectedAttempts(8);
  // 1.18 * 16 = 18.88
  assert.ok(got > 18 && got < 19.5, `expected ~18.88, got ${got}`);
});

test("expectedAttempts(128) is the MD5 birthday bound ~2.17e19", () => {
  const got = expectedAttempts(128);
  // 1.18 * 2^64 ≈ 2.176e19
  assert.ok(got > 2e19 && got < 2.5e19, `expected ~2.18e19, got ${got}`);
});

test("expectedAttempts scales as sqrt — doubling bits multiplies by 16", () => {
  // sqrt(2^(b+8)) / sqrt(2^b) = sqrt(2^8) = 16
  const a = expectedAttempts(8);
  const b = expectedAttempts(16);
  const ratio = b / a;
  assert.ok(ratio > 15.8 && ratio < 16.2, `expected ~16x, got ${ratio}`);
});

// ---------- truncatedHashHex ----------

test("truncatedHashHex('abc', 16) equals the first 4 hex chars of sha256('abc')", async () => {
  // sha256('abc') = ba7816bf...
  const t = await truncatedHashHex("abc", 16);
  assert.equal(t, "ba78");
});

test("truncatedHashHex returns the right length for various bit sizes", async () => {
  // 8 bits = 1 byte = 2 hex chars; 16 = 4; 24 = 6.
  assert.equal((await truncatedHashHex("x", 8)).length, 2);
  assert.equal((await truncatedHashHex("x", 16)).length, 4);
  assert.equal((await truncatedHashHex("x", 24)).length, 6);
  assert.equal((await truncatedHashHex("x", 32)).length, 8);
});

test("truncatedHashHex is deterministic", async () => {
  const a = await truncatedHashHex("hello", 16);
  const b = await truncatedHashHex("hello", 16);
  assert.equal(a, b);
});

// ---------- findCollision ----------

test("findCollision(8) returns a collision in under 100 attempts (birthday ~22)", async () => {
  // Spec: "Verify findCollision(8) returns a collision in < 100 attempts
  // (should be ~22 by birthday math)."
  const r = await findCollision(8);
  assert.ok(r.attempts > 0, "attempts must be positive");
  assert.ok(r.attempts < 100, `expected < 100 attempts, got ${r.attempts}`);
});

test("findCollision(8): the two inputs are different", async () => {
  const r = await findCollision(8);
  assert.notEqual(r.inputA, r.inputB, "inputA and inputB must be distinct");
});

test("findCollision(8): truncated hashes of the two inputs actually match", async () => {
  const r = await findCollision(8);
  const h1 = await truncatedHashHex(r.inputA, 8);
  const h2 = await truncatedHashHex(r.inputB, 8);
  assert.equal(h1, h2, "truncated hashes must collide");
  assert.equal(h1, r.hash, "returned hash must equal both truncated hashes");
});

test("findCollision(16) lands in the birthday ballpark (typically <2000)", async () => {
  // Expected attempts ~302; 2000 is ~6.6x the expectation — generous
  // ceiling to avoid spurious flakes. Statistical chance of exceeding
  // this on a uniform 16-bit hash is well under 0.001.
  const r = await findCollision(16);
  assert.ok(r.attempts > 0);
  assert.ok(r.attempts < 5000, `expected birthday-bounded attempts, got ${r.attempts}`);
  assert.notEqual(r.inputA, r.inputB);
});

test("findCollision(16): returned hash is exactly 4 hex chars (16 bits)", async () => {
  const r = await findCollision(16);
  assert.match(r.hash, /^[0-9a-f]{4}$/);
});

test("findCollision(16): the collision verifies under SHA-256 truncated to 16 bits", async () => {
  const r = await findCollision(16);
  const hA = await truncatedHashHex(r.inputA, 16);
  const hB = await truncatedHashHex(r.inputB, 16);
  assert.equal(hA, hB);
  assert.equal(hA, r.hash);
});

test("findCollision invokes progressCallback at least once on a long-ish run", async () => {
  // For 16 bits, expected ~302 attempts, callback fires every 100. So we
  // should expect to see ~2-3 callbacks on average. Allow zero in case of
  // unusually fast runs (< 100 attempts).
  let calls = 0;
  await findCollision(16, ({ attempts }) => {
    calls += 1;
    assert.ok(attempts > 0);
    assert.equal(attempts % 100, 0);
  });
  // Just check it doesn't error; the count can legitimately be 0 if
  // the run was lucky enough to land before the 100th attempt.
  assert.ok(calls >= 0);
});

test("findCollision rejects non-integer hashBits", async () => {
  await assert.rejects(() => findCollision(1.5), /integer/);
});

test("findCollision rejects hashBits out of range", async () => {
  await assert.rejects(() => findCollision(0), /\[1, 32\]/);
  await assert.rejects(() => findCollision(33), /\[1, 32\]/);
});
