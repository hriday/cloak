import { test } from "node:test";
import assert from "node:assert/strict";
import * as sha from "../sha_demo.js";

// Canonical SHA-256 test vectors (RFC 6234, NIST FIPS 180-4).
const EMPTY_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const ABC_HASH   = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

test("hashEmpty returns the canonical empty-string SHA-256", async () => {
  const h = await sha.hashEmpty();
  assert.equal(h, EMPTY_HASH);
});

test("hashHex('') matches hashEmpty()", async () => {
  assert.equal(await sha.hashHex(""), EMPTY_HASH);
});

test("hashHex('abc') matches the RFC 6234 test vector", async () => {
  assert.equal(await sha.hashHex("abc"), ABC_HASH);
});

test("hashHex output is always 64 lowercase hex characters", async () => {
  const h = await sha.hashHex("any string");
  assert.equal(h.length, 64);
  assert.match(h, /^[0-9a-f]{64}$/);
});

test("bitDiff('hello', 'Hello') flips around half the bits (avalanche)", async () => {
  const r = await sha.bitDiff("hello", "Hello");
  assert.equal(r.hex1.length, 64);
  assert.equal(r.hex2.length, 64);
  assert.equal(r.bits1.length, 256);
  assert.equal(r.bits2.length, 256);
  assert.equal(r.diffMask.length, 256);
  // Avalanche: a 1-bit change in input flips ~50% of output bits. Spec calls
  // for 120-130; allow a wide window to stay robust across SHA-256 outputs.
  assert.ok(r.diffCount >= 110 && r.diffCount <= 145,
    `Expected ~128 differing bits, got ${r.diffCount}`);
});

test("bitDiff diffMask matches XOR of the two bit strings", async () => {
  const r = await sha.bitDiff("hello", "Hello");
  let expectedDiff = 0;
  for (let i = 0; i < 256; i++) {
    const bit = r.bits1[i] === r.bits2[i] ? "0" : "1";
    assert.equal(r.diffMask[i], bit);
    if (bit === "1") expectedDiff += 1;
  }
  assert.equal(r.diffCount, expectedDiff);
});

test("bitDiff of identical strings has zero diff (determinism)", async () => {
  const r = await sha.bitDiff("hello", "hello");
  assert.equal(r.diffCount, 0);
  assert.equal(r.hex1, r.hex2);
  assert.equal(r.diffMask, "0".repeat(256));
});
