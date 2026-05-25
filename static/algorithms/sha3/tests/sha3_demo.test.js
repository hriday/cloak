import { test } from "node:test";
import assert from "node:assert/strict";
import * as sha3 from "../sha3_demo.js";

// Canonical SHA3-256 test vectors (NIST FIPS 202 / CAVS).
const EMPTY_HASH = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
const ABC_HASH   = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";
const HELLO_HASH = "3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392";

test("hashEmpty returns the canonical empty-string SHA3-256", async () => {
  const h = await sha3.hashEmpty();
  assert.equal(h, EMPTY_HASH);
});

test("hashHex('') matches hashEmpty()", async () => {
  assert.equal(await sha3.hashHex(""), EMPTY_HASH);
});

test("hashHex('abc') matches the FIPS 202 test vector", async () => {
  assert.equal(await sha3.hashHex("abc"), ABC_HASH);
});

test("hashHex('hello') matches the well-known SHA3-256 of 'hello'", async () => {
  assert.equal(await sha3.hashHex("hello"), HELLO_HASH);
});

test("hashHex output is always 64 lowercase hex characters", async () => {
  const h = await sha3.hashHex("any string");
  assert.equal(h.length, 64);
  assert.match(h, /^[0-9a-f]{64}$/);
});

test("hashHex handles inputs longer than the rate (136 bytes) — exercises multi-block absorb", async () => {
  // A 200-byte input forces two absorb iterations (rate = 136).
  const longInput = "a".repeat(200);
  const h = await sha3.hashHex(longInput);
  assert.equal(h.length, 64);
  assert.match(h, /^[0-9a-f]{64}$/);
  // Determinism check: same input twice produces same output.
  const h2 = await sha3.hashHex(longInput);
  assert.equal(h, h2);
});

test("hashHex handles input exactly at the rate boundary (135 bytes — forces a fresh padded block)", async () => {
  // When input length mod 136 is 135, padding shrinks to 1 byte → 0x06|0x80 share a byte.
  const h = await sha3.hashHex("a".repeat(135));
  assert.equal(h.length, 64);
  assert.match(h, /^[0-9a-f]{64}$/);
});

test("hashHex is sensitive to single-bit changes (avalanche sanity)", async () => {
  // Not asserting exact bit-flip counts here (no bitDiff in this demo), just
  // confirming the two digests differ — protects against an accidental no-op
  // implementation that returns the same value for everything.
  const a = await sha3.hashHex("hello");
  const b = await sha3.hashHex("Hello");
  assert.notEqual(a, b);
});
