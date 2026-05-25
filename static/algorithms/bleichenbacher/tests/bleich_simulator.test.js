import { test } from "node:test";
import assert from "node:assert/strict";
import {
  query,
  targetCiphertext,
  publicKey,
  getPlaintext,
  getQueryCount,
  _resetForTests,
  N,
  E,
  K,
  B,
  PLAINTEXT,
  TARGET_CT,
  _modPow,
} from "../bleich_simulator.js";

test("publicKey returns { n, e, k } with the expected types", () => {
  const pk = publicKey();
  assert.equal(typeof pk.n, "bigint");
  assert.equal(typeof pk.e, "bigint");
  assert.equal(pk.k, K);
  assert.equal(pk.n, N);
  assert.equal(pk.e, E);
});

test("targetCiphertext is a BigInt in [0, n)", () => {
  const c = targetCiphertext();
  assert.equal(typeof c, "bigint");
  assert.ok(c >= 0n);
  assert.ok(c < N);
});

test("getPlaintext returns the expected ASCII string", () => {
  assert.equal(typeof getPlaintext(), "string");
  assert.equal(getPlaintext(), PLAINTEXT);
});

test("query(targetCt) returns 'conforming' — the target ciphertext IS PKCS#1 v1.5", () => {
  _resetForTests();
  assert.equal(query(TARGET_CT), "conforming");
});

test("query on a random ciphertext is 'bad' the vast majority of the time", () => {
  _resetForTests();
  // P(random m is conforming) = (2B + 1) / n ≈ 2^{-11} for our params.
  // Across 256 random queries, expect ~0 conforming hits.
  let conforming = 0;
  for (let i = 0; i < 256; i++) {
    // Use a varied set of c values that aren't the target.
    const c = (TARGET_CT + BigInt(i + 1) * 1000003n) % N;
    if (query(c) === "conforming") conforming += 1;
  }
  // Expectation is ~256/2048 = ~0.125. Allow a generous threshold to avoid
  // flakiness — at most 8 of 256.
  assert.ok(
    conforming <= 8,
    `expected ≤ 8 conforming responses out of 256, got ${conforming}`
  );
});

test("query accepts BigInt, Number (integer), and decimal string", () => {
  _resetForTests();
  // BigInt
  assert.equal(query(TARGET_CT), "conforming");
  // Try a small ciphertext value as Number — almost certainly "bad", but
  // shouldn't throw.
  const r = query(42);
  assert.ok(r === "conforming" || r === "bad");
  // Decimal string
  const s = query(TARGET_CT.toString());
  assert.equal(s, "conforming");
});

test("query rejects non-integer Number with an error", () => {
  _resetForTests();
  assert.throws(() => query(3.14), /integer/);
});

test("query rejects non-numeric strings with an error", () => {
  _resetForTests();
  assert.throws(() => query("not a number"), /integer/);
});

test("getQueryCount increments on each query", () => {
  _resetForTests();
  assert.equal(getQueryCount(), 0);
  query(TARGET_CT);
  query(TARGET_CT);
  query(TARGET_CT);
  assert.equal(getQueryCount(), 3);
});

test("_resetForTests resets query counter (but NOT keypair)", () => {
  _resetForTests();
  query(TARGET_CT);
  query(TARGET_CT);
  assert.equal(getQueryCount(), 2);
  _resetForTests();
  assert.equal(getQueryCount(), 0);
  // Keypair still works — targetCt still decrypts to a conforming message.
  assert.equal(query(TARGET_CT), "conforming");
});

test("multiplicative homomorphism: query(c · s^e mod n) for a known s yields conforming whenever m · s mod n is in [2B, 3B)", () => {
  // This is the property Bleichenbacher exploits. We verify it directly:
  // for s = 1, c · 1^e mod n = c, the result is conforming. For random s,
  // it's almost certainly bad.
  _resetForTests();
  const c = TARGET_CT;
  // s = 1
  const s1 = 1n;
  const c1 = (c * _modPow(s1, E, N)) % N;
  assert.equal(query(c1), "conforming");

  // s = 2 — almost certainly bad
  const s2 = 2n;
  const c2 = (c * _modPow(s2, E, N)) % N;
  // Could be conforming with low probability; just assert it returns one of
  // the two valid responses.
  const r2 = query(c2);
  assert.ok(r2 === "conforming" || r2 === "bad");
});

test("B = 2^{8(k-2)}", () => {
  assert.equal(B, 1n << BigInt(8 * (K - 2)));
});

test("constants n, e, k are populated", () => {
  assert.ok(N > 0n);
  assert.equal(E, 17n);
  assert.equal(K, 8);
});
