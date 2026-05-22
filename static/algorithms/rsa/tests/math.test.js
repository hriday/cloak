import { test } from "node:test";
import assert from "node:assert/strict";
import { isPrime, gcd, modInv, modPow, phi, coprimeCandidates } from "../math.js";

test("isPrime", () => {
  assert.equal(isPrime(2n), true);
  assert.equal(isPrime(61n), true);
  assert.equal(isPrime(997n), true);
  assert.equal(isPrime(1n), false);
  assert.equal(isPrime(60n), false);
});

test("gcd", () => {
  assert.equal(gcd(48n, 18n), 6n);
  assert.equal(gcd(17n, 5n), 1n);
});

test("phi", () => {
  assert.equal(phi(61n, 53n), 3120n);
});

test("modInv", () => {
  assert.equal(modInv(17n, 3120n), 2753n);
});

test("modPow encrypt/decrypt roundtrip", () => {
  const c = modPow(65n, 17n, 3233n);
  assert.equal(modPow(c, 2753n, 3233n), 65n);
});

test("coprimeCandidates", () => {
  const cands = coprimeCandidates(3120n, 10);
  assert.equal(cands.length, 10);
  for (const e of cands) {
    assert.equal(gcd(e, 3120n), 1n);
  }
});
