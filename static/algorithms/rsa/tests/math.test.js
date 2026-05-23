import { test } from "node:test";
import assert from "node:assert/strict";
import { isPrime, gcd, modInv, modPow, phi, coprimeCandidates } from "../math.js";
import * as m from "../math.js";

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

test("textToCodes converts ASCII string to ASCII codes", () => {
  assert.deepEqual(m.textToCodes("Hi"), [72, 105]);
  assert.deepEqual(m.textToCodes(""), []);
  assert.deepEqual(m.textToCodes("A B"), [65, 32, 66]);
});

test("codesToText is inverse of textToCodes", () => {
  assert.equal(m.codesToText([72, 105]), "Hi");
  assert.equal(m.codesToText([]), "");
  const roundtrip = "Hello, world!";
  assert.equal(m.codesToText(m.textToCodes(roundtrip)), roundtrip);
});

test("toBinary8 zero-pads to 8 bits", () => {
  assert.equal(m.toBinary8(72), "01001000");
  assert.equal(m.toBinary8(0), "00000000");
  assert.equal(m.toBinary8(255), "11111111");
  assert.equal(m.toBinary8(1), "00000001");
});
