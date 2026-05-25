// Tests verifying the toy RSA parameters used by the Bleichenbacher demo
// are well-formed: primes are actually prime, e is coprime to (p-1)(q-1),
// e·d ≡ 1 mod φ, n is exactly k bytes long, and the target ciphertext
// decrypts back to the documented PKCS#1 v1.5 encoding of the plaintext.

import { test } from "node:test";
import assert from "node:assert/strict";
import { _bleichConfig as C } from "../bleich_config.js";

function isPrime(n) {
  if (n < 2n) return false;
  if (n < 4n) return true;
  if (n % 2n === 0n) return false;
  let i = 3n;
  while (i * i <= n) { if (n % i === 0n) return false; i += 2n; }
  return true;
}
function gcd(a, b) {
  a = a < 0n ? -a : a; b = b < 0n ? -b : b;
  while (b) { [a, b] = [b, a % b]; }
  return a;
}
function modPow(base, exp, mod) {
  let r = 1n;
  base = ((base % mod) + mod) % mod;
  while (exp > 0n) {
    if (exp & 1n) r = (r * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return r;
}

test("p is prime", () => {
  assert.ok(isPrime(C.p), `${C.p} is not prime`);
});

test("q is prime", () => {
  assert.ok(isPrime(C.q), `${C.q} is not prime`);
});

test("n = p · q", () => {
  assert.equal(C.n, C.p * C.q);
});

test("n is exactly k bytes long", () => {
  // n must be ≥ 2^{8(k-1)} (so the byte length is at least k) AND
  // n < 2^{8k} (so it's at most k). For k=8: 2^56 ≤ n < 2^64.
  const lower = 1n << BigInt(8 * (C.k - 1));
  const upper = 1n << BigInt(8 * C.k);
  assert.ok(C.n >= lower, `n=${C.n} is below 2^${8 * (C.k - 1)}`);
  assert.ok(C.n < upper, `n=${C.n} is at or above 2^${8 * C.k}`);
});

test("e is coprime to (p-1)(q-1)", () => {
  const phi = (C.p - 1n) * (C.q - 1n);
  assert.equal(gcd(C.e, phi), 1n);
});

test("e · d ≡ 1 (mod φ)", () => {
  const phi = (C.p - 1n) * (C.q - 1n);
  assert.equal((C.e * C.d) % phi, 1n);
});

test("paddedBytes matches the documented PKCS#1 v1.5 encoding of plaintext", () => {
  // 00 02 <ps_nonzero> 00 <message bytes>
  assert.equal(C.paddedBytes.length, C.k);
  assert.equal(C.paddedBytes[0], 0x00);
  assert.equal(C.paddedBytes[1], 0x02);
  // PS is everything between index 2 and the first 0x00 (must be nonzero
  // bytes, ≥1 long).
  let sepIdx = -1;
  for (let i = 2; i < C.paddedBytes.length; i++) {
    if (C.paddedBytes[i] === 0x00) { sepIdx = i; break; }
  }
  assert.ok(sepIdx >= 3, "0x00 separator must be at index ≥ 3");
  for (let i = 2; i < sepIdx; i++) {
    assert.notEqual(C.paddedBytes[i], 0x00, `PS byte at ${i} must be nonzero`);
  }
  // Bytes after the separator must equal the plaintext as ASCII.
  const msgBytes = C.paddedBytes.slice(sepIdx + 1);
  const decoded = String.fromCharCode(...msgBytes);
  assert.equal(decoded, C.plaintext);
});

test("paddedInt matches paddedBytes (big-endian)", () => {
  let expected = 0n;
  for (const b of C.paddedBytes) expected = (expected << 8n) | BigInt(b);
  assert.equal(C.paddedInt, expected);
});

test("targetCt = paddedInt^e mod n", () => {
  assert.equal(C.targetCt, modPow(C.paddedInt, C.e, C.n));
});

test("RSA round-trip: decrypt(targetCt) === paddedInt", () => {
  const decrypted = modPow(C.targetCt, C.d, C.n);
  assert.equal(decrypted, C.paddedInt);
});

test("paddedInt is PKCS#1 v1.5 conforming (2B ≤ m < 3B)", () => {
  // The leading bytes 0x00 0x02 mean the big-endian integer m satisfies
  // 2 · B ≤ m < 3 · B with B = 2^{8(k-2)}.
  const B = 1n << BigInt(8 * (C.k - 2));
  assert.ok(C.paddedInt >= 2n * B, `m=${C.paddedInt} should be ≥ 2B=${2n * B}`);
  assert.ok(C.paddedInt < 3n * B, `m=${C.paddedInt} should be < 3B=${3n * B}`);
});
