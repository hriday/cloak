import { test } from "node:test";
import assert from "node:assert/strict";
import {
  P, A, B, G, N,
  addPoints, scalarMul, signToy,
  recoverKFromReusedNonce, recoverDFromK, modInverse,
} from "../ecdsa_toy.js";

// Curve sanity — G must satisfy y^2 ≡ x^3 + ax + b (mod p).
test("generator G = (2, 7) lies on y^2 = x^3 + x + 6 (mod 11)", () => {
  const lhs = (G.y * G.y) % P;
  const rhs = ((G.x * G.x * G.x) + A * G.x + B) % P;
  assert.equal(lhs, rhs);
});

test("modInverse: 3^{-1} mod 13 = 9", () => {
  assert.equal(modInverse(3, 13), 9);
  assert.equal((3 * 9) % 13, 1);
});

test("modInverse: 8^{-1} mod 13 = 5", () => {
  assert.equal(modInverse(8, 13), 5);
});

test("modInverse: 11^{-1} mod 13 = 6", () => {
  assert.equal(modInverse(11, 13), 6);
});

test("modInverse: throws on 0", () => {
  assert.throws(() => modInverse(0, 13));
});

test("modInverse: handles negative input via reduction", () => {
  // -2 ≡ 11 (mod 13), so (-2)^{-1} should equal 11^{-1} = 6.
  assert.equal(modInverse(-2, 13), 6);
});

// Point arithmetic — hand-computed values from the spec.
test("2·G = (5, 2)", () => {
  const twoG = addPoints(G, G);
  assert.deepEqual(twoG, { x: 5, y: 2 });
});

test("3·G = (8, 3) via doubling-then-adding", () => {
  const twoG = addPoints(G, G);
  const threeG = addPoints(twoG, G);
  assert.deepEqual(threeG, { x: 8, y: 3 });
});

test("scalarMul(3, G) = (8, 3)", () => {
  assert.deepEqual(scalarMul(3, G), { x: 8, y: 3 });
});

test("scalarMul(2, G) = (5, 2)", () => {
  assert.deepEqual(scalarMul(2, G), { x: 5, y: 2 });
});

test("scalarMul(1, G) = G", () => {
  assert.deepEqual(scalarMul(1, G), G);
});

test("scalarMul(13, G) = identity (group has order n=13)", () => {
  assert.equal(scalarMul(13, G), null);
});

test("scalarMul(0, G) = identity", () => {
  assert.equal(scalarMul(0, G), null);
});

test("addPoints: P + (-P) = identity", () => {
  // For G = (2, 7), -G = (2, -7) = (2, 4) mod 11.
  const negG = { x: 2, y: 4 };
  assert.equal(addPoints(G, negG), null);
});

test("addPoints: identity is the neutral element", () => {
  assert.deepEqual(addPoints(null, G), G);
  assert.deepEqual(addPoints(G, null), G);
});

// --- The PS3 scenario --------------------------------------------------------
// d = 7, k = 3, e1 = 4, e2 = 10. Hand-computed in the spec:
//   r  = (3·G).x mod 13 = 8
//   s1 = 9 · (4 + 8·7) mod 13 = 7
//   s2 = 9 · (10 + 8·7) mod 13 = 9

test("signToy(d=7, k=3, e=4) = { r:8, s:7 }", () => {
  assert.deepEqual(signToy(7, 3, 4), { r: 8, s: 7 });
});

test("signToy(d=7, k=3, e=10) = { r:8, s:9 } — same r because same k", () => {
  assert.deepEqual(signToy(7, 3, 10), { r: 8, s: 9 });
});

test("signToy is deterministic for fixed (d, k, e)", () => {
  const a = signToy(7, 3, 4);
  const b = signToy(7, 3, 4);
  assert.deepEqual(a, b);
});

test("recoverKFromReusedNonce(s1=7, s2=9, e1=4, e2=10) = 3", () => {
  assert.equal(recoverKFromReusedNonce(7, 9, 4, 10), 3);
});

test("recoverKFromReusedNonce handles negative differences mod n", () => {
  // (e1 - e2) = -6 ≡ 7 (mod 13); (s1 - s2) = -2 ≡ 11 (mod 13).
  // Without proper mod handling this would explode.
  const k = recoverKFromReusedNonce(7, 9, 4, 10);
  assert.equal(k, 3);
});

test("recoverDFromK(k=3, r=8, s=7, e=4) = 7 — Sony's signing key", () => {
  assert.equal(recoverDFromK(3, 8, 7, 4), 7);
});

test("recoverDFromK using the second signature also gives d=7", () => {
  assert.equal(recoverDFromK(3, 8, 9, 10), 7);
});

test("end-to-end attack: two signatures with reused k recover d", () => {
  const sig1 = signToy(7, 3, 4);
  const sig2 = signToy(7, 3, 10);
  assert.equal(sig1.r, sig2.r);                                    // same r
  const k = recoverKFromReusedNonce(sig1.s, sig2.s, 4, 10);
  assert.equal(k, 3);
  const d = recoverDFromK(k, sig1.r, sig1.s, 4);
  assert.equal(d, 7);
});
