import { test } from "node:test";
import assert from "node:assert/strict";
import {
  P, G, Q,
  modPow, modInv,
  generateKeypair, hashChallenge, sign, verify,
} from "../schnorr_demo.js";

const hasSubtle = typeof crypto !== "undefined" && !!crypto.subtle;

// --- Group sanity ----------------------------------------------------------

test("constants — p=467, g=4, q=233", () => {
  assert.equal(P, 467n);
  assert.equal(G, 4n);
  assert.equal(Q, 233n);
});

test("g has order q in (Z/pZ)*  (g^q ≡ 1 mod p)", () => {
  assert.equal(modPow(G, Q, P), 1n);
});

test("g has order exactly q (g^2 ≠ 1)", () => {
  // q is prime, so order(g) is 1 or q. g^2 = 16 ≠ 1, so order(g) > 1, hence = q.
  assert.notEqual(modPow(G, 2n, P), 1n);
});

test("q divides p-1", () => {
  assert.equal((P - 1n) % Q, 0n);
  assert.equal((P - 1n) / Q, 2n);
});

// --- modPow / modInv -------------------------------------------------------

test("modPow(4, 0, 467) = 1", () => {
  assert.equal(modPow(4n, 0n, 467n), 1n);
});

test("modPow(4, 1, 467) = 4", () => {
  assert.equal(modPow(4n, 1n, 467n), 4n);
});

test("modPow(4, 2, 467) = 16", () => {
  assert.equal(modPow(4n, 2n, 467n), 16n);
});

test("modPow handles large exponents (4^232 · 4 = 4^233 ≡ 1)", () => {
  const a = modPow(4n, 232n, 467n);
  assert.equal((a * 4n) % 467n, 1n);
});

test("modInv: 3^{-1} mod 11 = 4", () => {
  assert.equal(modInv(3n, 11n), 4n);
  assert.equal((3n * 4n) % 11n, 1n);
});

test("modInv: throws on 0", () => {
  assert.throws(() => modInv(0n, 11n));
});

// --- generateKeypair -------------------------------------------------------

test("generateKeypair with seed produces deterministic (x, X)", () => {
  const a = generateKeypair(99n);
  const b = generateKeypair(99n);
  assert.equal(a.x, b.x);
  assert.equal(a.X, b.X);
});

test("generateKeypair: seed=99 gives x=100 (99 mod 232 + 1 = 100)", () => {
  const { x } = generateKeypair(99n);
  assert.equal(x, 100n);
});

test("generateKeypair: seed=99 → X = 4^100 mod 467 (fixed regression check)", () => {
  // Locked here so the lesson template's rendered public key matches what
  // the page actually computes when the user first hits the sign-and-verify
  // step. If anyone changes the seed or the group, this test points at the
  // template / fixtures that need updating.
  const { X } = generateKeypair(99n);
  assert.equal(X, 229n);
});

test("generateKeypair: x ∈ [1, Q-1]", () => {
  const { x } = generateKeypair(99n);
  assert.ok(x >= 1n && x < Q);
});

test("generateKeypair: X = g^x mod p", () => {
  const { x, X } = generateKeypair(99n);
  assert.equal(X, modPow(G, x, P));
});

test("generateKeypair without seed produces x in valid range", () => {
  const { x, X } = generateKeypair();
  assert.ok(x >= 1n && x < Q);
  assert.equal(X, modPow(G, x, P));
});

// --- hashChallenge ---------------------------------------------------------

test("hashChallenge returns a BigInt in [0, q)", async (t) => {
  if (!hasSubtle) { t.skip("crypto.subtle not available"); return; }
  const e = await hashChallenge(123n, 45n, "hello");
  assert.equal(typeof e, "bigint");
  assert.ok(e >= 0n && e < Q);
});

test("hashChallenge is deterministic for same (R, X, message)", async (t) => {
  if (!hasSubtle) { t.skip("crypto.subtle not available"); return; }
  const e1 = await hashChallenge(123n, 45n, "hello");
  const e2 = await hashChallenge(123n, 45n, "hello");
  assert.equal(e1, e2);
});

test("hashChallenge depends on the message", async (t) => {
  if (!hasSubtle) { t.skip("crypto.subtle not available"); return; }
  const e1 = await hashChallenge(123n, 45n, "hello");
  const e2 = await hashChallenge(123n, 45n, "world");
  assert.notEqual(e1, e2);
});

test("hashChallenge depends on R", async (t) => {
  if (!hasSubtle) { t.skip("crypto.subtle not available"); return; }
  const e1 = await hashChallenge(123n, 45n, "hello");
  const e2 = await hashChallenge(124n, 45n, "hello");
  assert.notEqual(e1, e2);
});

// --- sign / verify ---------------------------------------------------------

test("sign returns R = g^k mod p", async (t) => {
  if (!hasSubtle) { t.skip("crypto.subtle not available"); return; }
  const { x } = generateKeypair(99n);    // x = 100
  const { R, k } = await sign(x, "hello", 42n);
  assert.equal(R, modPow(G, k, P));
});

test("sign with fixed nonce is deterministic", async (t) => {
  if (!hasSubtle) { t.skip("crypto.subtle not available"); return; }
  const { x } = generateKeypair(99n);
  const a = await sign(x, "hello", 42n);
  const b = await sign(x, "hello", 42n);
  assert.equal(a.R, b.R);
  assert.equal(a.s, b.s);
  assert.equal(a.e, b.e);
});

test("sign satisfies the response equation s ≡ k + e·x (mod q)", async (t) => {
  if (!hasSubtle) { t.skip("crypto.subtle not available"); return; }
  const { x } = generateKeypair(99n);
  const { s, e, k } = await sign(x, "hello", 42n);
  const expected = (k + e * x) % Q;
  assert.equal(s, expected);
});

test("verify returns valid:true for a fresh signature", async (t) => {
  if (!hasSubtle) { t.skip("crypto.subtle not available"); return; }
  const { x, X } = generateKeypair(99n);
  const sig = await sign(x, "hello", 42n);
  const result = await verify(X, "hello", sig);
  assert.equal(result.valid, true);
  assert.equal(result.lhs, result.rhs);
});

test("verify equation: g^s ≡ R · X^e (mod p) on every valid signature", async (t) => {
  if (!hasSubtle) { t.skip("crypto.subtle not available"); return; }
  const { x, X } = generateKeypair(99n);
  for (const m of ["hello", "world", "schnorr", "bitcoin taproot"]) {
    const sig = await sign(x, m);
    const result = await verify(X, m, sig);
    assert.equal(result.valid, true, `signature on '${m}' should verify`);
    assert.equal(result.lhs, result.rhs, "lhs should equal rhs");
  }
});

test("verify rejects a tampered s", async (t) => {
  if (!hasSubtle) { t.skip("crypto.subtle not available"); return; }
  const { x, X } = generateKeypair(99n);
  const sig = await sign(x, "hello", 42n);
  const tampered = { R: sig.R, s: (sig.s + 1n) % Q };
  const result = await verify(X, "hello", tampered);
  assert.equal(result.valid, false);
  assert.notEqual(result.lhs, result.rhs);
});

test("verify rejects a tampered R", async (t) => {
  if (!hasSubtle) { t.skip("crypto.subtle not available"); return; }
  const { x, X } = generateKeypair(99n);
  const sig = await sign(x, "hello", 42n);
  const tampered = { R: (sig.R + 1n) % P, s: sig.s };
  const result = await verify(X, "hello", tampered);
  assert.equal(result.valid, false);
});

test("verify rejects a signature on a different message", async (t) => {
  if (!hasSubtle) { t.skip("crypto.subtle not available"); return; }
  const { x, X } = generateKeypair(99n);
  const sig = await sign(x, "hello", 42n);
  const result = await verify(X, "HELLO", sig);
  assert.equal(result.valid, false);
});

test("verify rejects a signature under the wrong public key", async (t) => {
  if (!hasSubtle) { t.skip("crypto.subtle not available"); return; }
  const { x } = generateKeypair(99n);
  const { X: wrongX } = generateKeypair(101n);
  const sig = await sign(x, "hello", 42n);
  const result = await verify(wrongX, "hello", sig);
  assert.equal(result.valid, false);
});

test("verify rejects R out of range", async (t) => {
  if (!hasSubtle) { t.skip("crypto.subtle not available"); return; }
  const { X } = generateKeypair(99n);
  const result = await verify(X, "hello", { R: 0n, s: 5n });
  assert.equal(result.valid, false);
});

test("verify rejects s out of range", async (t) => {
  if (!hasSubtle) { t.skip("crypto.subtle not available"); return; }
  const { X } = generateKeypair(99n);
  const result = await verify(X, "hello", { R: 16n, s: Q });
  assert.equal(result.valid, false);
});

// --- The pedagogical payoff: linearity / MuSig ----------------------------
//
// If Alice has (xA, XA) and Bob has (xB, XB), they can jointly sign with
// combined key XAB = XA · XB by each picking their own nonce, publishing the
// commitment RA / RB, computing joint R = RA · RB, computing the shared
// challenge e against the combined key, and each contributing sA = kA + e·xA,
// sB = kB + e·xB. The combined signature (R, sA + sB) verifies under XAB.
// This is the load-bearing test for the linearity step's claim.

test("multi-sig: combined sig (RA·RB, sA+sB) verifies under XA·XB", async (t) => {
  if (!hasSubtle) { t.skip("crypto.subtle not available"); return; }
  const A = generateKeypair(11n);   // xA, XA
  const B = generateKeypair(77n);   // xB, XB
  const kA = 17n, kB = 29n;
  const RA = modPow(G, kA, P);
  const RB = modPow(G, kB, P);
  const Rjoint = (RA * RB) % P;
  const Xjoint = (A.X * B.X) % P;
  const message = "co-signed by Alice and Bob";
  const e = await hashChallenge(Rjoint, Xjoint, message);
  const sA = (kA + e * A.x) % Q;
  const sB = (kB + e * B.x) % Q;
  const sJoint = (sA + sB) % Q;

  const result = await verify(Xjoint, message, { R: Rjoint, s: sJoint });
  assert.equal(result.valid, true, "joint Schnorr signature must verify under combined key");
  assert.equal(result.lhs, result.rhs);
});

test("multi-sig: each party's individual share is NOT a valid signature under Xjoint", async (t) => {
  // Sanity: only the combined (sA + sB) verifies. sA alone, with Rjoint,
  // shouldn't — that's why the construction is meaningful (each party
  // contributes their share without revealing their key).
  if (!hasSubtle) { t.skip("crypto.subtle not available"); return; }
  const A = generateKeypair(11n);
  const B = generateKeypair(77n);
  const kA = 17n, kB = 29n;
  const RA = modPow(G, kA, P);
  const RB = modPow(G, kB, P);
  const Rjoint = (RA * RB) % P;
  const Xjoint = (A.X * B.X) % P;
  const message = "co-signed by Alice and Bob";
  const e = await hashChallenge(Rjoint, Xjoint, message);
  const sA = (kA + e * A.x) % Q;

  const result = await verify(Xjoint, message, { R: Rjoint, s: sA });
  assert.equal(result.valid, false);
});
