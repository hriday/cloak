import { test } from "node:test";
import assert from "node:assert/strict";
import {
  Q,
  N,
  mod,
  polyAdd,
  polySub,
  polyMul,
  matVecMul,
  transpose,
  vecDot,
} from "../poly.js";

// ---- ring constants -------------------------------------------------------

test("ring parameters match the lesson's locked toy choice", () => {
  assert.equal(Q, 257);
  assert.equal(N, 4);
});

// ---- mod ------------------------------------------------------------------

test("mod normalises negative residues into [0, q)", () => {
  assert.equal(mod(-1), 256);
  assert.equal(mod(-258), 256);
  assert.equal(mod(0), 0);
  assert.equal(mod(257), 0);
  assert.equal(mod(256), 256);
});

test("mod accepts a custom modulus", () => {
  assert.equal(mod(-1, 17), 16);
  assert.equal(mod(20, 17), 3);
});

// ---- polyAdd / polySub ----------------------------------------------------

test("polyAdd is coefficient-wise mod q", () => {
  assert.deepEqual(
    polyAdd([1, 2, 3, 4], [5, 6, 7, 8]),
    [6, 8, 10, 12]
  );
});

test("polyAdd wraps past q", () => {
  assert.deepEqual(
    polyAdd([200, 200, 200, 200], [100, 100, 100, 100]),
    [43, 43, 43, 43] // 300 mod 257 = 43
  );
});

test("polySub canonicalises into [0, q)", () => {
  // 1 - 2 = -1 ≡ 256
  assert.deepEqual(
    polySub([1, 0, 0, 0], [2, 0, 0, 0]),
    [256, 0, 0, 0]
  );
});

test("polyAdd / polySub reject length mismatch", () => {
  assert.throws(() => polyAdd([0, 0], [0, 0, 0, 0]));
  assert.throws(() => polySub([0, 0], [0, 0, 0, 0]));
});

// ---- polyMul --------------------------------------------------------------

// The lesson's worked example from step 3:
//   (1 + 2X) · (3 + X^3) mod (X^4 + 1)
// First expand:
//   3 + X^3 + 6X + 2X^4
// Then reduce: 2X^4 = 2 · X · X^3 = 2 · (-1) = -2 (since X^4 = -1):
//   (3 - 2) + 6X + X^3 = 1 + 6X + X^3
// In R_257 (no further wrapping needed for these small numbers).
test("polyMul: (1 + 2X)·(3 + X^3) = 1 + 6X + X^3 mod (X^4+1)", () => {
  assert.deepEqual(
    polyMul([1, 2, 0, 0], [3, 0, 0, 1]),
    [1, 6, 0, 1]
  );
});

// The minimal demonstration of X^4 = -1: X · X^3 should give -1 ≡ q-1.
test("polyMul: X · X^3 = -1 = q-1 mod (X^4+1)", () => {
  assert.deepEqual(
    polyMul([0, 1, 0, 0], [0, 0, 0, 1]),
    [Q - 1, 0, 0, 0]
  );
});

test("polyMul: multiplying by 1 is the identity", () => {
  const one = [1, 0, 0, 0];
  const a = [5, 17, 200, 99];
  assert.deepEqual(polyMul(a, one), a);
  assert.deepEqual(polyMul(one, a), a);
});

test("polyMul: multiplying by 0 gives 0", () => {
  const zero = [0, 0, 0, 0];
  const a = [5, 17, 200, 99];
  assert.deepEqual(polyMul(a, zero), zero);
});

test("polyMul is commutative on a random example", () => {
  const a = [13, 200, 4, 100];
  const b = [5, 17, 250, 1];
  assert.deepEqual(polyMul(a, b), polyMul(b, a));
});

// X^2 · X^2 = X^4 = -1 — another wrap-around sanity check.
test("polyMul: X^2 · X^2 = -1 = q-1", () => {
  assert.deepEqual(
    polyMul([0, 0, 1, 0], [0, 0, 1, 0]),
    [Q - 1, 0, 0, 0]
  );
});

// Negative coefficients (from {-1, 0, 1} small polys) should flow through the
// modular reduction cleanly.
test("polyMul handles negative-coefficient inputs", () => {
  // (-1 + X) · (1 + X) = -1 - X + X + X^2 = -1 + X^2
  // mod q -> [256, 0, 1, 0]
  assert.deepEqual(
    polyMul([-1, 1, 0, 0], [1, 1, 0, 0]),
    [256, 0, 1, 0]
  );
});

// ---- transpose ------------------------------------------------------------

test("transpose swaps row/column indices, preserving polynomial entries", () => {
  const a = [[1, 0, 0, 0], [2, 0, 0, 0]];
  const b = [[3, 0, 0, 0], [4, 0, 0, 0]];
  const mat = [[a[0], a[1]], [b[0], b[1]]];
  const t = transpose(mat);
  assert.deepEqual(t[0][0], a[0]);
  assert.deepEqual(t[0][1], b[0]);
  assert.deepEqual(t[1][0], a[1]);
  assert.deepEqual(t[1][1], b[1]);
});

// ---- matVecMul ------------------------------------------------------------

// Hand-computed 2×2 example.
//   A = [[ X,    1 ],
//        [ 1+X,  0 ]]
//   v = [ 1, X ]
//   A·v[0] = X·1 + 1·X = 2X
//   A·v[1] = (1+X)·1 + 0·X = 1+X
test("matVecMul: 2×2 matrix times 2-vector — hand-computed", () => {
  const A = [
    [[0, 1, 0, 0], [1, 0, 0, 0]],
    [[1, 1, 0, 0], [0, 0, 0, 0]],
  ];
  const v = [[1, 0, 0, 0], [0, 1, 0, 0]];
  assert.deepEqual(matVecMul(A, v), [
    [0, 2, 0, 0],
    [1, 1, 0, 0],
  ]);
});

// ---- vecDot ---------------------------------------------------------------

test("vecDot: [1, X]·[X, 1] = X + X = 2X (in R_257)", () => {
  const a = [[1, 0, 0, 0], [0, 1, 0, 0]];
  const b = [[0, 1, 0, 0], [1, 0, 0, 0]];
  assert.deepEqual(vecDot(a, b), [0, 2, 0, 0]);
});

test("vecDot rejects length mismatch", () => {
  const a = [[1, 0, 0, 0]];
  const b = [[1, 0, 0, 0], [0, 1, 0, 0]];
  assert.throws(() => vecDot(a, b));
});
