import { test } from "node:test";
import assert from "node:assert/strict";
import {
  Q,
  N,
  mod,
  centered,
  polyAdd,
  polySub,
  polyMul,
  polyScalarMul,
  matVecMul,
  transpose,
  vecAdd,
  vecSub,
  vecPolyMul,
  polyInfinityNorm,
  vecInfinityNorm,
} from "../poly.js";

// ---- ring constants -------------------------------------------------------

test("ring parameters match the locked toy choice", () => {
  assert.equal(Q, 257);
  assert.equal(N, 4);
});

// ---- mod / centered -------------------------------------------------------

test("mod normalises negative residues into [0, q)", () => {
  assert.equal(mod(-1), 256);
  assert.equal(mod(-258), 256);
  assert.equal(mod(0), 0);
  assert.equal(mod(257), 0);
  assert.equal(mod(256), 256);
});

test("centered maps canonical [0, q) to signed (-q/2, q/2]", () => {
  assert.equal(centered(0), 0);
  assert.equal(centered(1), 1);
  assert.equal(centered(128), 128);
  assert.equal(centered(129), 129 - 257);
  assert.equal(centered(256), -1);
});

// ---- polyAdd / polySub ----------------------------------------------------

test("polyAdd is coefficient-wise mod q", () => {
  assert.deepEqual(polyAdd([1, 2, 3, 4], [5, 6, 7, 8]), [6, 8, 10, 12]);
});

test("polyAdd wraps past q", () => {
  assert.deepEqual(
    polyAdd([200, 200, 200, 200], [100, 100, 100, 100]),
    [43, 43, 43, 43]
  );
});

test("polySub canonicalises into [0, q)", () => {
  assert.deepEqual(polySub([1, 0, 0, 0], [2, 0, 0, 0]), [256, 0, 0, 0]);
});

test("polyAdd / polySub reject length mismatch", () => {
  assert.throws(() => polyAdd([0, 0], [0, 0, 0, 0]));
  assert.throws(() => polySub([0, 0], [0, 0, 0, 0]));
});

// ---- polyMul --------------------------------------------------------------

// (1 + 2X) · (3 + X^3) in R_257[X]/(X^4 + 1) — same hand-computed example as
// the Kyber lesson, kept here so the dilithium poly module passes the same
// regression independently.
test("polyMul: (1 + 2X)·(3 + X^3) = 1 + 6X + X^3 mod (X^4+1)", () => {
  assert.deepEqual(polyMul([1, 2, 0, 0], [3, 0, 0, 1]), [1, 6, 0, 1]);
});

test("polyMul: X · X^3 = -1 = q-1 mod (X^4+1)", () => {
  assert.deepEqual(polyMul([0, 1, 0, 0], [0, 0, 0, 1]), [Q - 1, 0, 0, 0]);
});

test("polyMul: X^2 · X^2 = -1 = q-1", () => {
  assert.deepEqual(polyMul([0, 0, 1, 0], [0, 0, 1, 0]), [Q - 1, 0, 0, 0]);
});

test("polyMul: multiplying by 1 is identity", () => {
  const one = [1, 0, 0, 0];
  const a = [5, 17, 200, 99];
  assert.deepEqual(polyMul(a, one), a);
  assert.deepEqual(polyMul(one, a), a);
});

test("polyMul is commutative", () => {
  const a = [13, 200, 4, 100];
  const b = [5, 17, 250, 1];
  assert.deepEqual(polyMul(a, b), polyMul(b, a));
});

// ---- polyScalarMul --------------------------------------------------------

test("polyScalarMul multiplies every coefficient", () => {
  assert.deepEqual(polyScalarMul([1, 2, 3, 4], 5), [5, 10, 15, 20]);
});

test("polyScalarMul wraps mod q", () => {
  // 200 * 2 = 400 mod 257 = 143
  assert.deepEqual(polyScalarMul([200, 0, 0, 0], 2), [143, 0, 0, 0]);
});

// ---- matVecMul ------------------------------------------------------------

test("matVecMul: 2×2 matrix times 2-vector — hand-computed", () => {
  const A = [
    [[0, 1, 0, 0], [1, 0, 0, 0]],
    [[1, 1, 0, 0], [0, 0, 0, 0]],
  ];
  const v = [[1, 0, 0, 0], [0, 1, 0, 0]];
  // A·v[0] = X·1 + 1·X = 2X
  // A·v[1] = (1+X)·1 + 0·X = 1+X
  assert.deepEqual(matVecMul(A, v), [
    [0, 2, 0, 0],
    [1, 1, 0, 0],
  ]);
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

// ---- vecAdd / vecSub / vecPolyMul ----------------------------------------

test("vecAdd adds k-vectors coefficient-wise", () => {
  const a = [[1, 2, 3, 4], [5, 6, 7, 8]];
  const b = [[10, 20, 30, 40], [50, 60, 70, 80]];
  assert.deepEqual(vecAdd(a, b), [
    [11, 22, 33, 44],
    [55, 66, 77, 88],
  ]);
});

test("vecSub subtracts k-vectors coefficient-wise", () => {
  const a = [[2, 4, 6, 8], [1, 1, 1, 1]];
  const b = [[1, 2, 3, 4], [0, 0, 0, 0]];
  assert.deepEqual(vecSub(a, b), [
    [1, 2, 3, 4],
    [1, 1, 1, 1],
  ]);
});

test("vecPolyMul multiplies each vector entry by a single polynomial c", () => {
  // c = X, vec = [1, X^2]
  // c·vec[0] = X·1 = X
  // c·vec[1] = X·X^2 = X^3
  assert.deepEqual(
    vecPolyMul([0, 1, 0, 0], [[1, 0, 0, 0], [0, 0, 1, 0]]),
    [[0, 1, 0, 0], [0, 0, 0, 1]]
  );
});

// ---- polyInfinityNorm / vecInfinityNorm ----------------------------------

test("polyInfinityNorm uses signed representation", () => {
  // 256 in canonical = -1 signed, norm = 1
  assert.equal(polyInfinityNorm([256, 0, 0, 0]), 1);
  // 128 in canonical = 128 (since half = floor(257/2) = 128, NOT > half so stays)
  assert.equal(polyInfinityNorm([128, 0, 0, 0]), 128);
  // 129 in canonical = -128 signed, norm = 128
  assert.equal(polyInfinityNorm([129, 0, 0, 0]), 128);
});

test("polyInfinityNorm reports the max across coefficients", () => {
  // Coefficients: 1, 256 (=-1), 5, 252 (=-5)
  assert.equal(polyInfinityNorm([1, 256, 5, 252]), 5);
});

test("polyInfinityNorm of the zero polynomial is 0", () => {
  assert.equal(polyInfinityNorm([0, 0, 0, 0]), 0);
});

test("vecInfinityNorm reports max across the whole vector", () => {
  assert.equal(
    vecInfinityNorm([
      [1, 2, 3, 0],
      [0, 0, 0, 252], // = -5 signed
    ]),
    5
  );
});
