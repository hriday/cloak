import { test } from "node:test";
import assert from "node:assert/strict";
import {
  K,
  N,
  Q,
  HALF_Q,
  QUARTER_Q,
  LESSON_SEED,
  makeRng,
  keygen,
  encapsulate,
  decapsulate,
  encodeBit,
  decodeBit,
  frozenVectors,
} from "../kyber_demo.js";

// ---- constants ------------------------------------------------------------

test("module parameters match the lesson's locked toy choice", () => {
  assert.equal(K, 2);
  assert.equal(N, 4);
  assert.equal(Q, 257);
  assert.equal(HALF_Q, 128);
  assert.equal(QUARTER_Q, 64);
});

// ---- encodeBit / decodeBit ------------------------------------------------

test("encodeBit(0) is the zero polynomial", () => {
  assert.deepEqual(encodeBit(0), [0, 0, 0, 0]);
});

test("encodeBit(1) puts q/2 in coefficient 0", () => {
  assert.deepEqual(encodeBit(1), [128, 0, 0, 0]);
});

test("decodeBit reads bit 1 from a coefficient near q/2", () => {
  assert.equal(decodeBit([128, 0, 0, 0]), 1);
  assert.equal(decodeBit([100, 0, 0, 0]), 1); // 100 ∈ [64, 193]
  assert.equal(decodeBit([193, 0, 0, 0]), 1); // 193 ∈ [64, 193]
});

test("decodeBit reads bit 0 from a coefficient near 0 or near q", () => {
  assert.equal(decodeBit([0, 0, 0, 0]), 0);
  assert.equal(decodeBit([10, 0, 0, 0]), 0);
  assert.equal(decodeBit([Q - 1, 0, 0, 0]), 0); // 256 (~ -1), close to 0
  assert.equal(decodeBit([Q - 10, 0, 0, 0]), 0);
});

// The boundary case: 63 should decode to 0, 64 should decode to 1.
test("decodeBit boundary is q/4 = 64", () => {
  assert.equal(decodeBit([63, 0, 0, 0]), 0);
  assert.equal(decodeBit([64, 0, 0, 0]), 1);
  assert.equal(decodeBit([193, 0, 0, 0]), 1); // q - q/4 = 193
  assert.equal(decodeBit([194, 0, 0, 0]), 0);
});

// ---- PRNG -----------------------------------------------------------------

test("makeRng produces deterministic output for the same seed", () => {
  const a = makeRng("seed-x");
  const b = makeRng("seed-x");
  for (let i = 0; i < 100; i++) {
    assert.equal(a.uniform(), b.uniform());
  }
});

test("makeRng produces different streams for different seeds", () => {
  const a = makeRng("seed-x");
  const b = makeRng("seed-y");
  // The very first sample will already disagree with overwhelming probability.
  // The test checks the first 5 just to be safe.
  let anyDifferent = false;
  for (let i = 0; i < 5; i++) {
    if (a.uniform() !== b.uniform()) {
      anyDifferent = true;
      break;
    }
  }
  assert.equal(anyDifferent, true);
});

test("makeRng.small samples from {-1, 0, 1} only", () => {
  const r = makeRng("smallness-test");
  for (let i = 0; i < 1000; i++) {
    const s = r.small();
    assert.ok(s === -1 || s === 0 || s === 1, "got " + s);
  }
});

test("makeRng.uniform stays in [0, q)", () => {
  const r = makeRng("uniformness-test");
  for (let i = 0; i < 1000; i++) {
    const u = r.uniform();
    assert.ok(u >= 0 && u < Q, "got " + u);
  }
});

// ---- frozen-vector regression --------------------------------------------
//
// These pinned values are the lesson's canonical fixtures. Any RNG / sampling
// /reduction change that shifts them will fail this test, forcing the author
// to update the lesson prose simultaneously.
//
// First coefficient pins (one line each so a drift report is readable):

test("frozenVectors: A first row first coefficient", () => {
  const f = frozenVectors(1);
  assert.equal(f.A[0][0][0], 254);
});

test("frozenVectors: A second row first coefficient", () => {
  const f = frozenVectors(1);
  assert.equal(f.A[1][0][0], 177);
});

test("frozenVectors: secret s pinned", () => {
  const f = frozenVectors(1);
  assert.deepEqual(f.s[0], [256, 0, 0, 256]);
  assert.deepEqual(f.s[1], [256, 0, 0, 0]);
});

test("frozenVectors: error e pinned", () => {
  const f = frozenVectors(1);
  assert.deepEqual(f.e[0], [0, 1, 256, 256]);
  assert.deepEqual(f.e[1], [1, 0, 0, 0]);
});

test("frozenVectors: public-key polynomial t pinned", () => {
  const f = frozenVectors(1);
  assert.deepEqual(f.t[0], [72, 30, 20, 218]);
  assert.deepEqual(f.t[1], [195, 137, 177, 2]);
});

test("frozenVectors: encap randomness (r, e1, e2) pinned", () => {
  const f = frozenVectors(1);
  assert.deepEqual(f.r[0],  [0, 256, 1, 1]);
  assert.deepEqual(f.r[1],  [1, 256, 1, 1]);
  assert.deepEqual(f.e1[0], [0, 256, 1, 256]);
  assert.deepEqual(f.e1[1], [1, 256, 0, 0]);
  assert.deepEqual(f.e2,    [1, 1, 0, 1]);
});

test("frozenVectors: ciphertext u and v pinned (v[0] is the lesson's answer)", () => {
  const f = frozenVectors(1);
  assert.deepEqual(f.u[0], [192, 71, 167, 94]);
  assert.deepEqual(f.u[1], [87, 127, 130, 248]);
  assert.deepEqual(f.v,    [180, 225, 57, 240]);
  // v[0] = 180 is the canonical answer for the step-5 input-numeric validator.
  assert.equal(f.v[0], 180);
});

test("LESSON_SEED is the spec's seed string", () => {
  assert.equal(LESSON_SEED, "cloak-kyber-v1");
});

// ---- round-trip correctness ----------------------------------------------

test("round-trip on frozen vectors: bit=1 decapsulates to 1", () => {
  const f = frozenVectors(1);
  const { bit, mPrime } = decapsulate(f.s, f.u, f.v);
  assert.equal(bit, 1);
  // Coefficient 0 of m' lands near 128 (= q/2). For these vectors it lands
  // at 131 — that's 128 + 3, well inside the [64, 193] decoding window.
  assert.ok(
    mPrime[0] >= QUARTER_Q && mPrime[0] <= Q - QUARTER_Q,
    "m'[0] = " + mPrime[0] + " must be in [64, 193]"
  );
});

test("round-trip on frozen vectors: bit=0 decapsulates to 0", () => {
  const f = frozenVectors(0);
  const { bit, mPrime } = decapsulate(f.s, f.u, f.v);
  assert.equal(bit, 0);
  // Coefficient 0 of m' should be near 0 (or wrapped near q). For these
  // vectors with bit 0 it lands at 3, well below 64.
  const c = mPrime[0];
  const distToZero = Math.min(c, Q - c);
  assert.ok(distToZero < QUARTER_Q, "m'[0] = " + c + " must round to 0");
});

// Many random round-trips — the noise-budget proof in action.
test("round-trip holds across 200 random seeds × both bits", () => {
  let failures = 0;
  for (let i = 0; i < 200; i++) {
    const seed = "round-trip-" + i;
    const { A, s, t } = keygen(seed);
    for (const bit of [0, 1]) {
      const { u, v } = encapsulate(A, t, bit, seed + ":m" + bit);
      const recovered = decapsulate(s, u, v).bit;
      if (recovered !== bit) {
        failures++;
        console.error("seed=" + seed + " bit=" + bit + " recovered=" + recovered);
      }
    }
  }
  assert.equal(failures, 0, "expected 0 decryption failures across 400 attempts");
});

// Noise-budget magnitude check — direct numeric assertion of the spec's
// hand-computed bound (2·k·n + 1 = 17) across many random ciphertexts.
test("decryption noise stays below q/4 = 64 across 200 trials", () => {
  let maxNoise = 0;
  for (let i = 0; i < 200; i++) {
    const seed = "noise-budget-" + i;
    const { A, s, t } = keygen(seed);
    for (const bit of [0, 1]) {
      const { u, v } = encapsulate(A, t, bit, seed + ":m" + bit);
      const { mPrime } = decapsulate(s, u, v);
      const m_hat = bit === 1 ? HALF_Q : 0;
      // Distance from the message coefficient, treating m' as signed mod q.
      for (let j = 0; j < N; j++) {
        const expected = j === 0 ? m_hat : 0;
        const diff = mPrime[j] - expected;
        // Wrap into [-q/2, q/2].
        let signed = diff;
        if (signed > Q / 2)  signed -= Q;
        if (signed < -Q / 2) signed += Q;
        if (Math.abs(signed) > maxNoise) maxNoise = Math.abs(signed);
      }
    }
  }
  // Spec bound is 17 (= 2·k·n + 1). Threshold for decryption is 64.
  assert.ok(maxNoise < QUARTER_Q, "max noise " + maxNoise + " must be < 64");
  // And in practice it stays even smaller than the worst-case bound.
  assert.ok(maxNoise <= 17, "max noise " + maxNoise + " must be ≤ 17 (spec bound)");
});

// ---- keygen sanity --------------------------------------------------------

test("keygen returns a 2×2 matrix of length-4 polynomials and 2-vectors", () => {
  const { A, s, e, t } = keygen("any-seed");
  assert.equal(A.length, K);
  assert.equal(A[0].length, K);
  assert.equal(A[0][0].length, N);
  assert.equal(s.length, K);
  assert.equal(s[0].length, N);
  assert.equal(e.length, K);
  assert.equal(e[0].length, N);
  assert.equal(t.length, K);
  assert.equal(t[0].length, N);
});

test("keygen secret coefficients are in {0, 1, 256} (= small {0, +1, -1})", () => {
  const { s, e } = keygen("any-seed");
  const allowed = new Set([0, 1, 256]);
  for (const poly of [...s, ...e]) {
    for (const c of poly) {
      assert.ok(allowed.has(c), "secret coeff " + c + " not in {0, 1, 256}");
    }
  }
});

test("keygen A coefficients fill the full [0, 257) range across many seeds", () => {
  // Sanity: A is uniform on R_q, so coefficients should span a wide range
  // (not all small). This rules out a sampling bug.
  const seen = new Set();
  for (let i = 0; i < 50; i++) {
    const { A } = keygen("uniform-spread-" + i);
    for (const row of A) {
      for (const p of row) {
        for (const c of p) seen.add(c);
      }
    }
  }
  // We don't need every value, just that the spread is wide.
  assert.ok(seen.size > 200, "expected wide A spread; saw " + seen.size + " distinct values");
});
