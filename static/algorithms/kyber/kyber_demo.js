// Toy ML-KEM (Kyber) — keygen, encapsulate, decapsulate at the lesson's
// locked toy parameters q = 257, n = 4, k = 2.
//
// This is a *teaching* implementation. It is not Kyber512 / Kyber768 /
// Kyber1024 — those use q = 3329, n = 256, and a centered binomial noise
// distribution. The toy version uses uniform ternary noise ({-1, 0, 1})
// and parameters small enough that every polynomial fits on one screen
// line. The pedagogical claim is that the *shape* of the algorithm —
// "the public key is A·s + e for small s, e; the ciphertext is two
// polynomials in the same ring; decryption removes the secret to expose
// the encoded bit through the noise budget" — transfers unchanged from
// these toy params to the real FIPS 203 parameters.
//
// The noise-budget proof from the spec:
//   max decryption noise = 2·k·n + 1 = 2·2·4 + 1 = 17
//   safe threshold        = q / 4    = 64
//   17 < 64, so decryption is reliable for any small (r, e, e1, e2).
//
// One-bit encapsulation: a message bit m ∈ {0, 1} is encoded as the
// polynomial [m · ⌊q/2⌉, 0, 0, 0] = [m · 128, 0, 0, 0] in R_q. The
// recipient recovers m by reading coefficient 0 of v − sᵀ·u and asking
// "closer to 0 or closer to q/2?" — equivalently, "is the coefficient in
// [⌊q/4⌉, ⌊3q/4⌉] = [64, 192]?" Real Kyber does this 256 times in
// parallel across the coefficients of a degree-256 polynomial; the toy
// teaches the structure with a single bit.

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
} from "./poly.js";

export const K = 2;                   // module rank (matches Kyber512)
export const HALF_Q = Math.floor(Q / 2); // 128 — the "bit-1" landing point
export const QUARTER_Q = Math.floor(Q / 4); // 64  — the decode threshold

// ---- deterministic seeded PRNG --------------------------------------------
//
// Lesson math has to be the *same numbers every visit* so the static
// rendering of A, s, e, t, etc. matches what `kyber_demo.encapsulate`
// re-derives on the page. We don't need cryptographic randomness — we
// need *stable* randomness across Node and browser. A 32-bit FNV-1a hash
// of the seed string drives a Mulberry32 generator. Both are textbook
// algorithms; both produce identical output everywhere a 32-bit unsigned
// integer multiplies the same way (i.e. everywhere with IEEE 754 doubles).
//
// If you change the seed or any of the sampling code, every fixture in
// `frozenVectors()` shifts. The `tests/kyber_demo.test.js` regression test
// pins the current values and will fail loudly to flag drift.

function fnv1a(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = (h * 0x01000193) >>> 0;
  }
  return h >>> 0;
}

// Mulberry32: tiny, well-distributed 32-bit PRNG.
// Returns a function that yields a fresh uint32 on each call.
function mulberry32(seed) {
  let state = seed >>> 0;
  return function nextU32() {
    state = (state + 0x6D2B79F5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0);
  };
}

// Build a PRNG that produces (1) uniform integers in [0, q) and (2)
// small ternary samples in {-1, 0, 1} — uniform across the three values.
export function makeRng(seedString) {
  const next = mulberry32(fnv1a(seedString));
  return {
    // Uniform integer in [0, q). Rejection-sampling avoids the modulo bias
    // when q doesn't divide 2^32 (which it doesn't, for q = 257).
    uniform(q = Q) {
      const limit = Math.floor(0x100000000 / q) * q;
      // eslint-disable-next-line no-constant-condition
      while (true) {
        const u = next();
        if (u < limit) return u % q;
      }
    },
    // Uniform sample from {-1, 0, 1}.
    small() {
      return (next() % 3) - 1;
    },
    // Direct uint32 escape hatch (used only by tests).
    nextU32: next,
  };
}

// Sample a polynomial of length n with coefficients drawn from `sampler`,
// then canonicalise into [0, q). `sampler` is one of rng.uniform / rng.small.
function samplePoly(rng, sampler, n = N) {
  const out = new Array(n);
  for (let i = 0; i < n; i++) {
    const v = sampler.call(rng);
    out[i] = mod(v);
  }
  return out;
}

// Sample a k-vector of polynomials.
function sampleVec(rng, sampler, k = K, n = N) {
  const out = new Array(k);
  for (let i = 0; i < k; i++) {
    out[i] = samplePoly(rng, sampler, n);
  }
  return out;
}

// ---- keygen ---------------------------------------------------------------
//
// 1. Sample uniform matrix A of shape k×k where each entry is a polynomial
//    with coefficients uniform in [0, q).
// 2. Sample small secret vector s ∈ R_q^k with coefficients in {-1, 0, 1}.
// 3. Sample small error vector e ∈ R_q^k with coefficients in {-1, 0, 1}.
// 4. Compute t = A·s + e mod q.
//
// Returns {A, s, e, t}. Private key is s; public key is (A, t).
export function keygen(seedString) {
  const rng = makeRng(seedString + ":keygen");
  const A = new Array(K);
  for (let i = 0; i < K; i++) {
    A[i] = new Array(K);
    for (let j = 0; j < K; j++) {
      A[i][j] = samplePoly(rng, rng.uniform);
    }
  }
  const s = sampleVec(rng, rng.small);
  const e = sampleVec(rng, rng.small);
  const t = vecAdd(matVecMul(A, s), e);
  return { A, s, e, t };
}

// Coefficient-wise add for k-vectors of polynomials.
function vecAdd(a, b) {
  const out = new Array(a.length);
  for (let i = 0; i < a.length; i++) {
    out[i] = polyAdd(a[i], b[i]);
  }
  return out;
}

// Coefficient-wise sub for k-vectors of polynomials.
function vecSub(a, b) {
  const out = new Array(a.length);
  for (let i = 0; i < a.length; i++) {
    out[i] = polySub(a[i], b[i]);
  }
  return out;
}

// Encode a single bit as a polynomial: bit 1 → ⌊q/2⌉ at coefficient 0,
// bit 0 → all-zero polynomial. This is the "message coefficient" that the
// recipient will recover.
export function encodeBit(bit) {
  const out = new Array(N).fill(0);
  if (bit === 1) out[0] = HALF_Q;
  return out;
}

// Decode coefficient 0 of (v − sᵀ·u) into a bit by asking "closer to 0 or
// closer to q/2?". Equivalently: bit = 1 iff coefficient ∈ [q/4, 3q/4].
export function decodeBit(poly) {
  const c = poly[0];
  return (c >= QUARTER_Q && c <= Q - QUARTER_Q) ? 1 : 0;
}

// ---- encapsulate ----------------------------------------------------------
//
// Sender side. Given the public key (A, t) and a one-bit message:
//   1. Sample r ∈ R_q^k, e1 ∈ R_q^k, e2 ∈ R_q  — all coefficients in {-1, 0, 1}.
//   2. u = Aᵀ·r + e1 mod q
//   3. v = tᵀ·r + e2 + encodeBit(m) mod q
//   4. Ciphertext is (u, v).
//
// Returns {u, v, r, e1, e2, m}. The randomness is returned so the lesson
// can display "the page sampled these specific r, e1, e2 values, now
// compute v[0]".
export function encapsulate(A, t, bit, seedString) {
  const rng = makeRng(seedString + ":encap");
  const r  = sampleVec(rng, rng.small);
  const e1 = sampleVec(rng, rng.small);
  const e2 = samplePoly(rng, rng.small);
  const m_hat = encodeBit(bit);
  const u = vecAdd(matVecMul(transpose(A), r), e1);
  // v is scalar in R_q: t^T · r is one polynomial.
  const v = polyAdd(polyAdd(vecDot(t, r), e2), m_hat);
  return { u, v, r, e1, e2, m: bit };
}

// ---- decapsulate ----------------------------------------------------------
//
// Recipient side. Given the private key s and ciphertext (u, v):
//   1. mPrime = v − sᵀ·u mod q
//   2. bit    = decodeBit(mPrime[0])
//
// Returns {bit, mPrime} so the lesson's decapsulation step can also show
// the recovered polynomial (so the learner sees coefficient 0 near 128
// for bit 1, near 0 for bit 0, and noise on the other coefficients).
export function decapsulate(s, u, v) {
  const mPrime = polySub(v, vecDot(s, u));
  return { bit: decodeBit(mPrime), mPrime };
}

// ---- frozen vectors -------------------------------------------------------
//
// The lesson's static rendering of every polynomial comes from a single
// canonical seed. Both the page and the validator re-derive the same
// numbers at runtime. The `tests/kyber_demo.test.js` regression test pins
// the first coefficient of A[0][0], s[0], e[0], t[0], r[0], e1[0], e2 and
// the resulting v[0] so a refactor that accidentally changes the RNG
// stream or the sampling order is caught immediately.
//
// `bit` defaults to 1 because that's what the lesson encapsulates.
// (Encapsulating bit 0 also works and decapsulates back to 0 — both
// paths are exercised by the test suite.)
export const LESSON_SEED = "cloak-kyber-v1";

export function frozenVectors(bit = 1) {
  const { A, s, e, t } = keygen(LESSON_SEED);
  const { u, v, r, e1, e2 } = encapsulate(A, t, bit, LESSON_SEED);
  return { A, s, e, t, r, e1, e2, m: bit, u, v };
}

// ---- public ring constants (re-exported for consumer convenience) --------

export { Q, N, mod };
