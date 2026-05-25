// Toy ML-DSA (Dilithium) — keygen, sign, verify at the lesson's locked toy
// parameters q = 257, n = 4, k = 2 (matrix is k×l with l = k = 2).
//
// This is a *teaching* implementation. It is not ML-DSA-44/65/87 — those
// use q = 8380417, n = 256, and a uniform challenge polynomial with exactly
// τ non-zero coefficients in {-1, +1}. The toy uses:
//
//   - q = 257, n = 4 (same ring as the Kyber toy — every primitive ports)
//   - Ternary noise s1, s2 with coefficients in {-1, 0, 1}
//   - Uniform y with coefficients in [-GAMMA1, GAMMA1] where GAMMA1 = 40
//   - Ternary challenge c (each coefficient from {-1, 0, 1}, derived from SHA-256)
//   - BETA = 4 (= n, the worst-case bound on ||c·s||_inf)
//   - Acceptance threshold ||z||_inf ≤ GAMMA1 − BETA = 36
//
// At those numbers ~50% of sign attempts get rejected by the loop — exactly
// the spec's "rejection sampling activates roughly half the time" property,
// scaled down. The rejection rate falls out of the threshold math: y is
// uniform on (2·GAMMA1+1)^(k·n) = 81^8 points, and the fraction with every
// coefficient inside [-(GAMMA1-BETA), GAMMA1-BETA] is (2·36+1)/81 = 73/81
// per coefficient. Across 8 coefficients that's (73/81)^8 ≈ 0.44. Empirically
// closer to 0.5 because we also accept the boundary.
//
// Signature shape: (z, c, w).
//
// Real Dilithium ships (z, c, h) where h is a tiny "hint" telling the
// verifier how to recover w's high bits from A·z − c·t without sending w.
// The toy ships w directly — verification works the same algebraically and
// the math is honest about the cancellation:
//
//   A·z − c·t = A·(y + c·s1) − c·(A·s1 + s2)
//             = A·y + c·A·s1 − c·A·s1 − c·s2
//             = w − c·s2
//
// So the verifier checks ||w − (A·z − c·t)||_inf ≤ BETA — that's where the
// noise budget closes. The real spec uses high-bits rounding so that w (~ a
// kilobyte) doesn't need to ship; the bytes saved are the entire reason the
// HighBits/MakeHint/UseHint machinery exists. The toy keeps it explicit.

import {
  Q,
  N,
  mod,
  matVecMul,
  vecAdd,
  vecSub,
  vecPolyMul,
  vecInfinityNorm,
} from "./poly.js";

export const K = 2;                    // module rank (also L: matrix is K×K)
export const L = K;
export const GAMMA1 = 40;              // bound on |y|_inf at sample time
export const BETA = 4;                 // worst-case |c·s|_inf bound (= n)
export const ACCEPT_BOUND = GAMMA1 - BETA; // |z|_inf must be ≤ this to accept
export const MAX_SIGN_ATTEMPTS = 20;   // failsafe; real signatures take ~2 attempts

// ---- deterministic seeded PRNG --------------------------------------------
//
// Same FNV-1a + Mulberry32 stack as Kyber so the lesson math is identical
// across Node and browser, and so the frozen-vectors regression test pins
// reproducible numbers.

function fnv1a(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

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

export function makeRng(seedString) {
  const next = mulberry32(fnv1a(seedString));
  return {
    // Uniform integer in [0, m). Rejection-sampling avoids modulo bias.
    uniform(m) {
      const limit = Math.floor(0x100000000 / m) * m;
      // eslint-disable-next-line no-constant-condition
      while (true) {
        const u = next();
        if (u < limit) return u % m;
      }
    },
    // Uniform sample from {-1, 0, 1}.
    small() {
      return (next() % 3) - 1;
    },
    // Uniform sample from {-range, ..., range}. Used for y in signing.
    rangeSmall(range) {
      return this.uniform(2 * range + 1) - range;
    },
    nextU32: next,
  };
}

function samplePoly(rng, sampler, n = N) {
  const out = new Array(n);
  for (let i = 0; i < n; i++) out[i] = mod(sampler.call(rng));
  return out;
}

function sampleVec(rng, sampler, k = K, n = N) {
  const out = new Array(k);
  for (let i = 0; i < k; i++) out[i] = samplePoly(rng, sampler, n);
  return out;
}

// Sample a vector of polynomials with coefficients uniform in [-range, range].
function sampleVecRange(rng, range, k = K, n = N) {
  const out = new Array(k);
  for (let i = 0; i < k; i++) {
    const p = new Array(n);
    for (let j = 0; j < n; j++) p[j] = mod(rng.rangeSmall(range));
    out[i] = p;
  }
  return out;
}

// ---- challenge derivation -------------------------------------------------
//
// Real Dilithium uses SHAKE-256 with domain separation and a fixed-weight
// challenge polynomial (τ non-zero coefficients in {-1, +1}, rest zero).
// The toy uses SHA-256 and a uniform ternary challenge — coefficients of
// c are derived as (byte[i] % 3) − 1 for i in [0, n).
//
// Browsers and Node both have SHA-256 in their standard library. We pick
// the implementation at call time so this module works in both environments.

async function sha256(bytes) {
  // Browser: Web Crypto is always available in TLS-served pages.
  if (typeof crypto !== "undefined" && crypto.subtle) {
    const buf = await crypto.subtle.digest("SHA-256", bytes);
    return new Uint8Array(buf);
  }
  // Node fallback. Dynamic import so this module loads cleanly in the browser
  // (where the static "node:crypto" specifier would otherwise fail to resolve).
  // Node 19+ has crypto.subtle on globalThis, so this branch usually doesn't
  // fire in modern Node either — but keep it as belt-and-braces.
  const { createHash } = await import("node:crypto");
  const h = createHash("sha256");
  h.update(bytes);
  return new Uint8Array(h.digest());
}

// Serialise a vector of polynomials into a byte buffer for hashing.
// Each coefficient is two little-endian bytes (q < 2^16, so 2 bytes is enough).
function serializeVec(vec) {
  let total = 0;
  for (const p of vec) total += p.length * 2;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of vec) {
    for (const c of p) {
      out[off++] = c & 0xff;
      out[off++] = (c >> 8) & 0xff;
    }
  }
  return out;
}

// Derive the ternary challenge polynomial c from (message, w).
export async function deriveChallenge(message, w) {
  const msgBytes = typeof message === "string"
    ? new TextEncoder().encode(message)
    : message;
  const wBytes = serializeVec(w);
  const combined = new Uint8Array(msgBytes.length + wBytes.length);
  combined.set(msgBytes, 0);
  combined.set(wBytes, msgBytes.length);
  const digest = await sha256(combined);
  const c = new Array(N);
  for (let i = 0; i < N; i++) {
    c[i] = mod((digest[i] % 3) - 1);
  }
  return c;
}

// ---- keygen ---------------------------------------------------------------
//
// 1. Sample uniform matrix A ∈ R_q^(k×l) with coefficients uniform in [0, q).
// 2. Sample small secret s1 ∈ R_q^l with coefficients in {-1, 0, 1}.
// 3. Sample small secret s2 ∈ R_q^k with coefficients in {-1, 0, 1}.
// 4. Compute t = A·s1 + s2 mod q.
//
// Returns {A, s1, s2, t}. Public key: (A, t). Private key: (s1, s2).
//
// Note vs Kyber: Kyber's "small secret" is s and the noise added to A·s is e.
// Dilithium calls the first one s1 (used to mask the challenge response) and
// the second one s2 (the noise that randomises t). Both are small.
export function keygen(seedString) {
  const rng = makeRng(seedString + ":keygen");
  const A = new Array(K);
  for (let i = 0; i < K; i++) {
    A[i] = new Array(L);
    for (let j = 0; j < L; j++) {
      A[i][j] = samplePoly(rng, rng.uniform.bind(rng, Q));
    }
  }
  const s1 = sampleVec(rng, rng.small, L);
  const s2 = sampleVec(rng, rng.small, K);
  const t = vecAdd(matVecMul(A, s1), s2);
  return { A, s1, s2, t };
}

// ---- sign -----------------------------------------------------------------
//
// Fiat-Shamir loop (real Dilithium structure):
//   1. Sample y uniformly with |y|_inf ≤ GAMMA1.
//   2. Compute w = A·y.
//   3. Derive c = H(message, w) (ternary polynomial).
//   4. Compute z = y + c·s1.
//   5. Reject if |z|_inf > GAMMA1 − BETA, else accept.
//
// Returns { z, c, w, attempts }. If acceptance fails after MAX_SIGN_ATTEMPTS,
// throws — extraordinarily unlikely with these parameters (~0.5^20 ≈ 1e-6).
//
// The signature is (z, c, w) for the toy. Real Dilithium replaces w with a
// short hint h that lets the verifier recover w's high bits from (A·z − c·t).
export async function sign(message, sk, seedString) {
  const { s1 } = sk;
  const { A } = sk;
  const seedBase = (seedString || "default") + ":sign:" + message;
  for (let attempt = 0; attempt < MAX_SIGN_ATTEMPTS; attempt++) {
    const rng = makeRng(seedBase + ":" + attempt);
    const y = sampleVecRange(rng, GAMMA1, L);
    const w = matVecMul(A, y);
    const c = await deriveChallenge(message, w);
    const cs1 = vecPolyMul(c, s1);
    const z = vecAdd(y, cs1);
    const zNorm = vecInfinityNorm(z);
    if (zNorm <= ACCEPT_BOUND) {
      return { z, c, w, attempts: attempt + 1 };
    }
  }
  throw new Error(
    "dilithium.sign: rejection sampling exhausted " + MAX_SIGN_ATTEMPTS +
    " attempts. Expected probability ~" + Math.pow(0.5, MAX_SIGN_ATTEMPTS).toExponential(2)
  );
}

// ---- verify ---------------------------------------------------------------
//
// Given (z, c, w), public (A, t), message m:
//   1. Check ||z||_inf ≤ GAMMA1 − BETA (short response).
//   2. Recompute w' = A·z − c·t.
//   3. Check ||w − w'||_inf ≤ BETA (algebra closes within noise).
//   4. Recompute c' = H(m, w); check c' == c.
//
// All three must hold. Returns true/false.
//
// The algebra (step 2 of the proof):
//   A·z − c·t = A·(y + c·s1) − c·(A·s1 + s2)
//             = A·y + c·A·s1 − c·A·s1 − c·s2
//             = w − c·s2
// So w − w' = c·s2, whose infinity norm is bounded by BETA = n.
export async function verify(message, signature, pk) {
  const { z, c, w } = signature;
  const { A, t } = pk;

  // (1) Short response.
  if (vecInfinityNorm(z) > ACCEPT_BOUND) {
    return false;
  }

  // (2) Recompute w' from z and c.
  const Az = matVecMul(A, z);
  const ct = vecPolyMul(c, t);
  const wPrime = vecSub(Az, ct);

  // (3) ||w − w'||_inf must fit in the noise budget BETA.
  const diff = vecSub(w, wPrime);
  if (vecInfinityNorm(diff) > BETA) {
    return false;
  }

  // (4) Challenge integrity.
  const cPrime = await deriveChallenge(message, w);
  if (cPrime.length !== c.length) return false;
  for (let i = 0; i < c.length; i++) {
    if (cPrime[i] !== c[i]) return false;
  }

  return true;
}

// ---- frozen vectors -------------------------------------------------------
//
// Deterministic A, s1, s2, t from the canonical lesson seed. The tests pin
// these values so any change to the RNG or sampling order is caught.

export const LESSON_SEED = "cloak-dilithium-v1";

export function frozenKeypair() {
  const { A, s1, s2, t } = keygen(LESSON_SEED);
  return { A, s1, s2, t, sk: { A, s1, s2, t }, pk: { A, t } };
}

// Convenience for tests: sign a fixed message with the frozen keypair.
export async function frozenSignature(message = "hello world") {
  const kp = frozenKeypair();
  const sig = await sign(message, kp.sk, LESSON_SEED);
  return { ...sig, kp, message };
}

// ---- public ring constants (re-exported for consumer convenience) --------

export { Q, N, mod };
