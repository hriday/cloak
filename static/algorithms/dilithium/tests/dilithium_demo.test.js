import { test } from "node:test";
import assert from "node:assert/strict";
import {
  K,
  L,
  N,
  Q,
  GAMMA1,
  BETA,
  ACCEPT_BOUND,
  MAX_SIGN_ATTEMPTS,
  LESSON_SEED,
  makeRng,
  keygen,
  sign,
  verify,
  deriveChallenge,
  frozenKeypair,
  frozenSignature,
} from "../dilithium_demo.js";
import { vecInfinityNorm, polyInfinityNorm } from "../poly.js";

// ---- module constants -----------------------------------------------------

test("module parameters match the lesson's locked toy choice", () => {
  assert.equal(K, 2);
  assert.equal(L, 2);
  assert.equal(N, 4);
  assert.equal(Q, 257);
  assert.equal(GAMMA1, 40);
  assert.equal(BETA, 4);
  assert.equal(ACCEPT_BOUND, 36);
  assert.equal(MAX_SIGN_ATTEMPTS, 20);
});

test("LESSON_SEED is the spec's seed string", () => {
  assert.equal(LESSON_SEED, "cloak-dilithium-v1");
});

// ---- PRNG -----------------------------------------------------------------

test("makeRng produces deterministic output for the same seed", () => {
  const a = makeRng("seed-x");
  const b = makeRng("seed-x");
  for (let i = 0; i < 100; i++) {
    assert.equal(a.uniform(Q), b.uniform(Q));
  }
});

test("makeRng produces different streams for different seeds", () => {
  const a = makeRng("seed-x");
  const b = makeRng("seed-y");
  let anyDifferent = false;
  for (let i = 0; i < 5; i++) {
    if (a.uniform(Q) !== b.uniform(Q)) {
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

test("makeRng.rangeSmall stays in [-range, range]", () => {
  const r = makeRng("range-test");
  for (let i = 0; i < 1000; i++) {
    const v = r.rangeSmall(GAMMA1);
    assert.ok(v >= -GAMMA1 && v <= GAMMA1, "got " + v);
  }
});

// ---- frozen-keypair regression -------------------------------------------
//
// These pinned values are the canonical fixtures for the lesson prose. Any
// drift in the RNG / sampling order will fail this test, forcing the author
// to update the lesson copy in lockstep.

test("frozenKeypair: A first row matches pinned values", () => {
  const { A } = frozenKeypair();
  // First sampled polynomial under seed "cloak-dilithium-v1:keygen".
  assert.deepEqual(A[0][0], [206, 231, 91, 176]);
  assert.deepEqual(A[0][1], [15, 142, 226, 3]);
});

test("frozenKeypair: A second row matches pinned values", () => {
  const { A } = frozenKeypair();
  assert.deepEqual(A[1][0], [26, 64, 209, 67]);
  assert.deepEqual(A[1][1], [222, 173, 207, 219]);
});

test("frozenKeypair: secret s1 pinned (ternary in canonical form)", () => {
  const { s1 } = frozenKeypair();
  assert.deepEqual(s1[0], [256, 1, 256, 1]); // signed: -1, 1, -1, 1
  assert.deepEqual(s1[1], [0, 0, 256, 1]);   // signed:  0, 0, -1, 1
});

test("frozenKeypair: secret s2 pinned (ternary in canonical form)", () => {
  const { s2 } = frozenKeypair();
  assert.deepEqual(s2[0], [0, 0, 256, 256]); // signed:  0, 0, -1, -1
  assert.deepEqual(s2[1], [1, 0, 1, 0]);     // signed:  1, 0,  1,  0
});

test("frozenKeypair: public-key polynomial t pinned", () => {
  const { t } = frozenKeypair();
  assert.deepEqual(t[0], [76, 94, 253, 19]);
  assert.deepEqual(t[1], [87, 89, 93, 153]);
});

// ---- keygen sanity --------------------------------------------------------

test("keygen returns a k×l matrix and k-vectors of length-n polynomials", () => {
  const { A, s1, s2, t } = keygen("any-seed");
  assert.equal(A.length, K);
  assert.equal(A[0].length, L);
  assert.equal(A[0][0].length, N);
  assert.equal(s1.length, L);
  assert.equal(s1[0].length, N);
  assert.equal(s2.length, K);
  assert.equal(s2[0].length, N);
  assert.equal(t.length, K);
  assert.equal(t[0].length, N);
});

test("keygen s1, s2 coefficients are in {0, 1, 256} (signed {0, ±1})", () => {
  const { s1, s2 } = keygen("any-seed");
  const allowed = new Set([0, 1, 256]);
  for (const poly of [...s1, ...s2]) {
    for (const c of poly) {
      assert.ok(allowed.has(c), "secret coeff " + c + " not in {0, 1, 256}");
    }
  }
});

// ---- challenge derivation ------------------------------------------------

test("deriveChallenge returns a ternary polynomial in canonical form", async () => {
  const w = [
    [123, 45, 67, 89],
    [1, 2, 3, 4],
  ];
  const c = await deriveChallenge("hello", w);
  assert.equal(c.length, N);
  for (const coef of c) {
    assert.ok(coef === 0 || coef === 1 || coef === 256, "challenge coeff out of {0, 1, 256}: " + coef);
  }
});

test("deriveChallenge is deterministic for the same (message, w)", async () => {
  const w = [
    [10, 20, 30, 40],
    [1, 2, 3, 4],
  ];
  const c1 = await deriveChallenge("the message", w);
  const c2 = await deriveChallenge("the message", w);
  assert.deepEqual(c1, c2);
});

test("deriveChallenge differs across messages with overwhelming probability", async () => {
  const w = [
    [10, 20, 30, 40],
    [1, 2, 3, 4],
  ];
  const c1 = await deriveChallenge("message A", w);
  const c2 = await deriveChallenge("message B", w);
  assert.notDeepEqual(c1, c2);
});

// ---- sign-and-verify roundtrip -------------------------------------------

test("frozen-keypair sign+verify roundtrip on 'hello world'", async () => {
  const kp = frozenKeypair();
  const sig = await sign("hello world", kp.sk, LESSON_SEED);
  assert.ok(sig.attempts >= 1 && sig.attempts <= MAX_SIGN_ATTEMPTS);
  const ok = await verify("hello world", sig, kp.pk);
  assert.equal(ok, true);
});

test("z is short on accepted signatures (||z||_inf ≤ GAMMA1 - BETA)", async () => {
  const kp = frozenKeypair();
  const sig = await sign("hello world", kp.sk, LESSON_SEED);
  assert.ok(vecInfinityNorm(sig.z) <= ACCEPT_BOUND);
});

test("verify rejects a wrong message (challenge integrity fails)", async () => {
  const kp = frozenKeypair();
  const sig = await sign("hello world", kp.sk, LESSON_SEED);
  const ok = await verify("HELLO WORLD", sig, kp.pk);
  assert.equal(ok, false);
});

test("verify rejects a tampered z (||z|| may grow OR algebra breaks)", async () => {
  const kp = frozenKeypair();
  const sig = await sign("hello world", kp.sk, LESSON_SEED);
  const tampered = {
    ...sig,
    z: sig.z.map((p, i) => i === 0 ? p.map((c, j) => j === 0 ? (c + 1) % Q : c) : p),
  };
  const ok = await verify("hello world", tampered, kp.pk);
  assert.equal(ok, false);
});

test("verify rejects a tampered c", async () => {
  const kp = frozenKeypair();
  const sig = await sign("hello world", kp.sk, LESSON_SEED);
  const tampered = {
    ...sig,
    c: sig.c.map((coef, j) => j === 0 ? (coef + 1) % Q : coef),
  };
  const ok = await verify("hello world", tampered, kp.pk);
  assert.equal(ok, false);
});

test("verify rejects a tampered w", async () => {
  const kp = frozenKeypair();
  const sig = await sign("hello world", kp.sk, LESSON_SEED);
  const tampered = {
    ...sig,
    w: sig.w.map((p, i) => i === 0 ? p.map((c, j) => j === 0 ? (c + 50) % Q : c) : p),
  };
  const ok = await verify("hello world", tampered, kp.pk);
  assert.equal(ok, false);
});

test("verify rejects a signature with oversized z (forged 'short' check)", async () => {
  const kp = frozenKeypair();
  const sig = await sign("hello world", kp.sk, LESSON_SEED);
  // Add GAMMA1 (40) to one coefficient so |z|_inf jumps past ACCEPT_BOUND.
  const tampered = {
    ...sig,
    z: sig.z.map((p, i) => i === 0 ? p.map((c, j) => j === 0 ? (c + GAMMA1) % Q : c) : p),
  };
  const ok = await verify("hello world", tampered, kp.pk);
  assert.equal(ok, false);
});

// ---- rejection sampling --------------------------------------------------

test("rejection sampling activates at the expected rate (~50% of attempts)", async () => {
  // Run many signatures with different messages and count the average attempts.
  // Expected acceptance rate ~50%, so expected attempts ~1/0.5 = 2.
  const kp = frozenKeypair();
  let totalAttempts = 0;
  const TRIALS = 30;
  for (let i = 0; i < TRIALS; i++) {
    const sig = await sign("trial-" + i, kp.sk, LESSON_SEED);
    totalAttempts += sig.attempts;
  }
  const avgAttempts = totalAttempts / TRIALS;
  // 1/p attempts on average where p ≈ 0.5. Allow 1.2..4 range — wide tolerance
  // because the empirical distribution has high variance at 30 trials.
  assert.ok(
    avgAttempts >= 1.2 && avgAttempts <= 4,
    "avg attempts " + avgAttempts + " outside expected [1.2, 4]"
  );
});

test("rejection sampling rejects a meaningful fraction of attempts", async () => {
  // Direct test: count how many of N attempts on the same message would have
  // been rejected vs accepted. We force the loop by signing many messages and
  // confirming at least some attempts >= 2 occur.
  const kp = frozenKeypair();
  let multiAttempt = 0;
  const TRIALS = 30;
  for (let i = 0; i < TRIALS; i++) {
    const sig = await sign("rej-" + i, kp.sk, LESSON_SEED);
    if (sig.attempts >= 2) multiAttempt++;
  }
  // At ~50% acceptance per attempt, we expect ~50% of signatures to need >= 2
  // attempts. Wide tolerance.
  assert.ok(
    multiAttempt >= 5,
    "expected at least 5/" + TRIALS + " multi-attempt signatures; got " + multiAttempt
  );
});

// ---- random-key round-trip stress test -----------------------------------

test("sign+verify roundtrip across 20 random keypairs × random messages", async () => {
  let failures = 0;
  for (let i = 0; i < 20; i++) {
    const seed = "stress-" + i;
    const kp = { ...keygen(seed), pk: null, sk: null };
    kp.pk = { A: kp.A, t: kp.t };
    kp.sk = { A: kp.A, s1: kp.s1, s2: kp.s2 };
    const msg = "msg-" + i;
    const sig = await sign(msg, kp.sk, seed);
    const ok = await verify(msg, sig, kp.pk);
    if (!ok) failures++;
  }
  assert.equal(failures, 0, "expected 0 verify failures across 20 keypairs");
});

// ---- noise budget --------------------------------------------------------

test("||w − (A·z − c·t)||_inf ≤ BETA on accepted signatures", async () => {
  // Direct check of the algebra: w − w' = c·s2, bounded by BETA = n.
  const kp = frozenKeypair();
  let maxDiff = 0;
  for (let i = 0; i < 20; i++) {
    const sig = await sign("budget-" + i, kp.sk, LESSON_SEED);
    // Manually compute w' and the diff. (Verify already checks this, but
    // we want the numeric value to confirm the budget holds with margin.)
    const { z, c, w } = sig;
    const { A, t } = kp.pk;
    // Reimport poly to compute the diff inline.
    const Az = await import("../poly.js").then((m) =>
      m.matVecMul(A, z)
    );
    const ct = await import("../poly.js").then((m) => m.vecPolyMul(c, t));
    const wPrime = await import("../poly.js").then((m) => m.vecSub(Az, ct));
    const diff = await import("../poly.js").then((m) => m.vecSub(w, wPrime));
    const n = vecInfinityNorm(diff);
    if (n > maxDiff) maxDiff = n;
  }
  assert.ok(maxDiff <= BETA, "max ||w-w'||_inf = " + maxDiff + " exceeds BETA = " + BETA);
});

// ---- frozenSignature helper ----------------------------------------------

test("frozenSignature returns a verifiable signature with all metadata", async () => {
  const sig = await frozenSignature("hello world");
  assert.ok(Array.isArray(sig.z));
  assert.ok(Array.isArray(sig.c));
  assert.ok(Array.isArray(sig.w));
  assert.ok(sig.attempts >= 1);
  assert.equal(sig.message, "hello world");
  const ok = await verify("hello world", sig, sig.kp.pk);
  assert.equal(ok, true);
});
