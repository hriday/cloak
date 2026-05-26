import test from "node:test";
import assert from "node:assert/strict";
import {
  pollardRho, brentVariant, gcd, factorDemo,
  DEMO_P, DEMO_Q, DEMO_N,
} from "../rho_demo.js";

// ---- math primitives ---------------------------------------------------

test("gcd basic", () => {
  assert.equal(gcd(12, 18), 6);
  assert.equal(gcd(101, 103), 1);
  assert.equal(gcd(0, 7), 7);
  assert.equal(gcd(7, 0), 7);
});

// ---- factorDemo --------------------------------------------------------

test("factorDemo returns the documented N = p * q", () => {
  const d = factorDemo();
  assert.equal(d.p, DEMO_P);
  assert.equal(d.q, DEMO_Q);
  assert.equal(d.n, DEMO_N);
  assert.equal(d.p * d.q, d.n);
});

// ---- pollardRho --------------------------------------------------------

test("pollardRho factors the demo N = 101100721", () => {
  const r = pollardRho(DEMO_N);
  assert.ok(r.factor !== null, "pollardRho should find a factor");
  // Must be one of the two true primes.
  assert.ok(r.factor === DEMO_P || r.factor === DEMO_Q,
    `expected factor to be ${DEMO_P} or ${DEMO_Q}, got ${r.factor}`);
  // Correctness: factor * (n / factor) === n.
  assert.equal(r.factor * (DEMO_N / r.factor), DEMO_N);
});

test("pollardRho factors a smaller composite", () => {
  // 8051 = 83 × 97.
  const r = pollardRho(8051);
  assert.ok(r.factor !== null);
  assert.ok(r.factor === 83 || r.factor === 97);
  assert.equal(r.factor * (8051 / r.factor), 8051);
});

test("pollardRho handles even N trivially", () => {
  const r = pollardRho(2 * 49);
  assert.equal(r.factor, 2);
});

test("pollardRho iteration count matches trajectory length within cap", () => {
  const r = pollardRho(DEMO_N);
  // trajectory cap is 500; iteration count is unbounded by that cap.
  assert.ok(r.trajectory.length <= 500);
  // Includes the initial (i=0) seed.
  assert.equal(r.trajectory[0].i, 0);
  assert.ok(r.iterations >= r.trajectory.length - 1);
});

test("pollardRho trajectory shows the cycling pattern on a small N where the cap doesn't truncate", () => {
  // The defining property of the rho-shape: the sequence x_0, x_1, x_2, ...
  // enters a cycle where tortoise (step i) and hare (step 2i) become
  // congruent modulo the factor p. Use a tiny composite where the entire
  // trajectory fits inside the 500-entry cap so the last recorded point
  // is also the detection point.
  const r = pollardRho(8051);
  assert.ok(r.factor === 83 || r.factor === 97);
  // At detection time, |tortoise - hare| is a multiple of the factor.
  // The last trajectory entry reflects that moment when the cap wasn't hit.
  const last = r.trajectory[r.trajectory.length - 1];
  const diff = Math.abs(last.x - last.y);
  assert.equal(diff % r.factor, 0,
    `expected |tortoise(${last.x}) - hare(${last.y})| = ${diff} to be a multiple of factor ${r.factor}`);
});

// ---- brentVariant -------------------------------------------------------

test("brentVariant factors the demo N = 101100721", () => {
  const r = brentVariant(DEMO_N);
  assert.ok(r.factor !== null);
  assert.ok(r.factor === DEMO_P || r.factor === DEMO_Q);
  assert.equal(r.factor * (DEMO_N / r.factor), DEMO_N);
});

test("brentVariant typically uses fewer iterations than Pollard's on the same N", () => {
  // Brent's is statistically ~24% faster. We assert <= rather than < to
  // tolerate the rare case where they tie or Floyd's edges out by luck.
  const a = pollardRho(DEMO_N);
  const b = brentVariant(DEMO_N);
  assert.ok(b.iterations <= a.iterations * 1.5,
    `Brent (${b.iterations}) shouldn't blow past Pollard (${a.iterations}) by >50%`);
});

test("brentVariant factors 8051 correctly", () => {
  const r = brentVariant(8051);
  assert.ok(r.factor !== null);
  assert.ok(r.factor === 83 || r.factor === 97);
});

test("brentVariant trajectory bounded by cap", () => {
  const r = brentVariant(DEMO_N);
  assert.ok(r.trajectory.length <= 500);
  assert.ok(r.iterations >= 1);
});
