import { test } from "node:test";
import assert from "node:assert/strict";
import {
  pointAdd, pointDouble, scalarMul,
  plotCurvePath, finiteFieldPoints, findThirdIntersection,
  animatedAdd, isNonSingular,
  DEFAULT_A, DEFAULT_B, FF_A, FF_B, FF_P,
  CURVE_PRESETS,
} from "../ec_demo.js";

// ----------------------------------------------------------------------
// Finite-field arithmetic, cross-checked against the toy curve used by
// the ECDSA lesson:
//   y² = x³ + x + 6  (mod 11),  G = (2, 7),  order n = 13.
// The ECDSA lesson's own tests have ratified these values, so any
// disagreement here means our generic implementation drifted.

const TOY_A = 1, TOY_B = 6, TOY_P = 11;
const G = { x: 2, y: 7 };

test("pointAdd over F_11 agrees with the ECDSA toy curve: G + G == 2G", () => {
  const sum = pointAdd(G, G, TOY_A, TOY_P);
  const dbl = pointDouble(G, TOY_A, TOY_P);
  assert.deepEqual(sum, dbl);
});

test("scalarMul(2, G) == pointDouble(G)", () => {
  const k2 = scalarMul(2, G, TOY_A, TOY_P);
  const dbl = pointDouble(G, TOY_A, TOY_P);
  assert.deepEqual(k2, dbl);
});

test("scalarMul(13, G) == null  (order of the toy group is 13)", () => {
  // Generating the full subgroup means 13·G lands on the point at infinity.
  const r = scalarMul(13, G, TOY_A, TOY_P);
  assert.equal(r, null);
});

test("scalarMul(14, G) == G  (one past the order wraps)", () => {
  const r = scalarMul(14, G, TOY_A, TOY_P);
  assert.deepEqual(r, G);
});

test("pointAdd is commutative: P + Q == Q + P (toy curve)", () => {
  const P = { x: 2, y: 7 };
  const Q = scalarMul(3, G, TOY_A, TOY_P);   // 3·G
  const ab = pointAdd(P, Q, TOY_A, TOY_P);
  const ba = pointAdd(Q, P, TOY_A, TOY_P);
  assert.deepEqual(ab, ba);
});

test("scalarMul roundtrip: 5·G + 8·G == 13·G == null (sums to the identity)", () => {
  const p5 = scalarMul(5, G, TOY_A, TOY_P);
  const p8 = scalarMul(8, G, TOY_A, TOY_P);
  const sum = pointAdd(p5, p8, TOY_A, TOY_P);
  assert.equal(sum, null);
});

test("pointAdd(P, null) == P  (identity element)", () => {
  assert.deepEqual(pointAdd(G, null, TOY_A, TOY_P), G);
  assert.deepEqual(pointAdd(null, G, TOY_A, TOY_P), G);
});

test("pointDouble(null) == null", () => {
  assert.equal(pointDouble(null, TOY_A, TOY_P), null);
});

// Enumerate every multiple of G on the toy curve and assert all 13 are
// distinct (modulo the point at infinity at k=13). That's the strongest
// possible sanity check on the group operation.
test("orbit of G under repeated addition is the full 13-element subgroup", () => {
  const seen = new Map();
  let p = null;
  for (let k = 1; k <= 13; k++) {
    p = pointAdd(p, G, TOY_A, TOY_P);
    if (k < 13) {
      assert.ok(p !== null, `k=${k}·G should be a finite point`);
      const key = `${p.x},${p.y}`;
      assert.ok(!seen.has(key), `duplicate point at k=${k} (also seen at k=${seen.get(key)})`);
      seen.set(key, k);
    } else {
      assert.equal(p, null, "13·G must be the point at infinity");
    }
  }
  assert.equal(seen.size, 12);
});

// ----------------------------------------------------------------------
// Real-number arithmetic — used for the visual lesson on y² = x³ - 3x + 5.

test("pointAdd over reals on y² = x³ - 3x + 5: known sum", () => {
  // P = (0, sqrt(5)), Q = (2, sqrt(7)) on y² = x³ - 3x + 5.
  const P = { x: 0, y: Math.sqrt(5) };
  const Q = { x: 2, y: Math.sqrt(7) };
  // Sanity: both on curve.
  assert.ok(Math.abs(P.y * P.y - (0 - 0 + 5)) < 1e-9);
  assert.ok(Math.abs(Q.y * Q.y - (8 - 6 + 5)) < 1e-9);
  const R = pointAdd(P, Q, DEFAULT_A, null);
  // R must be on the curve too.
  const lhs = R.y * R.y;
  const rhs = R.x ** 3 + DEFAULT_A * R.x + DEFAULT_B;
  assert.ok(Math.abs(lhs - rhs) < 1e-6, `R=${JSON.stringify(R)} not on curve: ${lhs} vs ${rhs}`);
});

test("pointDouble over reals on y² = x³ - 3x + 5: 2P stays on curve", () => {
  const P = { x: 2, y: Math.sqrt(7) };
  const R = pointDouble(P, DEFAULT_A, null);
  const lhs = R.y * R.y;
  const rhs = R.x ** 3 + DEFAULT_A * R.x + DEFAULT_B;
  assert.ok(Math.abs(lhs - rhs) < 1e-6, `2P=${JSON.stringify(R)} not on curve`);
});

test("scalarMul over reals: 3P = P + 2P (associativity)", () => {
  const P = { x: 2, y: Math.sqrt(7) };
  const threeP_via_scalar = scalarMul(3, P, DEFAULT_A, null);
  const twoP = pointDouble(P, DEFAULT_A, null);
  const threeP_via_add = pointAdd(P, twoP, DEFAULT_A, null);
  assert.ok(Math.abs(threeP_via_scalar.x - threeP_via_add.x) < 1e-6);
  assert.ok(Math.abs(threeP_via_scalar.y - threeP_via_add.y) < 1e-6);
});

// ----------------------------------------------------------------------
// scalarMul instrumentation: onStep callback is the bridge to the
// animated bit-ladder widget on step 5.

test("scalarMul invokes onStep once per bit of k", () => {
  const calls = [];
  scalarMul(11, G, TOY_A, TOY_P, (info) => calls.push(info));
  // 11 = 0b1011 → 4 bits.
  assert.equal(calls.length, 4);
  // Bit indices monotonically increasing from 0.
  calls.forEach((c, i) => assert.equal(c.bitIndex, i));
  // 11 = bits (LSB first) 1,1,0,1.
  assert.deepEqual(calls.map((c) => c.bit), [1, 1, 0, 1]);
  // First call: accumulator starts at null.
  assert.equal(calls[0].accumulator, null);
});

// ----------------------------------------------------------------------
// plotCurvePath — generated SVG path string

test("plotCurvePath returns a non-empty string with M/L commands for a real curve", () => {
  const d = plotCurvePath(DEFAULT_A, DEFAULT_B, -3, 3, 100);
  assert.ok(d.length > 0);
  assert.match(d, /^M /);
  assert.match(d, / L /);
  assert.match(d, / Z$/);
});

test("plotCurvePath on a 2-component curve emits two sub-paths", () => {
  // a=-7, b=6 has two components; the path should contain two "Z" closures.
  const d = plotCurvePath(-7, 6, -4, 4, 200);
  const zCount = (d.match(/Z/g) || []).length;
  assert.equal(zCount, 2, `expected 2 Z closures, got ${zCount}`);
});

// ----------------------------------------------------------------------
// finiteFieldPoints — the scatter chart on step 6.

test("finiteFieldPoints on y² = x³ + 7 mod 17 has at least 10 affine points", () => {
  const pts = finiteFieldPoints(FF_A, FF_B, FF_P);
  assert.ok(pts.length >= 10, `expected ≥10 points, got ${pts.length}: ${JSON.stringify(pts)}`);
  // Spot-check: (1, 5) should be a point because 5² = 25 ≡ 8 (mod 17), and
  // 1³ + 7 = 8. So (1, 5) and (1, 12) must both appear.
  assert.ok(pts.some((p) => p.x === 1 && p.y === 5), "expected (1,5) in the orbit");
  assert.ok(pts.some((p) => p.x === 1 && p.y === 12), "expected (1,12) in the orbit");
  // Every point must satisfy the equation.
  for (const { x, y } of pts) {
    const lhs = (y * y) % FF_P;
    const rhs = ((x * x * x) % FF_P + FF_B) % FF_P;
    assert.equal(lhs, rhs, `(${x},${y}) not on y² = x³ + 7 mod 17`);
  }
});

test("finiteFieldPoints on the ECDSA toy curve has 12 affine points (group order 13 minus the point at infinity)", () => {
  const pts = finiteFieldPoints(TOY_A, TOY_B, TOY_P);
  assert.equal(pts.length, 12);
});

// Exact count for the discrete-log step's curve. The brief asks for
// "at least 10 visible points" — we confirm the precise count here so a
// future change to the prime / coefficients can't silently shrink the
// visualization.
test("finiteFieldPoints on y² = x³ + 7 mod 17 has exactly 17 affine points (Hasse bound: 17 = p + 1 - t, total #E = 18 incl. ∞)", () => {
  const pts = finiteFieldPoints(FF_A, FF_B, FF_P);
  assert.equal(pts.length, 17, `expected 17 affine points, got ${pts.length}: ${JSON.stringify(pts)}`);
});

// The discrete-log widget seeds G = (15, 13) on the F_17 curve.
test("G = (15, 13) sits on y² ≡ x³ + 7 (mod 17) — used as the base point in the ECDLP widget", () => {
  const x = 15, y = 13;
  const lhs = (y * y) % 17;
  const rhs = ((x * x * x) % 17 + 7) % 17;
  assert.equal(lhs, rhs);
});

test("orbit of G=(15,13) on F_17 cycles through ≥ 6 points before hitting ∞ (enough to look chaotic)", () => {
  const G = { x: 15, y: 13 };
  let p = null;
  const seen = [];
  for (let k = 1; k <= 30; k++) {
    p = pointAdd(p, G, FF_A, FF_P);
    if (p === null) break;
    seen.push({ k, ...p });
  }
  assert.ok(seen.length >= 6, `orbit too small: only ${seen.length} steps`);
});

// ----------------------------------------------------------------------
// findThirdIntersection — the geometry helper used by the animator.

test("findThirdIntersection: third intersection of P+Q sits on the curve", () => {
  const P = { x: 0, y: Math.sqrt(5) };
  const Q = { x: 2, y: Math.sqrt(7) };
  const third = findThirdIntersection(P, Q, DEFAULT_A, DEFAULT_B);
  // Third intersection must satisfy the curve (third.y is on the line; both
  // values are equal at x=third.x because we're computing x via Vieta).
  // We assert -third.y (the reflection) is on the curve.
  const refl = { x: third.x, y: -third.y };
  const lhs = refl.y * refl.y;
  const rhs = refl.x ** 3 + DEFAULT_A * refl.x + DEFAULT_B;
  assert.ok(Math.abs(lhs - rhs) < 1e-6);
  // And P + Q (from pointAdd) should match the reflection.
  const sum = pointAdd(P, Q, DEFAULT_A, null);
  assert.ok(Math.abs(sum.x - refl.x) < 1e-6);
  assert.ok(Math.abs(sum.y - refl.y) < 1e-6);
});

test("findThirdIntersection: tangent case (P==Q) gives the same answer as pointDouble", () => {
  const P = { x: 2, y: Math.sqrt(7) };
  const third = findThirdIntersection(P, P, DEFAULT_A, DEFAULT_B);
  const dbl = pointDouble(P, DEFAULT_A, null);
  assert.ok(Math.abs(third.x - dbl.x) < 1e-6);
  assert.ok(Math.abs(-third.y - dbl.y) < 1e-6);
});

// ----------------------------------------------------------------------
// animatedAdd — orchestrator. Verify the state machine progresses through
// all four phases and resolves with the final point.

test("animatedAdd walks state through phases 0→1→2→3→4 and resolves at phase 4", async () => {
  const state = {};
  const P = { x: 0, y: Math.sqrt(5) };
  const Q = { x: 2, y: Math.sqrt(7) };
  // Very short durations so the test runs fast.
  const promise = animatedAdd(state, P, Q, DEFAULT_A, DEFAULT_B,
    { line: 5, third: 5, drop: 5, final: 5 });
  const result = await promise;
  assert.equal(state.phase, 4);
  assert.deepEqual(state.p1, P);
  assert.deepEqual(state.p2, Q);
  assert.ok(state.thirdPoint !== null);
  assert.ok(state.reflection !== null);
  // Reflection is on the curve.
  const lhs = result.y * result.y;
  const rhs = result.x ** 3 + DEFAULT_A * result.x + DEFAULT_B;
  assert.ok(Math.abs(lhs - rhs) < 1e-6);
});

test("animatedAdd phases progress in the right order during the run", async () => {
  const state = {};
  const phases = [];
  const P = { x: 0, y: Math.sqrt(5) };
  const Q = { x: 2, y: Math.sqrt(7) };
  // Watch state.phase right after each setTimeout fires by polling fast.
  const recorder = setInterval(() => phases.push(state.phase), 2);
  await animatedAdd(state, P, Q, DEFAULT_A, DEFAULT_B,
    { line: 30, third: 30, drop: 30, final: 30 });
  // Capture the final phase explicitly — the resolve callback flips to 4 in
  // the same microtask, so the interval may not have polled it before
  // clearInterval fires.
  phases.push(state.phase);
  clearInterval(recorder);
  // Phase only ever increases (never goes backwards).
  for (let i = 1; i < phases.length; i++) {
    assert.ok(phases[i] >= phases[i - 1],
      `phase regressed at index ${i}: ${phases.slice(0, i + 1).join(",")}`);
  }
  // Hit at least phases 1, 2, 3, 4 at some point.
  const unique = new Set(phases);
  for (const p of [1, 2, 3, 4]) {
    assert.ok(unique.has(p), `never saw phase ${p}; saw ${[...unique].join(",")}`);
  }
});

// ----------------------------------------------------------------------
// Presets / non-singular check.

test("CURVE_PRESETS all satisfy the non-singular discriminant condition", () => {
  for (const pre of CURVE_PRESETS) {
    assert.ok(isNonSingular(pre.a, pre.b),
      `preset ${pre.label} is singular (4a³+27b² = ${4*pre.a**3 + 27*pre.b**2})`);
  }
});

test("isNonSingular catches the canonical singular curve y² = x³", () => {
  assert.equal(isNonSingular(0, 0), false);
});
