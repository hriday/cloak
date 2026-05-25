import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";
import { pointAdd, pointDouble, scalarMul, DEFAULT_A } from "../ec_demo.js";

// ---- point_addition ---------------------------------------------------

test("point_addition writes ec_p / ec_q / ec_p_plus_q / ec_addition_done", () => {
  const r = v.point_addition({}, {});
  assert.equal(r.ok, true);
  assert.deepEqual(Object.keys(r.value).sort(),
    ["ec_addition_done", "ec_p", "ec_p_plus_q", "ec_q"]);
  assert.equal(r.value.ec_addition_done, true);
  assert.equal(typeof r.value.ec_p.x, "number");
  assert.equal(typeof r.value.ec_p_plus_q.x, "number");
});

test("point_addition's recorded sum agrees with pointAdd on the same preset", () => {
  const r = v.point_addition({}, {});
  const expected = pointAdd(v.ADD_PRESET.p, v.ADD_PRESET.q, DEFAULT_A, null);
  assert.ok(Math.abs(r.value.ec_p_plus_q.x - expected.x) < 1e-9);
  assert.ok(Math.abs(r.value.ec_p_plus_q.y - expected.y) < 1e-9);
});

test("point_addition's preset points lie on y² = x³ - 3x + 5", () => {
  const { p, q } = v.ADD_PRESET;
  for (const pt of [p, q]) {
    const lhs = pt.y * pt.y;
    const rhs = pt.x ** 3 + DEFAULT_A * pt.x + 5;
    assert.ok(Math.abs(lhs - rhs) < 1e-9,
      `preset ${JSON.stringify(pt)} not on curve`);
  }
});

// ---- point_doubling --------------------------------------------------

test("point_doubling writes ec_p_dbl / ec_2p / ec_doubling_done", () => {
  const r = v.point_doubling({}, {});
  assert.equal(r.ok, true);
  assert.deepEqual(Object.keys(r.value).sort(),
    ["ec_2p", "ec_doubling_done", "ec_p_dbl"]);
  assert.equal(r.value.ec_doubling_done, true);
});

test("point_doubling's recorded 2P agrees with pointDouble on the preset", () => {
  const r = v.point_doubling({}, {});
  const expected = pointDouble(v.DOUBLE_PRESET.p, DEFAULT_A, null);
  assert.ok(Math.abs(r.value.ec_2p.x - expected.x) < 1e-9);
  assert.ok(Math.abs(r.value.ec_2p.y - expected.y) < 1e-9);
});

// ---- scalar_multiplication ------------------------------------------

test("scalar_multiplication accepts integer 5", () => {
  const r = v.scalar_multiplication("5", {});
  assert.equal(r.ok, true);
  assert.equal(r.value.ec_scalar_k, 5);
  assert.equal(typeof r.value.ec_scalar_kp.x, "number");
  assert.ok(Array.isArray(r.value.ec_scalar_steps));
});

test("scalar_multiplication captures double-and-add steps in order", () => {
  // k=5 = 0b101 → 3 bits, bits (LSB→MSB) 1,0,1.
  const r = v.scalar_multiplication("5", {});
  const steps = r.value.ec_scalar_steps;
  assert.equal(steps.length, 3);
  assert.deepEqual(steps.map((s) => s.bit), [1, 0, 1]);
  assert.deepEqual(steps.map((s) => s.action), ["add", "skip", "add"]);
});

test("scalar_multiplication's recorded kP agrees with scalarMul independently", () => {
  for (const k of [2, 3, 5, 7]) {
    const r = v.scalar_multiplication(String(k), {});
    const expected = scalarMul(k, v.DOUBLE_PRESET.p, DEFAULT_A, null);
    assert.ok(Math.abs(r.value.ec_scalar_kp.x - expected.x) < 1e-9,
      `k=${k} x mismatch`);
    assert.ok(Math.abs(r.value.ec_scalar_kp.y - expected.y) < 1e-9,
      `k=${k} y mismatch`);
  }
});

test("scalar_multiplication rejects k=1 with the in-range hint", () => {
  const r = v.scalar_multiplication("1", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /between 2 and 15/);
});

test("scalar_multiplication rejects k=16", () => {
  const r = v.scalar_multiplication("16", {});
  assert.equal(r.ok, false);
});

test("scalar_multiplication rejects non-integer input", () => {
  assert.equal(v.scalar_multiplication("abc", {}).ok, false);
  assert.equal(v.scalar_multiplication("", {}).ok, false);
  assert.equal(v.scalar_multiplication("3.5", {}).ok, false);
  assert.equal(v.scalar_multiplication(null, {}).ok, false);
});

test("scalar_multiplication accepts numeric input as well as string", () => {
  const r = v.scalar_multiplication(5, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.ec_scalar_k, 5);
});

// ---- info --------------------------------------------------------------

test("info always returns ok with empty value", () => {
  assert.deepEqual(v.info("anything", {}), { ok: true, value: {} });
  assert.deepEqual(v.info(null, {}), { ok: true, value: {} });
});

// ---- walkthroughs ------------------------------------------------------

test("walkthroughs exports three rungs for each of the actionable steps", () => {
  for (const key of ["point_addition", "point_doubling", "scalar_multiplication"]) {
    assert.equal(typeof v.walkthroughs[key], "function", `${key} missing`);
    const rungs = v.walkthroughs[key]({});
    assert.equal(rungs.length, 3, `${key} should have 3 rungs`);
    rungs.forEach((r) => {
      assert.equal(typeof r, "string");
      assert.ok(r.length > 50, `rung too short: ${r}`);
    });
  }
});
