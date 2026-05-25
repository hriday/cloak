// Validators for the "Elliptic curves, visually" lesson.
//
// The interactive steps are all button-driven — the user clicks "Add P+Q"
// or "Double P" or picks a scalar k, and the validator records what just
// got computed so the codegen and downstream steps can refer back to it.
//
// State keys written:
//   point-addition       → ec_p, ec_q, ec_p_plus_q, ec_addition_done
//   point-doubling       → ec_p_dbl, ec_2p, ec_doubling_done
//   scalar-multiplication → ec_scalar_k, ec_scalar_kp, ec_scalar_steps
//   info steps           → {} (pass-through)

import {
  pointAdd, pointDouble, scalarMul,
  DEFAULT_A, DEFAULT_B,
} from "./ec_demo.js";

// The two preset points used for the point-addition step. Picked because
// both sit inside the plotted [-3, 3] window and produce a P+Q that does
// too. (Hand-verified: see ec_demo.test.js's "pointAdd over reals" case.)
export const ADD_PRESET = Object.freeze({
  p: Object.freeze({ x: 0,  y: Math.sqrt(5) }),  // (0,  2.236)
  q: Object.freeze({ x: 2,  y: Math.sqrt(7) }),  // (2,  2.646)
});

// The point used for the doubling step. Same curve.
export const DOUBLE_PRESET = Object.freeze({
  p: Object.freeze({ x: 2, y: Math.sqrt(7) }),
});

// ---- point-addition -----------------------------------------------------
//
// Button-driven. The template calls `check()` after the animation finishes
// (or immediately, on a replay click) and we record the canonical result.
// `input` is the multiInput object — we don't read from it; the points
// are fixed by the lesson.

export function point_addition(_input, _state) {
  const { p, q } = ADD_PRESET;
  const r = pointAdd(p, q, DEFAULT_A, null);
  if (r === null) {
    return { ok: false, hint: "Internal error: preset points don't form a valid sum." };
  }
  return {
    ok: true,
    value: {
      ec_p:          { x: p.x, y: p.y },
      ec_q:          { x: q.x, y: q.y },
      ec_p_plus_q:   { x: r.x, y: r.y },
      ec_addition_done: true,
    },
  };
}

// ---- point-doubling ----------------------------------------------------

export function point_doubling(_input, _state) {
  const { p } = DOUBLE_PRESET;
  const r = pointDouble(p, DEFAULT_A, null);
  if (r === null) {
    return { ok: false, hint: "Internal error: tangent is vertical (y=0)." };
  }
  return {
    ok: true,
    value: {
      ec_p_dbl:        { x: p.x, y: p.y },
      ec_2p:           { x: r.x, y: r.y },
      ec_doubling_done: true,
    },
  };
}

// ---- scalar-multiplication ---------------------------------------------
//
// Accepts an integer k ∈ [2, 15]. Runs scalarMul against the DOUBLE_PRESET
// base point and records the intermediate steps so the bit-ladder widget
// can replay the double-and-add procedure visually.

function _parseInt(s) {
  if (s === null || s === undefined) return null;
  const t = String(s).trim();
  if (!/^-?\d+$/.test(t)) return null;
  const n = Number(t);
  return Number.isFinite(n) ? n : null;
}

export function scalar_multiplication(input, _state) {
  const k = _parseInt(input);
  if (k === null) {
    return { ok: false, hint: "Enter a whole number between 2 and 15." };
  }
  if (k < 2 || k > 15) {
    return { ok: false, hint: "Pick a k between 2 and 15 — small enough to keep the result inside the plotted window." };
  }
  const { p } = DOUBLE_PRESET;
  const steps = [];
  const kp = scalarMul(k, p, DEFAULT_A, null, (info) => {
    steps.push({
      bitIndex:    info.bitIndex,
      bit:         info.bit,
      action:      info.action,
      // Snapshot accumulator + addend at this step so the widget can
      // tween between successive snapshots.
      accumulator: info.accumulator ? { x: info.accumulator.x, y: info.accumulator.y } : null,
      addend:      info.addend      ? { x: info.addend.x,      y: info.addend.y      } : null,
    });
  });
  if (kp === null) {
    return { ok: false, hint: "Got the point at infinity — pick a different k." };
  }
  return {
    ok: true,
    value: {
      ec_scalar_k:     k,
      ec_scalar_kp:    { x: kp.x, y: kp.y },
      ec_scalar_steps: steps,
    },
  };
}

// ---- info --------------------------------------------------------------

export function info(_input, _state) {
  return { ok: true, value: {} };
}

// ---- walkthroughs ------------------------------------------------------
//
// Help-me-more rungs for the three actionable steps. The info-only steps
// don't get walkthroughs — there's nothing to walk through.

export const walkthroughs = {
  point_addition: (_state) => [
    "**The geometric rule (one sentence):** draw a line through P and Q, find where it hits the curve a third time, then flip that third point across the x-axis — that's P + Q.",
    "**Why the flip?** Curves are symmetric: if (x, y) is on the curve, so is (x, −y) (because y is squared in the equation). The unflipped third intersection is the *negation* of P + Q. We define addition so that any line crossing the curve at three points has those three points summing to zero — and zero is the (made-up) 'point at infinity' that vertical lines meet at. To make the math close up cleanly, P + Q has to be the reflection.",
    "**The algebra:** the line through P=(xₚ, yₚ) and Q=(xq, yq) has slope `s = (yq − yₚ) / (xq − xₚ)`. Substituting into the curve equation gives a cubic in x whose roots are xₚ, xq, and (by Vieta's) `xᵣ = s² − xₚ − xq`. Then `yᵣ = s·(xₚ − xᵣ) − yₚ` — already negated, because the formula computes the *reflected* y directly. That's the entire addition law on a Weierstrass curve.",
  ],
  point_doubling: (_state) => [
    "**The geometric rule:** when you 'add P to itself,' there's no second point to draw a line through — so you use the *tangent* at P instead. Find where the tangent hits the curve again, then reflect across the x-axis.",
    "**Why a tangent?** Imagine Q sliding along the curve toward P. The secant line through P and Q approaches the tangent at P as Q → P. So the doubling formula is the addition formula with P=Q after taking that limit.",
    "**The algebra:** the tangent slope is `s = (3·xₚ² + a) / (2·yₚ)` (the derivative of `y² = x³ + ax + b`, implicit-differentiation style). Then `x₂ₚ = s² − 2·xₚ` and `y₂ₚ = s·(xₚ − x₂ₚ) − yₚ`. If yₚ = 0 the tangent is vertical and 2P is the point at infinity — same way P + (−P) lands there.",
  ],
  scalar_multiplication: (_state) => [
    "**The problem:** computing 13·P by adding P to itself 13 times is wasteful — and for real curves where k is 256 bits, it's impossible (10⁷⁷ additions). The standard trick: **double-and-add**, the same idea as fast modular exponentiation.",
    "**The algorithm:** write k in binary. Walk the bits from LSB to MSB. Keep two registers: `accumulator` (starts at the point at infinity) and `addend` (starts at P). On each bit: if the bit is 1, add `addend` to `accumulator`. Either way, double `addend` and shift k right. After ⌈log₂ k⌉ iterations you have k·P.",
    "**Worked example, k = 13 = 0b1101 (bits 1,0,1,1 LSB-first):** bit 0=1 → acc=P, addend=2P; bit 1=0 → skip, addend=4P; bit 2=1 → acc=P+4P=5P, addend=8P; bit 3=1 → acc=5P+8P=13P, addend=16P. Four iterations instead of thirteen — and the ratio gets much better as k grows.",
  ],
};
