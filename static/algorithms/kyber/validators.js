// Validators for the Kyber (ML-KEM) lesson.
//
// One substantive validator:
//   encap_coefficient — parses an integer in [0, 257), compares to the
//                       canonical v[0] derived from the lesson's frozen
//                       vectors (seed = cloak-kyber-v1, bit = 1).
//
// Plus the conventional pass-through `info` validator and a `walkthroughs`
// object that drives the 3-rung help panel for the input step. All the
// math the user is asked to do is dot-products of small polynomials in
// R_257[X]/(X^4+1) — easy to step through verbally, hard to do silently
// in your head, which is exactly why the help rungs build it up coefficient
// by coefficient.

import { Q, HALF_Q, frozenVectors } from "./kyber_demo.js";

// The canonical answer for step 5 (`encapsulation`) — re-derived from the
// shared seed at module load so any change to the toy code propagates
// here without the validator silently drifting from the lesson copy.
const _frozen = frozenVectors(1);
const EXPECTED_V0 = _frozen.v[0]; // 180 for seed cloak-kyber-v1, bit=1

// ---- encap_coefficient ---------------------------------------------------
//
// Parses an integer in [0, 257), compares to the canonical v[0]. Three
// rejection paths, each with a hint tuned to what the learner most likely
// got wrong:
//   - empty / unparseable    → "Enter an integer."
//   - out of range           → "Coefficients in R_257 are integers from 0 to 256."
//   - wrong value            → walks the dot product coefficient by coefficient
//                              and reveals the expected answer.

export function encap_coefficient(input, _state) {
  const raw = (input == null ? "" : String(input)).trim();
  if (raw === "") {
    return { ok: false, hint: "Enter an integer." };
  }
  if (!/^-?\d+$/.test(raw)) {
    return { ok: false, hint: "Enter an integer." };
  }
  const n = Number.parseInt(raw, 10);
  if (n < 0 || n >= Q) {
    return {
      ok: false,
      hint: "Coefficients in R_257 are integers from 0 to 256.",
    };
  }
  if (n === EXPECTED_V0) {
    return { ok: true, value: { kyber_v_coeff: n } };
  }
  return {
    ok: false,
    hint:
      "Compute (tᵀ·r)[0] + e2[0] + m̂[0] mod 257. " +
      "The dot product tᵀ·r is one polynomial in R_257 — take its " +
      "constant term, then add e2[0] = " + _frozen.e2[0] +
      " and the message coefficient m̂[0] = " + HALF_Q +
      ". Reduce mod 257. Expected: " + EXPECTED_V0 + ".",
  };
}

// ---- info -----------------------------------------------------------------

export function info(_input, _state) {
  return { ok: true, value: {} };
}

// ---- walkthroughs ---------------------------------------------------------
//
// Three rungs for `encap_coefficient`. Each builds on the previous so a
// learner who got stuck after rung 1 can climb without re-reading the prose.
//
// Rung 1: setup — what v[0] is, where the numbers come from.
// Rung 2: the actual calculation, working coefficient by coefficient.
// Rung 3: the punchline — why the message bit lands in coefficient 0.

export const walkthroughs = {
  encap_coefficient: (_state) => {
    const f = _frozen;
    // Render polys for the hint text. The lesson page also shows these,
    // but the walkthrough re-shows them inline so the rung is self-contained.
    const t0 = "[" + f.t[0].join(", ") + "]";
    const t1 = "[" + f.t[1].join(", ") + "]";
    const r0 = "[" + f.r[0].join(", ") + "]";
    const r1 = "[" + f.r[1].join(", ") + "]";
    const e2 = "[" + f.e2.join(", ") + "]";
    return [
      "**The formula:** `v = tᵀ·r + e2 + m̂ mod 257`. " +
      "`tᵀ·r` is a *polynomial* in R_257 — specifically it's `t[0]·r[0] + t[1]·r[1]`, " +
      "where each `t[i]·r[i]` is a polynomial multiplication in `R_257[X]/(X^4+1)` " +
      "(degree-4 terms wrap with a sign flip). " +
      "`m̂ = [128, 0, 0, 0]` because the bit we're sending is 1. " +
      "`e2 = " + e2 + "`. " +
      "We want `v[0]` — only the constant term.",

      "**Constant term of tᵀ·r.** With `t[0] = " + t0 + "`, `t[1] = " + t1 + "`, " +
      "`r[0] = " + r0 + "`, `r[1] = " + r1 + "`. " +
      "Each polynomial product's constant term comes from two places: " +
      "(a) the direct product `t[i][0] · r[i][0]`, and " +
      "(b) the wrap-around terms `−t[i][j] · r[i][n−j]` for j = 1, 2, 3 — " +
      "because X^j · X^(n−j) = X^n = −1. Sum all 8 such terms across i ∈ {0, 1} " +
      "and reduce mod 257 to get `(tᵀ·r)[0]`.",

      "**Putting it together.** Call the constant term you just computed `c`. " +
      "Then `v[0] = c + e2[0] + 128 mod 257`. " +
      "With `e2[0] = " + f.e2[0] + "` and the message coefficient 128, " +
      "the canonical answer is **" + EXPECTED_V0 + "**. " +
      "On the decapsulation step the recipient computes `v − sᵀ·u` and reads coefficient 0 — " +
      "it should land near 128, in the [64, 192] window that decodes back to bit 1.",
    ];
  },
};

// Exposed for tests / inspection — the canonical answer the validator
// expects, sourced from the shared frozen vectors.
export const _CANONICAL_V0 = EXPECTED_V0;
