// ECDSA validators — drive the toy-curve PS3-attack step.
//
// Curve / scenario constants are imported from ecdsa_toy.js so the prompt
// text, validator, and walkthrough never disagree about the numbers.

import { N, recoverDFromK, modInverse } from "./ecdsa_toy.js";

// Hand-baked attack scenario (matches the spec — see docs/superpowers/specs/
// 2026-05-25-ecdsa-lesson-design.md §"Pre-baked attack scenario"):
//   curve  : y^2 = x^3 + x + 6  (mod 11)
//   G      : (2, 7)             order n = 13
//   d      : 7                  (secret signing scalar)
//   k      : 3                  (the reused nonce — Sony's bug)
//   r      : 8                  (= (3·G).x mod n)
//   e1, s1 : 4, 7               (signature on message hash e1)
//   e2, s2 : 10, 9              (signature on message hash e2)
export const SCENARIO = Object.freeze({
  d: 7,
  k: 3,
  r: 8,
  e1: 4, s1: 7,
  e2: 10, s2: 9,
  n: N,
});

// Parse a signed integer from a string. Accepts decimal only — k is a small
// integer, no need for hex.
function _parseInt(s) {
  if (s === null || s === undefined) return null;
  const t = String(s).trim();
  if (!/^-?\d+$/.test(t)) return null;
  const n = Number(t);
  return Number.isFinite(n) ? n : null;
}

function _mod(a, m) {
  const r = a % m;
  return r < 0 ? r + m : r;
}

// `recover_k` — validator for step 5 (`the-ps3-attack`).
//
// Accepts ANY integer congruent to the true k mod n. So 3, 16 (= 3 + 13),
// and -10 (= 3 - 13) all pass; 0 is rejected because it has no modular
// inverse and breaks the signing equation; any other residue gives a hint.
//
// On success, the validator computes the private scalar d itself —
// matching the "advance the worked example" pattern used by RSA's
// compute_phi / compute_d chain — and writes both into state.
export function recover_k(input, _state) {
  const got = _parseInt(input);
  if (got === null) return { ok: false, hint: "Enter an integer." };

  const residue = _mod(got, SCENARIO.n);

  if (residue === 0) {
    return {
      ok: false,
      hint: "k cannot be 0 — it has no modular inverse, and signing with k=0 is undefined.",
    };
  }

  if (residue !== SCENARIO.k) {
    return {
      ok: false,
      hint:
        "Not quite. Compute (e₁ − e₂) · (s₁ − s₂)⁻¹ mod 13. " +
        "With e₁=4, e₂=10, s₁=7, s₂=9: differences are −6 and −2 — " +
        "reduce mod 13 (→ 7 and 11) before taking the inverse.",
    };
  }

  // Re-derive d from the canonical k so the worked-example state stays
  // self-consistent even if the user entered e.g. k = 16.
  const d = recoverDFromK(SCENARIO.k, SCENARIO.r, SCENARIO.s1, SCENARIO.e1, SCENARIO.n);

  return {
    ok: true,
    value: {
      ecdsa_recovered_k: SCENARIO.k,
      ecdsa_recovered_d: d,
    },
  };
}

export function info(_input, _state) {
  return { ok: true, value: {} };
}

// Three-rung walkthrough for the PS3 attack step. Rung 1 names the method,
// rung 2 walks the modular arithmetic with intermediate values, rung 3
// hands the answer.
export const walkthroughs = {
  recover_k: (_state) => {
    const { e1, e2, s1, s2, n } = SCENARIO;
    const diffE = _mod(e1 - e2, n);                            // 7
    const diffS = _mod(s1 - s2, n);                            // 11
    const diffSInv = modInverse(diffS, n);                     // 6
    const k = _mod(diffE * diffSInv, n);                       // 3
    return [
      `**The method:** Both signatures share r=${SCENARIO.r} because Sony reused k. Subtract the two signing equations:\n\ns₁ − s₂ ≡ k⁻¹ · (e₁ − e₂) (mod ${n})\n\nso k ≡ (e₁ − e₂) · (s₁ − s₂)⁻¹ (mod ${n}).`,
      `**Walk the modular arithmetic:**\n\n- e₁ − e₂ = ${e1} − ${e2} = ${e1 - e2} ≡ **${diffE}** (mod ${n})\n- s₁ − s₂ = ${s1} − ${s2} = ${s1 - s2} ≡ **${diffS}** (mod ${n})\n- (s₁ − s₂)⁻¹: find x where ${diffS}·x ≡ 1 (mod ${n}). ${diffS} · ${diffSInv} = ${diffS * diffSInv} ≡ 1 (mod ${n}), so x = **${diffSInv}**.\n- k = ${diffE} · ${diffSInv} = ${diffE * diffSInv} mod ${n}.`,
      `**k = ${k}.** Substitute into d = r⁻¹ · (s·k − e) mod ${n} and you get **d = ${SCENARIO.d}** — Sony's PS3 signing key. Two signatures, four lines of algebra.`,
    ];
  },
};
