// Validators for the Diffie-Hellman (classical) lesson.
//
// One substantive validator:
//   dh_compute — classical DH worked example: p=23, g=5, a=6, b=15 → s=2.
//
// This is the same arithmetic used in the X25519 lesson's `compute_dh`
// warmup; by design, doing one lesson makes the other feel familiar.
//
// Plus the conventional pass-through `info` validator and the
// `walkthroughs` object that drives the 3-rung help panel.

// ---- dh_compute -----------------------------------------------------------
//
// Page fixes p=23, g=5, Alice's secret a=6 → A=8, Bob's secret b=15 → B=19.
// The user, playing Alice, computes s = B^a mod p = 19^6 mod 23 = 2.
// Accept any whitespace-trimmed integer in [0, 22].

export function dh_compute(input, _state) {
  const raw = (input == null ? "" : String(input)).trim();
  if (raw === "") {
    return { ok: false, hint: "Enter a whole number." };
  }
  if (!/^-?\d+$/.test(raw)) {
    return { ok: false, hint: "Enter a whole number." };
  }
  const n = Number.parseInt(raw, 10);
  if (n < 0 || n > 22) {
    return { ok: false, hint: "The shared secret is in [0, 22]." };
  }
  if (n === 2) {
    return {
      ok: true,
      value: { dh_alice_secret: 6, dh_bob_secret: 15, dh_shared: 2 },
    };
  }
  return {
    ok: false,
    hint:
      "Compute 19^6 mod 23. Hint: 19² mod 23 = 16, 19⁴ mod 23 = 3, " +
      "19⁶ = 19⁴ · 19² mod 23 = 48 mod 23 = 2.",
  };
}

// ---- info -----------------------------------------------------------------

export function info(_input, _state) {
  return { ok: true, value: {} };
}

// ---- walkthroughs ---------------------------------------------------------

export const walkthroughs = {
  dh_compute: (_state) => [
    "**The setup:** Public parameters p=23, g=5. Alice picked secret a=6 and sent Bob A = 5^6 mod 23 = 8. Bob picked secret b=15 and sent Alice B = 5^15 mod 23 = 19. You're Alice — compute the shared secret s = B^a mod p = 19^6 mod 23.",
    "**The math (repeated squaring keeps the numbers small):** 19² = 361, and 361 mod 23 = 16 (since 23·15 = 345, and 361 − 345 = 16). 19⁴ = (19²)² = 16² = 256, and 256 mod 23 = 3 (23·11 = 253, 256 − 253 = 3). Then 19⁶ = 19⁴ · 19² mod 23 = 3 · 16 = 48, and 48 mod 23 = 2.",
    "**The answer is 2.** Bob will independently compute s = A^b mod p = 8^15 mod 23 and land on the same 2. Eve, who only saw p=23, g=5, A=8, B=19, has no shortcut — recovering a from A means solving the discrete logarithm 5^a ≡ 8 (mod 23). Easy for p=23, infeasible for a 2048-bit prime. That asymmetry is the whole 1976 trick.",
  ],
};
