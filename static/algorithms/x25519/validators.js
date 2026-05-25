// Validators for the X25519 lesson.
//
// Three substantive validators:
//   compute_dh   — classical Diffie-Hellman: 19^6 mod 23 = 2
//   clamp_byte   — RFC 7748 byte-0 clamping: byte AND 0xF8
//   exchange_keys — runs the live Web Crypto exchange and writes the hex
//                   blobs to state (or the canonical RFC fallback)
//
// Plus the conventional pass-through `info` validator and the
// `walkthroughs` object that drives the 3-rung help panel.

import { runExchange } from "./x25_demo.js";

// ---- compute_dh -----------------------------------------------------------
//
// Classical DH worked example: p=23, g=5, a=6, b=15 → A=8, B=19, s=2.
// The user has been told A and B; the page asks them to compute s = B^a mod p
// from Alice's side. Accept any whitespace-trimmed integer.

export function compute_dh(input, _state) {
  const raw = (input == null ? "" : String(input)).trim();
  if (raw === "") {
    return { ok: false, hint: "Enter a whole number." };
  }
  if (!/^-?\d+$/.test(raw)) {
    return { ok: false, hint: "Enter a whole number." };
  }
  const n = Number.parseInt(raw, 10);
  if (n === 2) {
    return { ok: true, value: { x25_classical_shared: 2 } };
  }
  return {
    ok: false,
    hint:
      "Compute 19^6 mod 23. Hint: 19² mod 23 = 361 mod 23 = 16. " +
      "19⁴ = 16² mod 23 = 256 mod 23 = 3. " +
      "19⁶ = 19⁴ · 19² mod 23 = 3 · 16 mod 23 = 48 mod 23 = 2.",
  };
}

// ---- clamp_byte -----------------------------------------------------------
//
// Byte-0 clamping per RFC 7748 §5: clear bits 0, 1, 2 — i.e. AND with 0xF8.
// The page pins byte 0 = 0xA7 (binary 10100111). Clamped: 10100000 = 0xA0.
// Accept hex (0xNN, NN with at least one hex letter) or decimal.

function _parseByte(raw) {
  const s = raw.trim().toLowerCase().replace(/^#/, "");
  if (s === "") return null;
  if (s.startsWith("0x")) {
    const body = s.slice(2);
    if (!/^[0-9a-f]+$/.test(body)) return null;
    return Number.parseInt(body, 16);
  }
  // Bare hex (contains a-f) — accept too.
  if (/^[0-9a-f]+$/.test(s) && /[a-f]/.test(s)) {
    return Number.parseInt(s, 16);
  }
  if (/^\d+$/.test(s)) {
    return Number.parseInt(s, 10);
  }
  return null;
}

export function clamp_byte(input, _state) {
  const raw = input == null ? "" : String(input);
  const parsed = _parseByte(raw);
  if (parsed === null || Number.isNaN(parsed)) {
    return { ok: false, hint: "Enter a byte in hex (0xNN) or decimal (0–255)." };
  }
  if (parsed < 0 || parsed > 255) {
    return { ok: false, hint: "A byte is 0–255." };
  }
  // The page pins the example byte to 0xA7. Expected clamped value: 0xA0.
  if (parsed === 0xA0) {
    return { ok: true, value: { x25_clamped: "0xA0" } };
  }
  return {
    ok: false,
    hint:
      "Clear the bottom three bits of 0xA7. " +
      "0xA7 = 10100111. Mask with 0xF8 = 11111000. " +
      "Result: 10100000 = 0xA0.",
  };
}

// ---- exchange_keys --------------------------------------------------------
//
// Button-press validator: the page calls this when the user clicks "Run".
// The actual input is ignored; we run the Web Crypto exchange (or fall back
// to the RFC vectors) and stash the resulting hex blobs in state for the
// page to render.

export async function exchange_keys(_input, _state) {
  try {
    const r = await runExchange();
    return {
      ok: true,
      value: {
        x25_alice_pub:      r.alicePubHex,
        x25_bob_pub:        r.bobPubHex,
        x25_shared_secret:  r.sharedHexFromAlice,
        x25_shared_from_b:  r.sharedHexFromBob,
        x25_match:          r.match,
        x25_used_fallback:  r.usedFallback,
      },
    };
  } catch (err) {
    return {
      ok: false,
      hint:
        "Couldn't run the key exchange. Refresh the step to retry. (" +
        (err && err.message ? err.message : String(err)) + ")",
    };
  }
}

// ---- info -----------------------------------------------------------------

export function info(_input, _state) {
  return { ok: true, value: {} };
}

// ---- walkthroughs ---------------------------------------------------------

export const walkthroughs = {
  compute_dh: (_state) => [
    "**The setup:** Alice and Bob agreed on public parameters p=23, g=5. Alice picked secret a=6 and sent Bob A = 5^6 mod 23 = 8. Bob picked secret b=15 and sent Alice B = 5^15 mod 23 = 19. You're Alice; compute s = B^a mod p = 19^6 mod 23.",
    "**The math:** Repeated squaring keeps the numbers small. 19² = 361, and 361 mod 23 = 16 (since 23·15 = 345, 361 − 345 = 16). 19⁴ = (19²)² = 16² = 256, and 256 mod 23 = 3 (23·11 = 253, 256 − 253 = 3). 19⁶ = 19⁴ · 19² mod 23 = 3 · 16 = 48, and 48 mod 23 = 2.",
    "**The point:** Bob will independently compute s = A^b mod p = 8^15 mod 23 — and land on the same 2. Eve sees A=8 and B=19 on the wire but can't recover a or b without solving the discrete logarithm. That asymmetry — easy to compute g^x mod p forward, hard to invert — is the entire foundation of Diffie-Hellman.",
  ],
  clamp_byte: (_state) => [
    "**Why clamp?** A raw 32-byte X25519 scalar has two problems: small-subgroup attacks (where a malicious peer's public key can leak information about your private key) and a variable-length scalar (which lets the Montgomery ladder leak timing). RFC 7748 §5 specifies three bit-twiddles that fix both.",
    "**The byte-0 rule:** Clear bits 0, 1, and 2 — i.e. mask with 0xF8 (binary 11111000). This forces the scalar to be a multiple of 8, which puts it in the cofactor-8 subgroup and dodges the small-subgroup attack. Your byte is 0xA7 = 10100111. AND with 11111000 = 10100000 = 0xA0.",
    "**The other two:** byte 31 also gets clamped (`AND 0x7F, OR 0x40`) — the first clears the high bit, the second sets bit 6, together forcing every clamped scalar to be exactly 254 bits long so the Montgomery ladder runs constant-time. We only check byte 0 here; the page shows byte 31 alongside so you see the full ritual.",
  ],
};
