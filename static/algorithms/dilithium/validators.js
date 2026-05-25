// Validators for the Dilithium (ML-DSA) lesson.
//
// One substantive validator:
//   dilithium_operation — driven by a button in the lesson template. Input
//                         shape is { op: "sign" | "verify", message,
//                         signature? }. On sign we produce a signature from
//                         the toy demo (frozen keypair, seeded per-attempt
//                         RNG); on verify we check that signature against
//                         the keypair.
//
// The validator mirrors Ed25519's ed25519_operation exactly in interface
// shape — the wizard template branch is shared (button row, message field,
// optional signature paste field, pill below with valid/invalid). The
// substantive difference is that signing is non-deterministic (the rejection
// sampling loop draws fresh y until one passes the ||z|| ≤ ACCEPT_BOUND
// check) so back-to-back sign of the same message produces *different*
// signatures — true to Dilithium's design and the opposite of Ed25519's
// deterministic behavior.

import {
  frozenKeypair,
  sign,
  verify,
  LESSON_SEED,
  ACCEPT_BOUND,
} from "./dilithium_demo.js";

// Format a signature as a compact hex-like string for display in the UI.
// Signature is { z, c, w } — each a k-vector of n-coefficient polynomials.
// We serialise as: <z polys><c poly><w polys> with each coefficient as 2
// little-endian hex bytes (since q = 257 < 2^16). Total length:
//   z: K*N*4 = 2*4*4 = 32 hex chars
//   c: N*4   = 16 hex chars
//   w: K*N*4 = 32 hex chars
//   total   : 80 hex chars
//
// Real ML-DSA-65 signatures are 3,309 bytes (6,618 hex chars). The toy is
// ~80× smaller because every parameter is dialled down to teaching scale.
function sigToHex(sig) {
  const parts = [];
  for (const vec of [sig.z, [sig.c], sig.w]) {
    for (const p of vec) {
      for (const c of p) {
        parts.push((c & 0xff).toString(16).padStart(2, "0"));
        parts.push(((c >> 8) & 0xff).toString(16).padStart(2, "0"));
      }
    }
  }
  return parts.join("");
}

// Inverse of sigToHex. Throws on malformed input.
function sigFromHex(hex) {
  const clean = hex.replace(/\s+/g, "").toLowerCase();
  if (!/^[0-9a-f]*$/.test(clean) || clean.length % 2 !== 0) {
    throw new Error("invalid hex");
  }
  // Expected length: 80 chars (40 bytes) per the layout above.
  const EXPECTED = 80;
  if (clean.length !== EXPECTED) {
    throw new Error("expected " + EXPECTED + " hex chars (got " + clean.length + ")");
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.slice(i, i + 2), 16);
  }
  // Layout:
  //  z: 2 polys × 4 coeffs × 2 bytes = 16 bytes (offset 0..16)
  //  c: 1 poly  × 4 coeffs × 2 bytes =  8 bytes (offset 16..24)
  //  w: 2 polys × 4 coeffs × 2 bytes = 16 bytes (offset 24..40)
  function readPoly(offset) {
    const p = new Array(4);
    for (let i = 0; i < 4; i++) {
      p[i] = bytes[offset + 2 * i] | (bytes[offset + 2 * i + 1] << 8);
    }
    return p;
  }
  const z = [readPoly(0), readPoly(8)];
  const c = readPoly(16);
  const w = [readPoly(24), readPoly(32)];
  return { z, c, w };
}

// ---- dilithium_operation -------------------------------------------------

export async function dilithium_operation(input, _state) {
  const op = input?.op;
  const message = (input?.message ?? "").trim();
  const signatureHex = (input?.signature ?? "").trim().toLowerCase();

  if (op !== "sign" && op !== "verify") {
    return { ok: false, hint: "Pick an operation: sign or verify." };
  }
  if (!message) {
    return { ok: false, hint: "Type a message to sign or verify." };
  }
  if (op === "verify") {
    if (!signatureHex) {
      return {
        ok: false,
        hint: "Verify needs the signature too — paste the hex output from a prior sign.",
      };
    }
    if (!/^[0-9a-f]+$/.test(signatureHex)) {
      return {
        ok: false,
        hint: "Signature must be hex (0-9, a-f). Did you paste the right field?",
      };
    }
    if (signatureHex.length !== 80) {
      return {
        ok: false,
        hint:
          "Toy Dilithium signatures are exactly 80 hex characters (40 bytes). " +
          "Got " + signatureHex.length + ".",
      };
    }
  }

  // Use the frozen keypair so the UI's "public key" display matches what
  // the validator signs/verifies with.
  const kp = frozenKeypair();

  let lastSignature = null;
  let verifyResult = null;
  let opError = null;
  let attempts = null;

  try {
    if (op === "sign") {
      // Each sign uses a fresh seed (clock + counter would be ideal in
      // browser; here we use message + a high-resolution Date.now()).
      const signSeed = LESSON_SEED + ":" + Date.now() + ":" + Math.random();
      const sig = await sign(message, kp.sk, signSeed);
      lastSignature = sigToHex(sig);
      attempts = sig.attempts;
    } else {
      try {
        const parsed = sigFromHex(signatureHex);
        verifyResult = await verify(message, parsed, kp.pk);
      } catch (_e) {
        // Malformed signature presents as "invalid".
        verifyResult = false;
      }
    }
  } catch (e) {
    opError = String(e?.message || e);
  }

  return {
    ok: true,
    value: {
      dilithium_last_op: op,
      dilithium_last_input: message,
      dilithium_signature: lastSignature,
      dilithium_verify_result: verifyResult,
      dilithium_op_error: opError,
      dilithium_attempts: attempts,
    },
  };
}

// ---- info -----------------------------------------------------------------

export function info(_input, _state) {
  return { ok: true, value: {} };
}

// ---- walkthroughs --------------------------------------------------------

export const walkthroughs = {
  dilithium_operation: (_state) => [
    `**The method:** Dilithium signing is a Fiat-Shamir loop. The page samples a fresh random ` +
    `polynomial *y* with coefficients in [-${40}, ${40}], computes the commitment ` +
    `**w = A·y**, derives a small challenge **c = H(message, w)** (a ternary polynomial), and ` +
    `computes the response **z = y + c·s1**. If ||z||∞ > ${ACCEPT_BOUND} the page *rejects* and ` +
    `restarts with a fresh y. About half the time the first attempt is rejected; that's the ` +
    `"rejection sampling" characteristic of Dilithium. Real ML-DSA-65 has a similar loop with ` +
    `larger parameters.`,

    `Try this: pick **Sign**, type 'hello', click Check. The output is 80 hex chars carrying ` +
    `(z, c, w). Sign 'hello' a *second* time — you'll get *different* bytes. Unlike Ed25519, ` +
    `Dilithium signing is randomized (because the rejection loop draws fresh y). Now pick ` +
    `**Verify**, paste the same 'hello' and signature → 'valid'. Flip one hex character of the ` +
    `signature → 'invalid'. Try verifying with a different message → 'invalid'.`,

    `**The point:** verification does **A·z − c·t**. Substitute z = y + c·s1 and t = A·s1 + s2: ` +
    `A·z − c·t = A·y + c·A·s1 − c·A·s1 − c·s2 = w − c·s2. The big A·s1 terms cancel, leaving ` +
    `only the tiny c·s2 noise (bounded by BETA = ${4} = n). So **w' ≈ w** within the noise ` +
    `budget — the verifier recovers the same w the signer committed to, the challenge hash ` +
    `matches, and the signature stands. Real ML-DSA ships a "hint" instead of w to save bytes; ` +
    `the toy ships w directly so you can see the cancellation work.`,
  ],
};
