// Validators for the padding-oracle lesson.
//
// Two substantive validators:
//   recover_byte   — runs the single-byte attack against the simulator and
//                    writes the recovered byte (as hex), the query count,
//                    and the target ciphertext block to state.
//   recover_block  — runs the full-block attack against the simulator and
//                    writes the recovered plaintext + total query count.
//
// Plus the conventional pass-through `info` validator and the
// `walkthroughs` object that drives the 3-rung help panel.

import { recoverByte, recoverBlock } from "./po_attack.js";
import {
  getTargetCiphertext,
  getPlaintext,
  query as _oracleQuery,
} from "./po_simulator.js";

// ---- recover_byte ---------------------------------------------------------
//
// Button-press validator: the page calls this when the user clicks "Run
// attack" on step 4. The input is ignored; we run the attack against the
// in-process simulator and stash the resulting hex blobs in state for the
// page to render.

export async function recover_byte(_input, _state) {
  // Detect missing Web Crypto early so we can produce a useful hint rather
  // than a generic "attack failed" error.
  if (typeof crypto === "undefined" || !crypto.subtle) {
    return {
      ok: false,
      hint:
        "This step needs a modern browser with Web Crypto. " +
        "Try Chrome / Firefox / Safari.",
    };
  }

  let target, recovered;
  try {
    target = await getTargetCiphertext();
    recovered = await recoverByte(15, new Uint8Array(16));
  } catch (e) {
    return {
      ok: false,
      hint:
        "The attack module failed mid-run — refresh the step and retry. " +
        "Original: " + (e && e.message ? e.message : String(e)),
    };
  }

  if (!recovered || typeof recovered.byte !== "number") {
    return {
      ok: false,
      hint:
        "Oracle returned bad_padding for all 256 candidates. " +
        "Refresh and retry.",
    };
  }

  return {
    ok: true,
    value: {
      po_recovered_byte_hex: recovered.byte.toString(16).padStart(2, "0"),
      po_queries_made: recovered.queries,
      po_target_block_hex: target.ct_hex,
      po_target_iv_hex: target.iv_hex,
    },
  };
}

// ---- recover_block --------------------------------------------------------
//
// Step 5's button-press validator. Runs the full 16-byte attack, writes the
// recovered plaintext + total query count to state. The page UI separately
// drives an animated reveal by calling po_attack.recoverBlock directly with
// its own progressCallback — the validator just produces the final state
// write so progress survives a step-advance / reload.

export async function recover_block(_input, _state) {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    return {
      ok: false,
      hint:
        "This step needs a modern browser with Web Crypto. " +
        "Try Chrome / Firefox / Safari.",
    };
  }

  let result, target;
  try {
    target = await getTargetCiphertext();
    result = await recoverBlock();
  } catch (e) {
    return {
      ok: false,
      hint:
        "The block-recovery attack failed mid-run — refresh and retry. " +
        "Original: " + (e && e.message ? e.message : String(e)),
    };
  }

  if (!result || !(result.plaintext instanceof Uint8Array)) {
    return {
      ok: false,
      hint:
        "Block recovery did not produce 16 bytes. " +
        "Refresh and retry.",
    };
  }

  // Decode as UTF-8 for display, but also keep the hex so the page can
  // show non-printable bytes correctly.
  let asString = null;
  try {
    asString = new TextDecoder("utf-8", { fatal: false }).decode(result.plaintext);
  } catch (_e) {
    asString = null;
  }

  const ptHex = Array.from(result.plaintext)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return {
    ok: true,
    value: {
      po_plaintext: asString,
      po_plaintext_hex: ptHex,
      po_total_queries: result.totalQueries,
      po_target_block_hex: target.ct_hex,
      po_target_iv_hex: target.iv_hex,
    },
  };
}

// ---- info -----------------------------------------------------------------

export function info(_input, _state) {
  return { ok: true, value: {} };
}

// ---- walkthroughs ---------------------------------------------------------

export const walkthroughs = {
  recover_byte: (_state) => [
    `**The setup:** The simulator holds a random AES-128 key and a fixed 16-byte plaintext, encrypted to one ciphertext block. You see only the ciphertext (and its IV) — no key, no plaintext. The oracle's API is one function: \`query(iv_hex, ct_hex)\` returning \`"ok"\`, \`"bad_padding"\`, or \`"internal_error"\`. Your job is to recover the last byte of the plaintext using only that response.`,
    `**The trick:** In CBC, plaintext = D(C) XOR IV. The decryption D(C) is fixed by the key (which you don't have), but you fully control the IV (which you do). If you can find a forged IV whose last byte makes the decrypted plaintext end in valid PKCS7 — most likely \`0x01\` — the oracle returns \`"ok"\` and you've learned exactly one byte of D(C). XOR with the real IV's last byte to recover the real plaintext byte.`,
    `**The sweep:** For each candidate byte 0x00..0xFF, replace the real IV's last byte with the candidate, send to the oracle, watch for the response that isn't \`"bad_padding"\`. Average 128 queries, worst-case 256. One subtle edge: if the resulting plaintext is \`...0x02 0x02\` you'll get a false positive (the last two bytes form valid padding by accident). The attack disambiguates by perturbing the second-to-last forged IV byte and re-querying — if the response stays non-bad_padding, the suffix was truly \`0x01\` and the candidate is real.`,
  ],
  recover_block: (_state) => [
    `**Induction:** Once you have the last byte, force the plaintext's last byte to \`0x02\` (XOR the forged IV's last byte appropriately), then sweep the second-to-last byte's 256 candidates looking for valid \`0x02 0x02\` padding. Then force \`0x03 0x03 0x03\`, sweep again. Then \`0x04 0x04 0x04 0x04\`. Repeat 16 times. Each byte costs ~128 oracle queries on average; the full block costs ~2048 queries.`,
    `**No key, no problem:** You never see the AES key. You never run any cryptographic primitive yourself. The entire attack is a search over 256 byte values per position, gated only by the oracle's \`"ok"\` vs \`"bad_padding"\` response. That single bit of side-channel information is enough to decrypt the whole block — which is the entire reason TLS 1.0/1.1 moved to encrypt-then-MAC (TLS 1.2) and the industry moved to AEAD modes (AES-GCM, ChaCha20-Poly1305) for TLS 1.3.`,
    `**Real-world incarnations:** Vaudenay (Eurocrypt 2002) introduced the attack on PKCS7-padded CBC. BEAST (2011) and Lucky 13 (2013) weaponised it against TLS — Lucky 13 in particular extracted the padding/MAC distinguisher from response *timing* rather than a literal error string, but the structural attack is the same one you just ran. POODLE (2014) revived it against SSLv3. The fix everywhere: encrypt-then-MAC ordering and, more durably, AEAD modes where any tampering is detected before the padding check runs.`,
  ],
};
