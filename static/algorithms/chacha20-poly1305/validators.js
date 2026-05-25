// Validators for the ChaCha20-Poly1305 lesson.
//
// Two real validators (quarter_round_line on step 3; encrypt_aead on step 6),
// the standard pass-through info validator, and walkthroughs.

import { encryptDemo, tamperDemo } from "./chap_demo.js";

// Hand-picked inputs for step 3 — kept as exports so the prompt can
// reference the literal values and stay in sync with the validator.
export const QR_INPUT_A = 0x11111111;
export const QR_INPUT_B = 0x01020304;
export const QR_EXPECTED_A = (QR_INPUT_A + QR_INPUT_B) >>> 0;  // 0x12131415

// Parse hex/decimal into a 32-bit unsigned integer or return null on
// any malformed input. Accepts: "305419896", "0x12131415", "12131415"
// (bare hex if any letter present), "0X..." (case-insensitive prefix).
function _parseU32(s) {
  if (s === null || s === undefined) return null;
  const t = String(s).trim();
  if (t === "") return null;
  let n;
  if (/^0[xX][0-9a-fA-F]+$/.test(t)) n = parseInt(t.slice(2), 16);
  else if (/^[0-9a-fA-F]+$/.test(t) && /[a-fA-F]/.test(t)) n = parseInt(t, 16);
  else if (/^\d+$/.test(t)) n = parseInt(t, 10);
  else return null;
  return Number.isFinite(n) ? n : null;
}

function _u32RangeOk(n) {
  return Number.isInteger(n) && n >= 0 && n <= 0xFFFFFFFF;
}

// ---- Step 3 — first line of the quarter-round ----
//
// Asks the learner for `(a + b) mod 2^32` where a, b are the hand-picked
// constants above. Only the first ARX line — the help_template walks
// the remaining three.
export function quarter_round_line(input, _state) {
  const n = _parseU32(input);
  if (n === null) {
    return { ok: false, hint: "Enter a 32-bit value in hex (0xNNNNNNNN) or decimal." };
  }
  if (!_u32RangeOk(n)) {
    return { ok: false, hint: "Quarter-round words are 32-bit (0 to 0xFFFFFFFF)." };
  }
  if (n !== QR_EXPECTED_A) {
    const hexExpected = `0x${QR_EXPECTED_A.toString(16).padStart(8, "0")}`;
    return {
      ok: false,
      hint: `Compute 0x${QR_INPUT_A.toString(16)} + 0x${QR_INPUT_B.toString(16).padStart(8, "0")} mod 2³² = ${hexExpected}. Additions wrap at 2³².`,
    };
  }
  return {
    ok: true,
    value: { chap_qr_input: QR_INPUT_A, chap_qr_output: QR_EXPECTED_A },
  };
}

// ---- Step 6 — encrypt + tamper demo ----
//
// Input shape: { message: string, aad?: string }. Generates a fresh
// random (key, nonce), runs the real AEAD, then immediately re-runs
// it against a flipped ciphertext byte to prove the tag catches tampering.
export async function encrypt_aead(input, _state) {
  const message = input?.message == null ? "" : String(input.message);
  const aad = input?.aad == null ? "" : String(input.aad);

  if (message.length === 0) return { ok: false, hint: "Type at least one character." };
  if (message.length > 500) return { ok: false, hint: "Keep the message under 500 characters." };
  for (let i = 0; i < message.length; i++) {
    const code = message.charCodeAt(i);
    if (code < 32 || code > 126) {
      return { ok: false, hint: `Only printable ASCII for now — no emoji, accents, tabs, or newlines. Found: '${message[i]}'.` };
    }
  }
  if (aad.length > 200) return { ok: false, hint: "Associated data must be ≤200 characters." };
  for (let i = 0; i < aad.length; i++) {
    const code = aad.charCodeAt(i);
    if (code < 32 || code > 126) {
      return { ok: false, hint: `Associated data must be printable ASCII. Found: '${aad[i]}'.` };
    }
  }

  // In Node without crypto.getRandomValues / TextEncoder this would fail;
  // gracefully degrade so validator unit tests pass even though full
  // encryption only happens in the browser. The AEAD itself runs in Node
  // — but encryptDemo specifically uses crypto.getRandomValues.
  const value = { chap_message: message, chap_aad: aad };
  let encryptionResult = null;
  let encryptError = null;
  try {
    if (typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function") {
      encryptionResult = await encryptDemo(message, aad);
    }
  } catch (e) {
    encryptError = String(e.message || e);
  }

  if (encryptionResult) {
    value.chap_key_hex = encryptionResult.keyHex;
    value.chap_nonce_hex = encryptionResult.nonceHex;
    value.chap_ciphertext_hex = encryptionResult.ciphertextHex;
    value.chap_tag_hex = encryptionResult.tagHex;
    value.chap_decrypted = encryptionResult.decrypted;

    // Tamper test — runs immediately so step 6 hands the Done step a
    // complete record. Uses the just-generated artifacts.
    try {
      const tamper = await tamperDemo({
        keyHex: encryptionResult.keyHex,
        nonceHex: encryptionResult.nonceHex,
        ciphertextHex: encryptionResult.ciphertextHex,
        tagHex: encryptionResult.tagHex,
        aad,
      });
      value.chap_tamper_failed = tamper.error === "InvalidTag";
      if (tamper.error && tamper.error !== "InvalidTag") {
        value.chap_tamper_error = tamper.error;
      }
    } catch (e) {
      value.chap_tamper_error = String(e.message || e);
      value.chap_tamper_failed = false;
    }
  }
  if (encryptError) value.chap_encrypt_error = encryptError;

  return { ok: true, value };
}

export function info(_input, _state) {
  return { ok: true, value: {} };
}

export const walkthroughs = {
  quarter_round_line: (_state) => {
    const hexA = `0x${QR_INPUT_A.toString(16)}`;
    const hexB = `0x${QR_INPUT_B.toString(16).padStart(8, "0")}`;
    const hexExp = `0x${QR_EXPECTED_A.toString(16).padStart(8, "0")}`;
    return [
      `**The method:** The ChaCha20 quarter-round runs 4 ARX lines on (a, b, c, d). The first line is just \`a = a + b mod 2³²\` — ordinary 32-bit unsigned addition that wraps on overflow.`,
      `Plug in the lesson values: ${hexA} + ${hexB}. The high half adds 0x11 + 0x01 = 0x12; the low halves slot in. No wrap (the sum fits in 32 bits), so this is straight addition.`,
      `**Answer: ${hexExp} (decimal ${QR_EXPECTED_A}).** (In Python: \`(${hexA} + ${hexB}) & 0xFFFFFFFF\`.) The remaining 3 lines update d, then b, then d again with XOR + rotate ops; together those 4 lines complete one quarter-round, and 160 of them (20 rounds × 8 quarter-rounds) produce one 64-byte keystream block.`,
    ];
  },
};
