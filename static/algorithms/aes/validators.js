import { SBOX } from "./tables.js";
import { encryptMessage } from "./aes_demo.js";

// Canonical lesson values — referenced from prompts so they stay in sync.
export const SUB_BYTE_INPUT = 0x53;          // S-box row 5, col 3
export const ARK_STATE_BYTE = 0xED;          // = SBOX[0x53]
export const ARK_ROUND_KEY_BYTE = 0x2B;      // chosen so XOR result is 0xC6

// Parse a byte input: decimal "237", "0xED", "ED", "0xed", "ed". Null on parse failure.
function _parseByte(s) {
  if (s === null || s === undefined) return null;
  const t = String(s).trim();
  if (t === "") return null;
  let n;
  if (/^0x[0-9a-fA-F]+$/.test(t)) n = parseInt(t, 16);
  else if (/^[0-9a-fA-F]{1,2}$/.test(t) && /[a-fA-F]/.test(t)) n = parseInt(t, 16);
  else if (/^\d+$/.test(t)) n = parseInt(t, 10);
  else return null;
  return Number.isFinite(n) ? n : null;
}

function _byteRangeOk(n) {
  return Number.isInteger(n) && n >= 0 && n <= 255;
}

export function sub_byte(input, _state) {
  const n = _parseByte(input);
  if (n === null) return { ok: false, hint: "Enter a byte value (0–255 in decimal, or 0xNN in hex)." };
  if (!_byteRangeOk(n)) return { ok: false, hint: "S-box outputs a byte. Enter 0–255 (or 0xNN)." };
  const expected = SBOX[SUB_BYTE_INPUT];
  if (n !== expected) {
    return { ok: false, hint: `The S-box at row 5, column 3 (input 0x53) is 0x${expected.toString(16).toUpperCase()} (decimal ${expected}). Look at the highlighted cell above.` };
  }
  return { ok: true, value: { a_sub_input: SUB_BYTE_INPUT, a_sub_output: expected } };
}

export function add_round_key(input, _state) {
  const n = _parseByte(input);
  if (n === null) return { ok: false, hint: "Enter a byte value (0–255 in decimal, or 0xNN in hex)." };
  if (!_byteRangeOk(n)) return { ok: false, hint: "AddRoundKey outputs a byte. Enter 0–255 (or 0xNN)." };
  const expected = ARK_STATE_BYTE ^ ARK_ROUND_KEY_BYTE;
  if (n !== expected) {
    return { ok: false, hint: `AddRoundKey is byte-wise XOR. With state byte = 0x${ARK_STATE_BYTE.toString(16).toUpperCase()} (${ARK_STATE_BYTE}) and round-key byte = 0x${ARK_ROUND_KEY_BYTE.toString(16).toUpperCase()} (${ARK_ROUND_KEY_BYTE}), compute ${ARK_STATE_BYTE} XOR ${ARK_ROUND_KEY_BYTE} = ${expected} (0x${expected.toString(16).toUpperCase()}).` };
  }
  return { ok: true, value: { a_ark_input: ARK_STATE_BYTE, a_ark_key: ARK_ROUND_KEY_BYTE, a_ark_output: expected } };
}

// ShiftRows input row used in the lesson — kept here so the prompt can reference it.
export const SHIFT_INPUT_ROW = [0x09, 0xCF, 0x4F, 0x3C];

export function shift_row(input, _state) {
  const fields = ["b0", "b1", "b2", "b3"];
  const parsed = fields.map((k) => _parseByte(input?.[k]));
  if (parsed.some((n) => n === null)) {
    return { ok: false, hint: "Enter 4 bytes (one per column)." };
  }
  if (parsed.some((n) => !_byteRangeOk(n))) {
    return { ok: false, hint: "Each value must be 0–255." };
  }
  const expected = [SHIFT_INPUT_ROW[1], SHIFT_INPUT_ROW[2], SHIFT_INPUT_ROW[3], SHIFT_INPUT_ROW[0]];
  if (parsed.some((n, i) => n !== expected[i])) {
    const inStr = SHIFT_INPUT_ROW.map((b) => `0x${b.toString(16).toUpperCase()}`).join(", ");
    const outStr = expected.map((b) => `0x${b.toString(16).toUpperCase()}`).join(", ");
    return { ok: false, hint: `Row 1 shifts left by 1, so input [${inStr}] becomes [${outStr}] — the first byte wraps to the end.` };
  }
  return { ok: true, value: { a_shifted_row: expected } };
}

export async function pick_aes_message(input, _state) {
  const s = input == null ? "" : String(input);
  if (s.length === 0) return { ok: false, hint: "Type at least one character." };
  if (s.length > 500) return { ok: false, hint: "Keep it under 500 characters." };
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code < 32 || code > 126) {
      return { ok: false, hint: `Only printable ASCII for now — no emoji, accents, tabs, or newlines. Found: '${s[i]}'.` };
    }
  }
  // Validation passed — encrypt via Web Crypto (browser only). In Node tests,
  // crypto.subtle may not be available; gracefully degrade so the validation
  // tests still pass.
  let encryptionResult = null;
  let encryptError = null;
  try {
    if (typeof crypto !== "undefined" && crypto.subtle) {
      encryptionResult = await encryptMessage(s);
    }
  } catch (e) {
    encryptError = String(e.message || e);
  }
  const value = { a_message: s };
  if (encryptionResult) {
    value.a_key_hex = encryptionResult.keyHex;
    value.a_iv_hex = encryptionResult.ivHex;
    value.a_ciphertext_hex = encryptionResult.ciphertextHex;
    value.a_recovered = encryptionResult.recovered;
  }
  if (encryptError) value.a_encrypt_error = encryptError;
  return { ok: true, value };
}

export function info(_input, _state) {
  return { ok: true, value: {} };
}

export const walkthroughs = {
  sub_byte: (_state) => {
    const result = SBOX[SUB_BYTE_INPUT];
    return [
      `**The method:** AES SubBytes replaces each byte with the value from a fixed 16×16 table called the S-box. The high nibble of the input picks the row; the low nibble picks the column.`,
      `Input 0x53 — high nibble 5, low nibble 3. Look at row 5, column 3 of the S-box grid above (it's highlighted).`,
      `**Answer: 0x${result.toString(16).toUpperCase()} (decimal ${result}).** (In Python: \`SBOX[0x53]\`.)`,
    ];
  },

  shift_row: (_state) => {
    const hex = (b) => `0x${b.toString(16).toUpperCase().padStart(2, "0")}`;
    const inStr = SHIFT_INPUT_ROW.map(hex).join(", ");
    const expected = [SHIFT_INPUT_ROW[1], SHIFT_INPUT_ROW[2], SHIFT_INPUT_ROW[3], SHIFT_INPUT_ROW[0]];
    const outStr = expected.map(hex).join(", ");
    return [
      `**The method:** ShiftRows rotates each row of the state left by its row index. Row 0 unchanged, row 1 by 1, row 2 by 2, row 3 by 3. We're doing row 1, so shift left by 1.`,
      `Input row: [${inStr}]. Drop the first byte to the end; everything else moves left by 1.`,
      `**Answer: [${outStr}].**`,
    ];
  },

  add_round_key: (_state) => {
    const result = ARK_STATE_BYTE ^ ARK_ROUND_KEY_BYTE;
    return [
      `**The method:** AddRoundKey XORs each state byte with the corresponding round-key byte. Same XOR you've seen — bit-wise exclusive OR.`,
      `State byte = 0x${ARK_STATE_BYTE.toString(16).toUpperCase()} (${ARK_STATE_BYTE}), round-key byte = 0x${ARK_ROUND_KEY_BYTE.toString(16).toUpperCase()} (${ARK_ROUND_KEY_BYTE}). Compute ${ARK_STATE_BYTE} XOR ${ARK_ROUND_KEY_BYTE}.`,
      `**Answer: 0x${result.toString(16).toUpperCase()} (decimal ${result}).** (In Python: \`${ARK_STATE_BYTE} ^ ${ARK_ROUND_KEY_BYTE}\`.)`,
    ];
  },
};
