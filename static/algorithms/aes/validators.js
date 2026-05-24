import { SBOX } from "./tables.js";

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

export function pick_aes_message(input, _state) {
  const s = input == null ? "" : String(input);
  if (s.length === 0) return { ok: false, hint: "Type at least one character." };
  if (s.length > 500) return { ok: false, hint: "Keep it under 500 characters." };
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code < 32 || code > 126) {
      return { ok: false, hint: `Only printable ASCII for now — no emoji, accents, tabs, or newlines. Found: '${s[i]}'.` };
    }
  }
  return { ok: true, value: { a_message: s } };
}

export function info(_input, _state) {
  return { ok: true, value: {} };
}
