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
