// Canonical lesson values for Twofish — referenced from prompts and hints so they stay in sync.
// Step 4 (whitening): output = input_byte XOR whitening_byte. Twofish XORs plaintext bytes with
// whitening subkeys before round 1 (and again at the output) — same pattern as AES AddRoundKey.
export const WHITENING_INPUT = 0x6A;
export const WHITENING_KEY = 0x35;
export const WHITENING_OUTPUT = (WHITENING_INPUT ^ WHITENING_KEY) & 0xFF; // = 0x5F

const _hex2 = (n) => "0x" + (n & 0xFF).toString(16).toUpperCase().padStart(2, "0");
const _bin8 = (n) => (n & 0xFF).toString(2).padStart(8, "0");

// Parse a byte: "0x5F", "5F", "0x5f", or decimal "95". Returns 0–255 int or null.
function _parseByte(s) {
  if (s === null || s === undefined) return null;
  const t = String(s).trim();
  if (t === "") return null;
  let n;
  if (/^0x[0-9a-fA-F]+$/.test(t)) n = parseInt(t.slice(2), 16);
  else if (/^[0-9a-fA-F]{1,2}$/.test(t) && /[a-fA-F]/.test(t)) n = parseInt(t, 16);
  else if (/^\d+$/.test(t)) n = parseInt(t, 10);
  else return null;
  if (!Number.isFinite(n)) return null;
  return n;
}

function _byteRangeOk(n) {
  return Number.isInteger(n) && n >= 0 && n <= 255;
}

export function whitening(input, _state) {
  const n = _parseByte(input);
  if (n === null) {
    return { ok: false, hint: "Enter a byte in hex (0xNN) or decimal." };
  }
  if (!_byteRangeOk(n)) {
    return { ok: false, hint: "A byte is 8 bits — 0 to 255 (0x00 to 0xFF)." };
  }
  if (n !== WHITENING_OUTPUT) {
    return {
      ok: false,
      hint:
        `Whitening is byte-wise XOR. Line up the bits and XOR each column ` +
        `(0 if bits match, 1 if they differ): ` +
        `${_hex2(WHITENING_INPUT)} = ${_bin8(WHITENING_INPUT)}, ` +
        `${_hex2(WHITENING_KEY)} = ${_bin8(WHITENING_KEY)}, ` +
        `XOR = ${_bin8(WHITENING_OUTPUT)} = ${_hex2(WHITENING_OUTPUT)}.`,
    };
  }
  return { ok: true, value: { tf_whitening_input: _hex2(WHITENING_INPUT), tf_whitening_output: _hex2(WHITENING_OUTPUT) } };
}

export function pick_twofish_message(input, _state) {
  const s = input == null ? "" : String(input).trim();
  if (s.length === 0) return { ok: false, hint: "Type at least one character." };
  if (s.length > 500) return { ok: false, hint: "Keep it under 500 characters." };
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code < 32 || code > 126) {
      return { ok: false, hint: `Only printable ASCII for now — no emoji, accents, tabs, or newlines. Found: '${s[i]}'.` };
    }
  }
  return { ok: true, value: { tf_message: s } };
}

export function info(_input, _state) {
  return { ok: true, value: {} };
}

export const walkthroughs = {
  whitening: (_state) => [
    `**The method:** Whitening XORs the plaintext byte with a whitening subkey, bit by bit (Twofish does this before round 1 and again at the output — same pattern as AES AddRoundKey). For each bit position: 0 if the two bits match, 1 if they differ.`,
    `Walk it through: ${_hex2(WHITENING_INPUT)} = ${_bin8(WHITENING_INPUT)} and ${_hex2(WHITENING_KEY)} = ${_bin8(WHITENING_KEY)}. Stack them and XOR column by column: ${_bin8(WHITENING_INPUT)} XOR ${_bin8(WHITENING_KEY)} = ${_bin8(WHITENING_OUTPUT)}. That binary value is ${_hex2(WHITENING_OUTPUT)} in hex.`,
    `**Answer: ${_hex2(WHITENING_OUTPUT)}** (decimal ${WHITENING_OUTPUT}). Whitening is cheap — just a XOR — but it adds an extra layer of key material at the cipher's boundaries, frustrating attacks that target the first and last rounds.`,
  ],
};
