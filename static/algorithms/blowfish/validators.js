// Canonical lesson values for Blowfish — referenced from prompts and hints so they stay in sync.
// Step 3 (f-function): F = ((S1[a] + S2[b]) XOR S3[c]) + S4[d], all adds mod 2^32.
export const F_INPUT = 0x12345678;
export const S1_VALUE = 0xD7CABA51; // S1[0x12]
export const S2_VALUE = 0x4BCA8A93; // S2[0x34]
export const S3_VALUE = 0x9A3FE5C1; // S3[0x56]
export const S4_VALUE = 0x1E45EE99; // S4[0x78]

// Compute F once and bake it in: ((S1 + S2) XOR S3) + S4, mod 2^32.
const _add32 = (x, y) => ((x + y) >>> 0);
export const F_OUTPUT = _add32((_add32(S1_VALUE, S2_VALUE) ^ S3_VALUE) >>> 0, S4_VALUE);
// = 0xD7F08FBE.

const _hex = (n) => "0x" + n.toString(16).toUpperCase().padStart(8, "0");

// Parse a 32-bit input: "0xD7F08FBE", "D7F08FBE", "d7f08fbe", or decimal "3623849918".
// Returns an unsigned 32-bit integer, or null if unparseable.
function _parse32(s) {
  if (s === null || s === undefined) return null;
  const t = String(s).trim();
  if (t === "") return null;
  let n;
  if (/^0x[0-9a-fA-F]+$/.test(t)) n = parseInt(t.slice(2), 16);
  else if (/^[0-9a-fA-F]+$/.test(t) && /[a-fA-F]/.test(t)) n = parseInt(t, 16);
  else if (/^\d+$/.test(t)) n = parseInt(t, 10);
  else return null;
  if (!Number.isFinite(n)) return null;
  return n >>> 0;
}

function _range32Ok(n) {
  return Number.isInteger(n) && n >= 0 && n <= 0xFFFFFFFF;
}

export function f_function(input, _state) {
  const n = _parse32(input);
  if (n === null) {
    return { ok: false, hint: "Enter a 32-bit value in hex (0xNNNNNNNN) or decimal." };
  }
  if (!_range32Ok(n)) {
    return { ok: false, hint: "F outputs a 32-bit value (0 to 0xFFFFFFFF)." };
  }
  if (n !== F_OUTPUT) {
    return {
      ok: false,
      hint: `Compute ((${_hex(S1_VALUE)} + ${_hex(S2_VALUE)}) XOR ${_hex(S3_VALUE)}) + ${_hex(S4_VALUE)} mod 2^32. All additions are mod 2^32 — overflow wraps. Answer: ${_hex(F_OUTPUT)}.`,
    };
  }
  return { ok: true, value: { bf_f_input: F_INPUT, bf_f_output: _hex(F_OUTPUT) } };
}

export function pick_blowfish_message(input, _state) {
  const s = input == null ? "" : String(input).trim();
  if (s.length === 0) return { ok: false, hint: "Type at least one character." };
  if (s.length > 500) return { ok: false, hint: "Keep it under 500 characters." };
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code < 32 || code > 126) {
      return { ok: false, hint: `Only printable ASCII for now — no emoji, accents, tabs, or newlines. Found: '${s[i]}'.` };
    }
  }
  return { ok: true, value: { bf_message: s } };
}

export function info(_input, _state) {
  return { ok: true, value: {} };
}

export const walkthroughs = {
  f_function: (_state) => {
    const sum1 = _add32(S1_VALUE, S2_VALUE);
    const xor1 = (sum1 ^ S3_VALUE) >>> 0;
    return [
      `**The method:** Blowfish's F splits the 32-bit input into 4 bytes (a, b, c, d), looks each one up in its own S-box (each S-box maps 8 bits to 32 bits), then combines: \`F = ((S1[a] + S2[b]) XOR S3[c]) + S4[d]\`. All additions are mod 2^32 (overflow wraps).`,
      `The four S-box lookups for this input are: S1[0x12] = ${_hex(S1_VALUE)}, S2[0x34] = ${_hex(S2_VALUE)}, S3[0x56] = ${_hex(S3_VALUE)}, S4[0x78] = ${_hex(S4_VALUE)}. Step by step: ${_hex(S1_VALUE)} + ${_hex(S2_VALUE)} = ${_hex(sum1)} (mod 2^32). Then ${_hex(sum1)} XOR ${_hex(S3_VALUE)} = ${_hex(xor1)}. Finally ${_hex(xor1)} + ${_hex(S4_VALUE)} = the answer.`,
      `**Answer: ${_hex(F_OUTPUT)}** (decimal ${F_OUTPUT}). The final add wraps mod 2^32 — that's how Blowfish mixes bits cheaply.`,
    ];
  },
};
