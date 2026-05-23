import { modPow, xorBytes } from "./math.js";

// Canonical RSA keypair baked into hybrid lesson prompts.
// p=11, q=13 → n=143, φ=120, e=7, d=103. Verified: 7×103 ≡ 1 (mod 120).
const HYBRID_E = 7n;
const HYBRID_D = 103n;
const HYBRID_N = 143n;

function _parseInt(s) {
  if (s === null || s === undefined) return null;
  const t = String(s).trim();
  if (!/^-?\d+$/.test(t)) return null;
  return BigInt(t);
}

function _ok(value) {
  const out = {};
  for (const [k, val] of Object.entries(value)) {
    out[k] = typeof val === "bigint" ? Number(val) : val;
  }
  return { ok: true, value: out };
}

export function pick_sym_key(input, _state) {
  const got = _parseInt(input);
  if (got === null) return { ok: false, hint: "Enter a whole number." };
  if (got < 0n || got > 127n) {
    return { ok: false, hint: "Pick a number from 0 to 127 (so it fits in our RSA key, n=143)." };
  }
  return _ok({ h_sym_key: got });
}

export function wrap_key(input, state) {
  const got = _parseInt(input);
  if (got === null) return { ok: false, hint: "Enter a whole number." };
  const symKey = BigInt(state.h_sym_key);
  const expected = modPow(symKey, HYBRID_E, HYBRID_N);
  if (got !== expected) {
    return { ok: false, hint: `c = m^e mod n. With m=${symKey}, e=7, n=143.` };
  }
  return _ok({ h_wrapped_key: got });
}

export function type_message(input, _state) {
  const s = input == null ? "" : String(input);
  if (s.length === 0) return { ok: false, hint: "Type at least one character." };
  if (s.length > 500) return { ok: false, hint: "Keep it under 500 characters." };
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code < 32 || code > 126) {
      return { ok: false, hint: `Only printable ASCII for now — no emoji, accents, tabs, or newlines. Found: '${s[i]}'.` };
    }
  }
  return { ok: true, value: { h_message: s, h_first_char: s[0], h_first_code: s.charCodeAt(0) } };
}

export function xor_encrypt_head(input, state) {
  const got = _parseInt(input);
  if (got === null) return { ok: false, hint: "Enter a whole number." };
  const msg = state?.h_message || "";
  if (!msg) return { ok: false, hint: "No message in state — go back and type one first." };
  const symKey = Number(state.h_sym_key);
  const firstCode = msg.charCodeAt(0);
  const expectedFirst = firstCode ^ symKey;
  if (Number(got) !== expectedFirst) {
    return { ok: false, hint: `Compute first_char XOR sym_key. With first_char = ${firstCode} (ASCII of '${msg[0]}') and sym_key = ${symKey}.` };
  }
  return { ok: true, value: { h_ciphertext: xorBytes(msg, symKey) } };
}
