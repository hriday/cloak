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
  const ciphertext = xorBytes(msg, symKey);
  return {
    ok: true,
    value: {
      h_ciphertext: ciphertext,
      h_first_encrypted: ciphertext[0],
      h_ciphertext_str: ciphertext.join(", "),
    },
  };
}

export function unwrap_key(input, state) {
  const got = _parseInt(input);
  if (got === null) return { ok: false, hint: "Enter a whole number." };
  const wrapped = BigInt(state.h_wrapped_key);
  const expected = modPow(wrapped, HYBRID_D, HYBRID_N);
  if (got !== expected) {
    return { ok: false, hint: `m = c^d mod n. With c=${wrapped}, d=103, n=143.` };
  }
  return _ok({ h_recovered_key: got });
}

export function xor_decrypt_head(input, state) {
  const got = _parseInt(input);
  if (got === null) return { ok: false, hint: "Enter a whole number." };
  const cipher = state?.h_ciphertext;
  if (!Array.isArray(cipher) || cipher.length === 0) {
    return { ok: false, hint: "No ciphertext in state — go back and encrypt first." };
  }
  const recoveredKey = Number(state.h_recovered_key);
  const firstByte = cipher[0];
  const expectedFirst = firstByte ^ recoveredKey;
  if (Number(got) !== expectedFirst) {
    return { ok: false, hint: `Compute first_ciphertext_byte XOR recovered_key. With c[0] = ${firstByte} and recovered_key = ${recoveredKey}.` };
  }
  const decoded = cipher.map((c) => c ^ recoveredKey);
  const recovered = decoded.map((code) => String.fromCharCode(code)).join("");
  return { ok: true, value: { h_recovered_message: recovered } };
}

export function info(_input, _state) {
  return { ok: true, value: {} };
}

// ---- Walkthroughs (powering the "I don't know how" button) ----
// Each returns an array of 3 escalating string rungs: method → worked
// example → answer. Same pattern as the RSA lesson's walkthroughs.

export const walkthroughs = {
  wrap_key: (state) => {
    const m = BigInt(state?.h_sym_key ?? 0);
    const result = modPow(m, HYBRID_E, HYBRID_N);
    return [
      `**The method:** c = m^e mod n. Here m is the symmetric key you picked, e and n are the public RSA key.`,
      `m = ${m}, e = 7, n = 143. So compute ${m}^7 mod 143.`,
      `**Answer: ${result}.** (In Python: \`pow(${m}, 7, 143)\`.)`,
    ];
  },

  xor_encrypt_head: (state) => {
    const msg = state?.h_message || "";
    const ch = msg[0] || "?";
    const code = msg.charCodeAt(0) || 0;
    const k = Number(state?.h_sym_key ?? 0);
    const result = code ^ k;
    return [
      `**The method:** XOR the ASCII code of the first character with your symmetric key. XOR is bit-wise; the answer is a byte value (0–255).`,
      `For '${ch}', ASCII = ${code}. sym_key = ${k}. Compute ${code} XOR ${k}.`,
      `**Answer: ${result}.** (In Python: \`${code} ^ ${k}\`.)`,
    ];
  },

  unwrap_key: (state) => {
    const c = BigInt(state?.h_wrapped_key ?? 0);
    const result = modPow(c, HYBRID_D, HYBRID_N);
    return [
      `**The method:** m = c^d mod n. Same shape as the toy RSA decrypt — d is the private exponent that undoes the wrap.`,
      `c = ${c}, d = 103, n = 143. Compute ${c}^103 mod 143.`,
      `**Answer: ${result}.** (In Python: \`pow(${c}, 103, 143)\`.)`,
    ];
  },

  xor_decrypt_head: (state) => {
    const cipher = Array.isArray(state?.h_ciphertext) ? state.h_ciphertext : [0];
    const c = cipher[0];
    const k = Number(state?.h_recovered_key ?? 0);
    const result = c ^ k;
    return [
      `**The method:** XOR is self-inverse — the same operation that encrypted decrypts. Take the first ciphertext byte and XOR with the recovered key.`,
      `c[0] = ${c}, recovered_key = ${k}. Compute ${c} XOR ${k}.`,
      `**Answer: ${result}.** That's the ASCII code for '${String.fromCharCode(result)}'. (In Python: \`${c} ^ ${k}\`.)`,
    ];
  },
};
