import { toyEncrypt, mitmFind } from "./mitm.js";

// Canonical lesson values — referenced from prompts so they stay in sync.
export const MITM_PLAINTEXT = 0x42;
export const MITM_K1_HINT = 0x10;
export const MITM_K2_HINT = 0x20;
export const MITM_CIPHERTEXT = toyEncrypt(MITM_PLAINTEXT, MITM_K1_HINT, MITM_K2_HINT);

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

export function mitm_attack(input, _state) {
  const k1 = _parseByte(input?.k1);
  const k2 = _parseByte(input?.k2);
  if (k1 === null || k2 === null) {
    return { ok: false, hint: "Enter two whole numbers (0–255 each, decimal or 0xNN)." };
  }
  if (!_byteRangeOk(k1) || !_byteRangeOk(k2)) {
    return { ok: false, hint: "Each key is 8 bits — 0–255." };
  }
  const result = toyEncrypt(MITM_PLAINTEXT, k1, k2);
  if (result !== MITM_CIPHERTEXT) {
    return { ok: false, hint: `MITM attack: find (K1, K2) such that toyEncrypt(0x${MITM_PLAINTEXT.toString(16).toUpperCase()}, K1, K2) = 0x${MITM_CIPHERTEXT.toString(16).toUpperCase()}. For 2-round XOR, K1 XOR K2 must equal 0x${(MITM_K1_HINT ^ MITM_K2_HINT).toString(16).toUpperCase()}.` };
  }
  return { ok: true, value: { td_k1: k1, td_k2: k2 } };
}

export function pick_3des_message(input, _state) {
  const s = input == null ? "" : String(input);
  if (s.length === 0) return { ok: false, hint: "Type at least one character." };
  if (s.length > 500) return { ok: false, hint: "Keep it under 500 characters." };
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code < 32 || code > 126) {
      return { ok: false, hint: `Only printable ASCII for now — no emoji, accents, tabs, or newlines. Found: '${s[i]}'.` };
    }
  }
  return { ok: true, value: { td_message: s } };
}

export function info(_input, _state) {
  return { ok: true, value: {} };
}

export const walkthroughs = {
  mitm_attack: (_state) => {
    const matches = mitmFind(MITM_PLAINTEXT, MITM_CIPHERTEXT);
    const hex = (b) => "0x" + b.toString(16).toUpperCase().padStart(2, "0");
    const first = matches[0];
    return [
      `**The method:** Find any (K1, K2) such that toyEncrypt(plaintext, K1, K2) = ciphertext. MITM: build a lookup of E(K1, plaintext) for all 256 K1s, then for each K2 compute D(K2, ciphertext) and check the table.`,
      `Plaintext: ${hex(MITM_PLAINTEXT)}, ciphertext: ${hex(MITM_CIPHERTEXT)}. For 2-round XOR, valid (K1, K2) pairs satisfy K1 XOR K2 = ${hex(MITM_PLAINTEXT ^ MITM_CIPHERTEXT)}. There are 256 such pairs.`,
      `**Try (${hex(first[0])}, ${hex(first[1])}).** That's the first match from the brute force, but any pair where K1 XOR K2 = ${hex(MITM_PLAINTEXT ^ MITM_CIPHERTEXT)} also works.`,
    ];
  },
};
