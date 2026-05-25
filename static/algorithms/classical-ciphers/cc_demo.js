// Educational implementations of Caesar, Vigenère, and the one-time pad,
// plus a small frequency-analysis toolkit used to break Vigenère.
//
// These are EDUCATIONAL ONLY. Do not use any of this code to protect
// anything real. Classical ciphers fall to a patient teenager with a
// laptop; that's the whole point of this lesson.

// English letter frequencies (Wikipedia, Cornell), used to score candidate
// shifts during frequency analysis. Sums to ~1.0.
export const ENGLISH_FREQ = {
  a: 0.08167, b: 0.01492, c: 0.02782, d: 0.04253, e: 0.12702,
  f: 0.02228, g: 0.02015, h: 0.06094, i: 0.06966, j: 0.00153,
  k: 0.00772, l: 0.04025, m: 0.02406, n: 0.06749, o: 0.07507,
  p: 0.01929, q: 0.00095, r: 0.05987, s: 0.06327, t: 0.09056,
  u: 0.02758, v: 0.00978, w: 0.02360, x: 0.00150, y: 0.01974,
  z: 0.00074,
};

const A = "a".charCodeAt(0);

function _isLetter(code) {
  return (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
}

function _shiftChar(ch, k) {
  const code = ch.charCodeAt(0);
  if (code >= 65 && code <= 90) {
    return String.fromCharCode(((code - 65 + k) % 26 + 26) % 26 + 65);
  }
  if (code >= 97 && code <= 122) {
    return String.fromCharCode(((code - 97 + k) % 26 + 26) % 26 + 97);
  }
  return ch;
}

// ---- Caesar ---------------------------------------------------------------

export function caesarEncrypt(plaintext, k) {
  const shift = ((k % 26) + 26) % 26;
  let out = "";
  for (const ch of plaintext) out += _shiftChar(ch, shift);
  return out;
}

export function caesarDecrypt(ciphertext, k) {
  return caesarEncrypt(ciphertext, -k);
}

// ---- Vigenère -------------------------------------------------------------

function _normalizeKey(key) {
  let out = "";
  for (const ch of key) {
    const code = ch.charCodeAt(0);
    if (code >= 65 && code <= 90) out += String.fromCharCode(code + 32);
    else if (code >= 97 && code <= 122) out += ch;
  }
  return out;
}

export function vigenereEncrypt(plaintext, key) {
  const k = _normalizeKey(key);
  if (k.length === 0) throw new Error("Vigenère key must contain at least one letter.");
  let out = "";
  let ki = 0;
  for (const ch of plaintext) {
    if (_isLetter(ch.charCodeAt(0))) {
      const shift = k.charCodeAt(ki % k.length) - A;
      out += _shiftChar(ch, shift);
      ki += 1;
    } else {
      out += ch;
    }
  }
  return out;
}

export function vigenereDecrypt(ciphertext, key) {
  const k = _normalizeKey(key);
  if (k.length === 0) throw new Error("Vigenère key must contain at least one letter.");
  let out = "";
  let ki = 0;
  for (const ch of ciphertext) {
    if (_isLetter(ch.charCodeAt(0))) {
      const shift = k.charCodeAt(ki % k.length) - A;
      out += _shiftChar(ch, -shift);
      ki += 1;
    } else {
      out += ch;
    }
  }
  return out;
}

// ---- Frequency analysis ---------------------------------------------------

// Returns the per-letter frequency of `text` (letters only), keyed by
// lowercase a-z. Each value is the share of letters of that kind; sums
// to 1.0 for non-empty inputs. Empty input returns all zeros.
export function frequencyDist(text) {
  const counts = {};
  for (let i = 0; i < 26; i++) counts[String.fromCharCode(A + i)] = 0;
  let total = 0;
  for (const ch of text) {
    const code = ch.charCodeAt(0);
    if (code >= 65 && code <= 90) {
      counts[String.fromCharCode(code + 32)] += 1;
      total += 1;
    } else if (code >= 97 && code <= 122) {
      counts[ch] += 1;
      total += 1;
    }
  }
  const dist = {};
  for (const k of Object.keys(counts)) {
    dist[k] = total === 0 ? 0 : counts[k] / total;
  }
  return dist;
}

// Score how well a frequency distribution matches English. We use the
// "chi-squared" statistic against ENGLISH_FREQ — LOWER is better. This is
// the simplest viable scoring function and works well on >100 char streams.
function _chiSquaredScore(dist) {
  let score = 0;
  for (const letter of Object.keys(ENGLISH_FREQ)) {
    const expected = ENGLISH_FREQ[letter];
    const observed = dist[letter] || 0;
    const diff = observed - expected;
    score += (diff * diff) / expected;
  }
  return score;
}

// Tries all 26 Caesar shifts on the input, returns {shift, plaintext}
// where `shift` is the value k that minimizes the chi-squared distance
// between the SHIFTED ciphertext's letter distribution and English.
export function breakCaesarByFrequency(ciphertext) {
  let best = { shift: 0, score: Infinity, plaintext: ciphertext };
  for (let k = 0; k < 26; k++) {
    const candidate = caesarDecrypt(ciphertext, k);
    const score = _chiSquaredScore(frequencyDist(candidate));
    if (score < best.score) best = { shift: k, score, plaintext: candidate };
  }
  return { shift: best.shift, plaintext: best.plaintext };
}

// Breaks a Vigenère ciphertext given a KNOWN key length. Splits the
// letters into `keyLen` streams (stream i = ciphertext letters at positions
// i, i+keyLen, i+2*keyLen, ...), breaks each as a Caesar cipher via
// chi-squared frequency analysis, then reassembles the key and runs
// vigenereDecrypt to recover the plaintext.
//
// Non-letter characters (spaces, punctuation) are skipped when splitting
// into streams but preserved in the recovered plaintext.
export function breakVigenereByFrequency(ciphertext, keyLen) {
  if (!Number.isInteger(keyLen) || keyLen < 1) {
    throw new Error("keyLen must be a positive integer.");
  }
  // Extract letter-only streams, one per key position.
  const streams = Array.from({ length: keyLen }, () => "");
  let letterIdx = 0;
  for (const ch of ciphertext) {
    if (_isLetter(ch.charCodeAt(0))) {
      streams[letterIdx % keyLen] += ch;
      letterIdx += 1;
    }
  }
  // Break each stream as a Caesar cipher.
  let key = "";
  for (let i = 0; i < keyLen; i++) {
    const { shift } = breakCaesarByFrequency(streams[i]);
    key += String.fromCharCode(A + shift);
  }
  const plaintext = vigenereDecrypt(ciphertext, key);
  return { key, plaintext };
}

// ---- One-time pad ---------------------------------------------------------
//
// XOR-based OTP over byte arrays. Encrypt and decrypt are the same
// operation (XOR is self-inverse). The key MUST be exactly as long as
// the message and MUST be truly random and used only once — otherwise
// it's not an OTP, it's just a weak stream cipher.

function _toBytes(input) {
  if (input instanceof Uint8Array) return input;
  if (typeof input === "string") return new TextEncoder().encode(input);
  if (Array.isArray(input)) return new Uint8Array(input);
  throw new Error("OTP input must be a Uint8Array, string, or array of bytes.");
}

export function otpEncrypt(plaintext, key) {
  const pt = _toBytes(plaintext);
  const k = _toBytes(key);
  if (k.length !== pt.length) {
    throw new Error(`OTP key length (${k.length}) must equal message length (${pt.length}).`);
  }
  const out = new Uint8Array(pt.length);
  for (let i = 0; i < pt.length; i++) out[i] = pt[i] ^ k[i];
  return out;
}

export function otpDecrypt(ciphertext, key) {
  // Identical to encrypt — XOR is self-inverse.
  return otpEncrypt(ciphertext, key);
}
