// Simulated padding-oracle server. The "server" decrypts an attacker-supplied
// (iv, ct) under a secret AES-128 key, then runs a strict PKCS7 padding check
// and returns one of three explicit responses:
//
//   "ok"             — decryption succeeded AND PKCS7 padding is valid
//   "bad_padding"    — decryption succeeded but PKCS7 padding is malformed
//   "internal_error" — decrypt itself blew up (rare; defensive)
//
// The key never leaves this module. The attacker's job is to recover the
// secret plaintext using only the three-way response — no key, no oracle
// for the key, no timing channel. The single bit of information the server
// leaks ("did the padding parse?") is enough to decrypt the whole block.
//
// Pedagogical only. A real server distinguishes padding errors from MAC
// errors via timing (Lucky 13), via length-based response sizes, or — in
// the worst cases — by returning literally different HTTP status codes. We
// use explicit string responses to make the attack legible; the structural
// vulnerability is identical.
//
// Implementation note. Web Crypto AES-CBC always strips PKCS7 padding on
// decrypt — there's no flag to disable it — and throws an opaque
// OperationError on malformed padding. That's the opposite of what an
// oracle needs to expose. So this module ships a small pure-JS AES-128
// decryption (FIPS-197 reference implementation). One block per query;
// performance isn't a concern. The simulator deliberately leaks the
// padding result anyway — that's the whole point.

// ---- pure-JS AES-128 (single-block decrypt) ----

const _SBOX = [
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];
const _INV_SBOX = (() => {
  const out = new Array(256);
  for (let i = 0; i < 256; i++) out[_SBOX[i]] = i;
  return out;
})();
const _RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36];

function _xtime(a) {
  return ((a << 1) ^ (((a >> 7) & 1) * 0x1b)) & 0xff;
}
function _gmul(a, b) {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    a = _xtime(a);
    b >>= 1;
  }
  return p & 0xff;
}

function _keyExpansion(key) {
  // AES-128: 11 round keys × 16 bytes = 176 bytes.
  const w = new Uint8Array(176);
  w.set(key, 0);
  for (let i = 16; i < 176; i += 4) {
    let t0 = w[i - 4], t1 = w[i - 3], t2 = w[i - 2], t3 = w[i - 1];
    if (i % 16 === 0) {
      // RotWord
      const tmp = t0; t0 = t1; t1 = t2; t2 = t3; t3 = tmp;
      // SubWord
      t0 = _SBOX[t0]; t1 = _SBOX[t1]; t2 = _SBOX[t2]; t3 = _SBOX[t3];
      // Rcon
      t0 ^= _RCON[i / 16 - 1];
    }
    w[i]     = w[i - 16]     ^ t0;
    w[i + 1] = w[i - 16 + 1] ^ t1;
    w[i + 2] = w[i - 16 + 2] ^ t2;
    w[i + 3] = w[i - 16 + 3] ^ t3;
  }
  return w;
}

function _invShiftRows(s) {
  const t = new Uint8Array(16);
  t[0]  = s[0];  t[1]  = s[13]; t[2]  = s[10]; t[3]  = s[7];
  t[4]  = s[4];  t[5]  = s[1];  t[6]  = s[14]; t[7]  = s[11];
  t[8]  = s[8];  t[9]  = s[5];  t[10] = s[2];  t[11] = s[15];
  t[12] = s[12]; t[13] = s[9];  t[14] = s[6];  t[15] = s[3];
  for (let i = 0; i < 16; i++) s[i] = t[i];
}

function _aes128DecryptBlock(key, block) {
  const w = _keyExpansion(key);
  const s = new Uint8Array(block);

  for (let i = 0; i < 16; i++) s[i] ^= w[160 + i];

  for (let round = 9; round >= 1; round--) {
    _invShiftRows(s);
    for (let i = 0; i < 16; i++) s[i] = _INV_SBOX[s[i]];
    for (let i = 0; i < 16; i++) s[i] ^= w[round * 16 + i];
    for (let c = 0; c < 4; c++) {
      const a0 = s[c*4], a1 = s[c*4+1], a2 = s[c*4+2], a3 = s[c*4+3];
      s[c*4]   = _gmul(a0,0x0e) ^ _gmul(a1,0x0b) ^ _gmul(a2,0x0d) ^ _gmul(a3,0x09);
      s[c*4+1] = _gmul(a0,0x09) ^ _gmul(a1,0x0e) ^ _gmul(a2,0x0b) ^ _gmul(a3,0x0d);
      s[c*4+2] = _gmul(a0,0x0d) ^ _gmul(a1,0x09) ^ _gmul(a2,0x0e) ^ _gmul(a3,0x0b);
      s[c*4+3] = _gmul(a0,0x0b) ^ _gmul(a1,0x0d) ^ _gmul(a2,0x09) ^ _gmul(a3,0x0e);
    }
  }

  _invShiftRows(s);
  for (let i = 0; i < 16; i++) s[i] = _INV_SBOX[s[i]];
  for (let i = 0; i < 16; i++) s[i] ^= w[i];
  return s;
}

// ---- simulator state ----

let _state = null;
let _statePromise = null;

const _PLAINTEXT_BANK = [
  "attack at dawn!!",
  "secret message_!",
  "the eagle flies.",
  "cipher must fall",
  "no key required.",
  "hidden in plain!",
  "padding leaks me",
  "vaudenay was rt!",
];

async function _initState() {
  if (typeof crypto === "undefined" || !crypto.subtle || !crypto.getRandomValues) {
    throw new Error("po_simulator requires Web Crypto (crypto.subtle).");
  }

  const ptString = _PLAINTEXT_BANK[
    Math.floor(Math.random() * _PLAINTEXT_BANK.length)
  ];
  const ptBytes = new TextEncoder().encode(ptString);
  if (ptBytes.length !== 16) {
    throw new Error("po_simulator plaintext must be exactly 16 bytes");
  }

  const keyRaw = crypto.getRandomValues(new Uint8Array(16));
  const ivRaw = crypto.getRandomValues(new Uint8Array(16));

  // Web Crypto encrypts (with mandatory PKCS7); we'll only keep the first
  // ciphertext block since the data is exactly 16 bytes — the second block
  // is just the all-0x10 padding block, irrelevant to the attack.
  const encKey = await crypto.subtle.importKey(
    "raw", keyRaw, { name: "AES-CBC" }, false, ["encrypt"]
  );
  const ctBuf = await crypto.subtle.encrypt(
    { name: "AES-CBC", iv: ivRaw }, encKey, ptBytes
  );
  const ct = new Uint8Array(ctBuf).slice(0, 16);

  _state = {
    keyRaw,
    ivHex: _bytesToHex(ivRaw),
    ctHex: _bytesToHex(ct),
    plaintext: ptString,
    queriesServed: 0,
  };
  return _state;
}

async function _getState() {
  if (_state) return _state;
  if (!_statePromise) _statePromise = _initState();
  return _statePromise;
}

// ---- public API ----

// The oracle. Returns "ok" | "bad_padding" | "internal_error".
//
// Validation is the standard naive PKCS7 check: read the last byte N,
// require 1 ≤ N ≤ 16, require the last N bytes all equal N. This is the
// exact validation rule that powered every real-world padding oracle
// (TLS 1.0 → Lucky 13, ASP.NET ViewState, JSF view-state). The
// vulnerability is not in the check — the check is correct. The
// vulnerability is *exposing the result* to the attacker as a
// distinguishable response, instead of returning the same generic error
// for every decrypt failure including MAC mismatches.
export async function query(iv_hex, ct_hex) {
  const state = await _getState();
  state.queriesServed += 1;

  let pt;
  try {
    const iv = _hexToBytes(iv_hex);
    const ct = _hexToBytes(ct_hex);
    if (iv.length !== 16 || ct.length !== 16) return "internal_error";
    const decrypted = _aes128DecryptBlock(state.keyRaw, ct);
    pt = new Uint8Array(16);
    for (let i = 0; i < 16; i++) pt[i] = decrypted[i] ^ iv[i];
  } catch (_e) {
    return "internal_error";
  }

  const lastByte = pt[15];
  if (lastByte < 1 || lastByte > 16) return "bad_padding";
  for (let i = 16 - lastByte; i < 16; i++) {
    if (pt[i] !== lastByte) return "bad_padding";
  }
  return "ok";
}

// Expose the target ciphertext (iv, ct) to the attacker. This is the only
// information the attacker has at the start of the attack — no key, no
// plaintext, no oracle hints. Just one 16-byte ciphertext block + its IV.
export async function getTargetCiphertext() {
  const state = await _getState();
  return { iv_hex: state.ivHex, ct_hex: state.ctHex };
}

// Reveal the plaintext. Used only by tests + validators to confirm the
// attack recovered the right bytes — never by the attack module itself.
export async function getPlaintext() {
  const state = await _getState();
  return state.plaintext;
}

// How many oracle queries has the simulator served? Reset between sessions
// by reloading the module / page.
export async function getQueryCount() {
  const state = await _getState();
  return state.queriesServed;
}

// Test hook: reset the simulator state so each test starts fresh.
// Production pages should never call this.
export function _resetForTests() {
  _state = null;
  _statePromise = null;
}

// ---- helpers ----

function _bytesToHex(arr) {
  return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function _hexToBytes(hex) {
  const clean = String(hex).replace(/\s+/g, "").toLowerCase();
  if (!/^[0-9a-f]*$/.test(clean) || clean.length % 2 !== 0) {
    throw new Error("invalid hex");
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    out[i / 2] = parseInt(clean.slice(i, i + 2), 16);
  }
  return out;
}
