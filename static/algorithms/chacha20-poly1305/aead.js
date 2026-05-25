// ChaCha20-Poly1305 AEAD per RFC 8439 §2.8.
//
// AEAD = Authenticated Encryption with Associated Data. The construction:
//   1. Derive a one-time Poly1305 key from ChaCha20(key, counter=0, nonce).
//      Take the first 32 bytes; discard the rest. Counter=0 is reserved
//      for this — encryption starts at counter=1.
//   2. Encrypt the plaintext with ChaCha20 (counter=1) → ciphertext.
//   3. Compute Poly1305 tag over:
//        aad || pad16(aad) || ciphertext || pad16(ciphertext)
//          || len(aad) as LE u64 || len(ciphertext) as LE u64
//      That structure binds the length of each part so an attacker can't
//      shuffle bytes between the AAD and the ciphertext regions.

import { chachaBlock, chacha20Encrypt } from "./chacha20.js";
import { poly1305Mac } from "./poly1305.js";

// Thrown by aeadDecrypt when the tag doesn't verify. The name is the
// catch target in calling code — match `cryptography.exceptions.InvalidTag`
// so the lesson reads identically across JS and Python.
export class InvalidTag extends Error {
  constructor(message = "InvalidTag") {
    super(message);
    this.name = "InvalidTag";
  }
}

// ---- helpers ----

// Concatenate any number of Uint8Arrays into one.
function concatBytes(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// pad16(x) — append zero bytes so the total length of (x || pad) is a
// multiple of 16. If x is already a multiple of 16, pad is empty.
function pad16(bytes) {
  const rem = bytes.length % 16;
  return rem === 0 ? new Uint8Array(0) : new Uint8Array(16 - rem);
}

// Encode `value` as 8 little-endian bytes. RFC 8439 §2.8 specifies u64
// even though the underlying counts are usually much smaller — the fixed
// width is what makes the MAC input unambiguous.
function leU64(value) {
  const out = new Uint8Array(8);
  let n = BigInt(value);
  for (let i = 0; i < 8; i++) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

// Build the Poly1305 input per RFC 8439 §2.8.
function macInput(aad, ciphertext) {
  return concatBytes(
    aad, pad16(aad),
    ciphertext, pad16(ciphertext),
    leU64(aad.length), leU64(ciphertext.length),
  );
}

// Constant-time 16-byte compare. Avoids early-exit timing leaks that
// would let an attacker discover the tag a byte at a time.
function ctEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ---- public API ----

// Encrypt + authenticate. Returns the ciphertext and the 16-byte tag
// separately (Python's cryptography library bundles them; we keep them
// split so the lesson can display each).
export function aeadEncrypt(key, nonce, plaintext, aad) {
  if (key.length !== 32) throw new Error("AEAD key must be 32 bytes");
  if (nonce.length !== 12) throw new Error("AEAD nonce must be 12 bytes");
  const aadBytes = aad ?? new Uint8Array(0);

  // Step 1 — derive one-time Poly1305 key from ChaCha20 keystream block 0.
  const otk = chachaBlock(key, 0, nonce).subarray(0, 32);

  // Step 2 — encrypt with ChaCha20 starting at counter=1.
  const ciphertext = chacha20Encrypt(key, nonce, plaintext, 1);

  // Step 3 — Poly1305 over the structured MAC input.
  const tag = poly1305Mac(otk, macInput(aadBytes, ciphertext));

  return { ciphertext, tag };
}

// Verify tag then decrypt. Throws InvalidTag on failure — never returns
// a plaintext for a bad tag.
export function aeadDecrypt(key, nonce, ciphertext, tag, aad) {
  if (key.length !== 32) throw new Error("AEAD key must be 32 bytes");
  if (nonce.length !== 12) throw new Error("AEAD nonce must be 12 bytes");
  if (tag.length !== 16) throw new InvalidTag();
  const aadBytes = aad ?? new Uint8Array(0);

  const otk = chachaBlock(key, 0, nonce).subarray(0, 32);
  const expected = poly1305Mac(otk, macInput(aadBytes, ciphertext));

  if (!ctEqual(expected, tag)) {
    throw new InvalidTag();
  }
  // Tag verified — safe to decrypt. ChaCha20 is XOR-symmetric, so the
  // encrypt routine doubles as the decrypt routine.
  return chacha20Encrypt(key, nonce, ciphertext, 1);
}
