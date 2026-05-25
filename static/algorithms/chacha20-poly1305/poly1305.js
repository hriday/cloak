// Pure-JS Poly1305 — the one-time MAC half of ChaCha20-Poly1305.
//
// Poly1305 evaluates a polynomial over GF(2^130 - 5):
//   tag = ((c_1 r^n + c_2 r^{n-1} + … + c_n r) mod (2^130 - 5) + s) mod 2^128
// where the c_i are 16-byte message chunks (with a trailing 0x01 byte to
// distinguish lengths) and (r, s) is the per-message one-time key.
//
// 130-bit modular arithmetic doesn't fit native 32/64-bit ints, so we use
// JS BigInt. Performance is fine for the lesson — we MAC <600 bytes per
// validator call.

// ---- the prime ----

// p = 2^130 - 5, the Poly1305 modulus.
const P = (1n << 130n) - 5n;

// Bitmask for 128 bits — used when truncating the final value before adding s.
const MASK_128 = (1n << 128n) - 1n;

// ---- the r clamp ----

// RFC 8439 §2.5.1: zero specific bits of r so the polynomial-evaluation
// math stays within the 130-bit field without overflow on intermediate
// reductions. The clamp pattern is fixed by the RFC.
function clampR(r16) {
  const r = new Uint8Array(r16); // copy — never mutate caller's bytes
  r[3]  &= 0x0f;
  r[7]  &= 0x0f;
  r[11] &= 0x0f;
  r[15] &= 0x0f;
  r[4]  &= 0xfc;
  r[8]  &= 0xfc;
  r[12] &= 0xfc;
  return r;
}

// ---- byte ↔ BigInt helpers ----

// Read `n` little-endian bytes from `bytes[off..off+n]` as a BigInt.
function leToBigInt(bytes, off, n) {
  let acc = 0n;
  for (let i = 0; i < n; i++) {
    acc |= BigInt(bytes[off + i]) << BigInt(i * 8);
  }
  return acc;
}

// Write a non-negative BigInt as 16 little-endian bytes.
function bigIntToLe16(value) {
  const out = new Uint8Array(16);
  let v = value & MASK_128;
  for (let i = 0; i < 16; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

// ---- the MAC ----

// Compute the 16-byte Poly1305 tag for `message` under one-time key `otk`
// (32 bytes: first 16 are r, last 16 are s). Algorithm per RFC 8439 §2.5.
export function poly1305Mac(otk, message) {
  if (otk.length !== 32) throw new Error("Poly1305 OTK must be 32 bytes");

  const r = leToBigInt(clampR(otk.subarray(0, 16)), 0, 16);
  const s = leToBigInt(otk, 16, 16);

  let acc = 0n;
  let off = 0;
  while (off < message.length) {
    const chunkLen = Math.min(16, message.length - off);
    // Read the chunk as a little-endian integer, then set the bit just
    // above the high byte — this is the "0x01" length-distinguisher
    // (bit 8·chunkLen). It's how Poly1305 disambiguates messages whose
    // padded forms would otherwise collide.
    const n = leToBigInt(message, off, chunkLen) | (1n << BigInt(chunkLen * 8));
    acc = ((acc + n) * r) % P;
    off += chunkLen;
  }

  // Final step: add s mod 2^128, then serialize.
  acc = (acc + s) & MASK_128;
  return bigIntToLe16(acc);
}
