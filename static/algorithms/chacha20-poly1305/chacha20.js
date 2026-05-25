// Pure-JS ChaCha20 implementation per RFC 8439.
// Built around three primitive ops on 32-bit unsigned words: Add (mod 2^32),
// Rotate, XOR — the ARX design. No S-boxes, no MixColumns. Constant-time
// on any sensible JS engine because there are no data-dependent branches
// or table lookups.

// ---- bit helpers ----

// Rotate-left for 32-bit words. JS bit ops are signed-32; ">>> 0" coerces
// to an unsigned 32-bit value so the result fits the expected range.
const rotl = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;

// ---- the quarter-round ----

// In-place update of 4 words of the 16-word state. Four ARX lines:
//   a += b; d ^= a; d <<<= 16
//   c += d; b ^= c; b <<<= 12
//   a += b; d ^= a; d <<<=  8
//   c += d; b ^= c; b <<<=  7
//
// Every "+" is mod 2^32 (enforced by ">>> 0"), every "<<<" is a 32-bit
// rotate. This is the only nonlinear* mixing step in ChaCha20.
// (*nonlinear in the sense that carries in "+" interact with the XORs.)
export function quarterRound(state, ai, bi, ci, di) {
  state[ai] = (state[ai] + state[bi]) >>> 0;
  state[di] ^= state[ai];
  state[di] = rotl(state[di], 16);

  state[ci] = (state[ci] + state[di]) >>> 0;
  state[bi] ^= state[ci];
  state[bi] = rotl(state[bi], 12);

  state[ai] = (state[ai] + state[bi]) >>> 0;
  state[di] ^= state[ai];
  state[di] = rotl(state[di], 8);

  state[ci] = (state[ci] + state[di]) >>> 0;
  state[bi] ^= state[ci];
  state[bi] = rotl(state[bi], 7);
}

// ---- the block function ----

// "expand 32-byte k" as 4 little-endian 32-bit words — the constants
// that anchor every ChaCha state.
const CONSTANTS = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

// Read 4 bytes from `bytes` at offset `off` as a little-endian uint32.
function leU32(bytes, off) {
  return (
    (bytes[off]) |
    (bytes[off + 1] << 8) |
    (bytes[off + 2] << 16) |
    (bytes[off + 3] << 24)
  ) >>> 0;
}

// Write `value` as 4 little-endian bytes into `out` starting at `off`.
function writeLeU32(out, off, value) {
  out[off]     = value & 0xff;
  out[off + 1] = (value >>> 8) & 0xff;
  out[off + 2] = (value >>> 16) & 0xff;
  out[off + 3] = (value >>> 24) & 0xff;
}

// Build the 4×4 (16-word) initial state per RFC 8439 §2.3:
//
//   c c c c   <- 4 constants
//   k k k k   <- 8 words of key
//   k k k k
//   b n n n   <- block counter, then 3 words of nonce
//
// where the layout is row-major into a length-16 Uint32Array.
function initialState(key, counter, nonce) {
  if (key.length !== 32) throw new Error("ChaCha20 key must be 32 bytes");
  if (nonce.length !== 12) throw new Error("ChaCha20 nonce must be 12 bytes");
  const state = new Uint32Array(16);
  state[0] = CONSTANTS[0];
  state[1] = CONSTANTS[1];
  state[2] = CONSTANTS[2];
  state[3] = CONSTANTS[3];
  for (let i = 0; i < 8; i++) {
    state[4 + i] = leU32(key, i * 4);
  }
  state[12] = counter >>> 0;
  state[13] = leU32(nonce, 0);
  state[14] = leU32(nonce, 4);
  state[15] = leU32(nonce, 8);
  return state;
}

// Produce one 64-byte keystream block.
//
// Algorithm: copy the initial state, run 20 rounds = 10 "double-rounds"
// (each = 4 column quarter-rounds + 4 diagonal quarter-rounds), then
// add the original state back word-by-word. The final add prevents
// trivial round-inversion: without it an attacker could undo the rounds.
export function chachaBlock(key, counter, nonce) {
  const state = initialState(key, counter, nonce);
  const working = new Uint32Array(state);

  for (let i = 0; i < 10; i++) {
    // Column rounds — 4 vertical quarter-rounds across the 4 columns.
    quarterRound(working, 0, 4,  8, 12);
    quarterRound(working, 1, 5,  9, 13);
    quarterRound(working, 2, 6, 10, 14);
    quarterRound(working, 3, 7, 11, 15);
    // Diagonal rounds — 4 quarter-rounds along the down-right diagonals,
    // which gives bytes from different columns a chance to mix.
    quarterRound(working, 0, 5, 10, 15);
    quarterRound(working, 1, 6, 11, 12);
    quarterRound(working, 2, 7,  8, 13);
    quarterRound(working, 3, 4,  9, 14);
  }

  // Word-wise add of original state — the "feed-forward" that makes
  // the block function non-invertible without the key.
  const out = new Uint8Array(64);
  for (let i = 0; i < 16; i++) {
    writeLeU32(out, i * 4, (working[i] + state[i]) >>> 0);
  }
  return out;
}

// ---- stream encryption ----

// Encrypt (and decrypt — XOR is involutive) `plaintext` with the
// ChaCha20 keystream starting at the given block counter. Per RFC 8439
// §2.4, AEAD encryption starts at counter=1 (counter=0 is reserved
// for deriving the Poly1305 one-time key).
export function chacha20Encrypt(key, nonce, plaintext, counter = 1) {
  const out = new Uint8Array(plaintext.length);
  let blockCounter = counter;
  for (let off = 0; off < plaintext.length; off += 64) {
    const ks = chachaBlock(key, blockCounter, nonce);
    const limit = Math.min(64, plaintext.length - off);
    for (let i = 0; i < limit; i++) {
      out[off + i] = plaintext[off + i] ^ ks[i];
    }
    blockCounter = (blockCounter + 1) >>> 0;
  }
  return out;
}
