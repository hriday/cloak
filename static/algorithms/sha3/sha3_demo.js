// SHA3-256 (FIPS 202) implementation for the SHA-3 lesson.
//
// Unlike the SHA-256 lesson, we can't lean on Web Crypto: as of 2026 most
// browsers still don't expose SHA3-256 through `crypto.subtle.digest` — the
// W3C Web Crypto spec only mandates SHA-1 and the SHA-2 family. So we ship a
// small Keccak-f[1600] implementation in pure JS.
//
// Step 5 (walk-empty) calls hashEmpty() on a button press.
// Step 6 (hash-a-sentence) calls hashHex(userMessage) on submit.
//
// The implementation is verified against the canonical FIPS 202 test vectors
// in tests/sha3_demo.test.js — SHA3-256("") = a7ffc6f8...8434a and
// SHA3-256("abc") = 3a985da7...31532.

// Round constants for the ι (iota) step. 24 rounds.
const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

// Rotation offsets for the ρ (rho) step, indexed by lane (x + 5*y).
// Standard FIPS 202 table.
const R = [
   0,  1, 62, 28, 27,
  36, 44,  6, 55, 20,
   3, 10, 43, 25, 39,
  41, 45, 15, 21,  8,
  18,  2, 61, 56, 14,
];

const MASK64 = (1n << 64n) - 1n;

function rotl64(x, n) {
  // 64-bit rotate left by n (0 <= n < 64).
  if (n === 0) return x;
  return ((x << BigInt(n)) | (x >> BigInt(64 - n))) & MASK64;
}

// One application of Keccak-f[1600]. Mutates `lanes` (a Array(25) of BigInt).
function keccakF(lanes) {
  for (let round = 0; round < 24; round++) {
    // θ (theta): mix column parities
    const C = new Array(5);
    for (let x = 0; x < 5; x++) {
      C[x] = lanes[x] ^ lanes[x + 5] ^ lanes[x + 10] ^ lanes[x + 15] ^ lanes[x + 20];
    }
    const D = new Array(5);
    for (let x = 0; x < 5; x++) {
      D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
    }
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        lanes[x + 5 * y] ^= D[x];
      }
    }

    // ρ (rho) + π (pi) combined: rotate each lane by its offset and move it
    // to its new position. Build a fresh `B` to avoid in-place clobbering.
    const B = new Array(25);
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        const src = x + 5 * y;
        const newX = y;
        const newY = (2 * x + 3 * y) % 5;
        B[newX + 5 * newY] = rotl64(lanes[src], R[src]);
      }
    }

    // χ (chi): nonlinear mixing across rows.
    for (let y = 0; y < 5; y++) {
      for (let x = 0; x < 5; x++) {
        lanes[x + 5 * y] = B[x + 5 * y] ^ ((~B[((x + 1) % 5) + 5 * y]) & B[((x + 2) % 5) + 5 * y] & MASK64);
      }
    }

    // ι (iota): XOR a round constant into lane (0,0).
    lanes[0] ^= RC[round];
  }
}

// Convert 8 little-endian bytes into a 64-bit BigInt lane.
function bytesToLane(bytes, offset) {
  let lane = 0n;
  for (let i = 7; i >= 0; i--) {
    lane = (lane << 8n) | BigInt(bytes[offset + i]);
  }
  return lane;
}

// Convert a 64-bit BigInt lane to 8 little-endian bytes, written into `out`
// starting at `offset`.
function laneToBytes(lane, out, offset) {
  for (let i = 0; i < 8; i++) {
    out[offset + i] = Number((lane >> BigInt(8 * i)) & 0xffn);
  }
}

// Core sponge for SHA3-256 (rate = 1088 bits = 136 bytes, capacity = 512 bits).
// Domain-separation suffix is 0x06 per FIPS 202 (SHA-3 family). The output is
// 32 bytes (256 bits) — squeezed in one pass because 32 < 136.
function sha3_256_bytes(input) {
  const RATE_BYTES = 136;
  const lanes = new Array(25).fill(0n);

  // Build the padded message: input || 0x06 || 0x00... || 0x80, length a multiple of 136.
  const padLen = RATE_BYTES - (input.length % RATE_BYTES);
  const padded = new Uint8Array(input.length + padLen);
  padded.set(input);
  padded[input.length] = 0x06;  // SHA-3 domain separator + first padding bit
  padded[padded.length - 1] |= 0x80;  // final padding bit

  // Absorb: XOR each rate-sized block into the state, then permute.
  for (let off = 0; off < padded.length; off += RATE_BYTES) {
    for (let i = 0; i < RATE_BYTES / 8; i++) {
      lanes[i] ^= bytesToLane(padded, off + 8 * i);
    }
    keccakF(lanes);
  }

  // Squeeze: read 32 bytes (4 lanes) from the rate part. No second permute
  // needed because 32 <= RATE_BYTES.
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    laneToBytes(lanes[i], out, 8 * i);
  }
  return out;
}

function bytesToHex(arr) {
  return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function hashHex(message) {
  // Always lowercase hex, always 64 chars. Matches the SHA-256 demo shape so
  // template branches and validators don't need to switch on algorithm.
  const bytes = new TextEncoder().encode(message);
  const digest = sha3_256_bytes(bytes);
  return bytesToHex(digest);
}

export async function hashEmpty() {
  return hashHex("");
}
