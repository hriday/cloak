// Hash + collision-blob support for the Hash Collisions lesson.
//
// Two demos live here:
//   - getMd5CollidingBlobs() / md5Hash()  — Wang/Stevens 2004 MD5 pair
//   - getSha1CollidingBlobs() / sha1Hash() — Stevens SHA-1 colliding messages
//
// MD5 is implemented from scratch (~150 lines) because Web Crypto does NOT
// expose MD5 — the W3C spec only mandates SHA-1 and SHA-2. The implementation
// follows RFC 1321 and is verified in tests against md5("abc") =
// "900150983cd24fb0d6963f7d28e17f72" plus the published Wang/Stevens hash
// "79054025255fb1a26e4bc422aef54eb4".
//
// SHA-1 IS exposed by Web Crypto (`crypto.subtle.digest("SHA-1", ...)`), so
// we use it directly. Node ≥19 ships crypto.subtle globally, so this file is
// unit-testable without a browser.

// ============================================================================
// MD5 (RFC 1321) — pure JS reference implementation.
// ============================================================================

// Per-round shift amounts. Four groups of four, repeated by round.
const MD5_S = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

// Per-round constants T[i] = floor(2^32 * abs(sin(i+1))). RFC 1321 §3.4.
const MD5_K = new Uint32Array([
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
]);

function rotl32(x, n) {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

// One 64-byte block update. Mutates `H` (Uint32Array of length 4) in place.
function md5Compress(H, block) {
  // Load block as 16 little-endian 32-bit words.
  const M = new Uint32Array(16);
  for (let i = 0; i < 16; i++) {
    M[i] =
      (block[4 * i]) |
      (block[4 * i + 1] << 8) |
      (block[4 * i + 2] << 16) |
      (block[4 * i + 3] << 24);
    M[i] = M[i] >>> 0;
  }

  let a = H[0], b = H[1], c = H[2], d = H[3];

  for (let i = 0; i < 64; i++) {
    let f, g;
    if (i < 16) {
      // Round 1: F(b,c,d) = (b AND c) OR ((NOT b) AND d)
      f = (b & c) | (~b & d);
      g = i;
    } else if (i < 32) {
      // Round 2: G(b,c,d) = (d AND b) OR ((NOT d) AND c)
      f = (d & b) | (~d & c);
      g = (5 * i + 1) % 16;
    } else if (i < 48) {
      // Round 3: H(b,c,d) = b XOR c XOR d
      f = b ^ c ^ d;
      g = (3 * i + 5) % 16;
    } else {
      // Round 4: I(b,c,d) = c XOR (b OR (NOT d))
      f = c ^ (b | ~d);
      g = (7 * i) % 16;
    }
    f = (f + a + MD5_K[i] + M[g]) >>> 0;
    a = d;
    d = c;
    c = b;
    b = (b + rotl32(f, MD5_S[i])) >>> 0;
  }

  H[0] = (H[0] + a) >>> 0;
  H[1] = (H[1] + b) >>> 0;
  H[2] = (H[2] + c) >>> 0;
  H[3] = (H[3] + d) >>> 0;
}

// MD5 of a Uint8Array. Returns lowercase hex.
function md5Bytes(input) {
  // Pad: 0x80, then zero bytes, so total length ≡ 56 (mod 64). Then append
  // 64-bit little-endian bit length.
  const origLen = input.length;
  const bitLen = BigInt(origLen) * 8n;
  // Pad-zero count: bring origLen+1 up to a length ≡ 56 (mod 64).
  const padZeros = (56 - (origLen + 1)) % 64;
  const padLen = origLen + 1 + (padZeros < 0 ? padZeros + 64 : padZeros) + 8;
  const padded = new Uint8Array(padLen);
  padded.set(input);
  padded[origLen] = 0x80;
  // 64-bit little-endian length (in bits), trailing 8 bytes.
  for (let i = 0; i < 8; i++) {
    padded[padLen - 8 + i] = Number((bitLen >> BigInt(8 * i)) & 0xffn);
  }

  // Initialize MD5 state (RFC 1321 §3.3). Stored little-endian.
  const H = new Uint32Array([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]);
  for (let off = 0; off < padded.length; off += 64) {
    md5Compress(H, padded.subarray(off, off + 64));
  }

  // Output: H[0]..H[3] as little-endian bytes, concatenated.
  const out = new Uint8Array(16);
  for (let i = 0; i < 4; i++) {
    out[4 * i]     = (H[i]) & 0xff;
    out[4 * i + 1] = (H[i] >>> 8) & 0xff;
    out[4 * i + 2] = (H[i] >>> 16) & 0xff;
    out[4 * i + 3] = (H[i] >>> 24) & 0xff;
  }
  return out;
}

// ============================================================================
// Public hash wrappers.
// ============================================================================

function bytesToHex(arr) {
  return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  const clean = hex.replace(/\s+/g, "");
  if (clean.length % 2 !== 0) throw new Error("hex length must be even");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(2 * i, 2), 16);
  }
  return out;
}

export async function md5Hash(data) {
  // Accepts a Uint8Array (bytes) or a string (UTF-8 encoded).
  const bytes = typeof data === "string"
    ? new TextEncoder().encode(data)
    : data;
  return bytesToHex(md5Bytes(bytes));
}

export async function sha1Hash(data) {
  const bytes = typeof data === "string"
    ? new TextEncoder().encode(data)
    : data;
  const buf = await crypto.subtle.digest("SHA-1", bytes);
  return bytesToHex(new Uint8Array(buf));
}

// ============================================================================
// Wang/Stevens MD5 colliding pair (2004, refined 2007).
//
// Two 128-byte messages that hash to the SAME MD5 digest:
//   md5(BLOB_1) == md5(BLOB_2) == "79054025255fb1a26e4bc422aef54eb4"
// but BLOB_1 != BLOB_2 (they differ in 6 byte positions: 19, 45, 59, 83,
// 109, 123).
//
// Source: Wang, X. & Yu, H. "How to Break MD5 and Other Hash Functions"
// (EUROCRYPT 2005), with the specific bytes from the canonical demo pair
// circulated by Marc Stevens and Vlastimil Klima. This is the example used
// in every "MD5 collision" demo since 2007.
// ============================================================================

const MD5_BLOB_1_HEX =
  "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f89" +
  "55ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b" +
  "d8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0" +
  "e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70";

const MD5_BLOB_2_HEX =
  "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f89" +
  "55ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b" +
  "d8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0" +
  "e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70";

// The shared MD5 hash of both blobs. Used by validators / tests to lock in
// the well-known value.
export const MD5_COLLISION_HASH = "79054025255fb1a26e4bc422aef54eb4";

export function getMd5CollidingBlobs() {
  return {
    blob1: hexToBytes(MD5_BLOB_1_HEX),
    blob2: hexToBytes(MD5_BLOB_2_HEX),
    expectedHash: MD5_COLLISION_HASH,
  };
}

// ============================================================================
// SHAttered SHA-1 colliding messages (Stevens, Bursztein, Karpman, Albertini,
// Markov 2017; Google + CWI Amsterdam).
//
// SHAttered's headline artifact was two distinct PDF files with the same
// SHA-1 digest. Both ~422 KB PDFs hash to:
//   38762cf7f55934b34d179ae6a4c80cadccbb7f0a
// despite rendering as visibly different images.
//
// We do NOT bake the colliding PDFs inline — they are 422,435 bytes each,
// and SHA-1 collisions are extremely byte-sensitive (a single flipped bit
// in a "near-collision block" breaks the collision). Shipping them as hex
// constants would balloon the bundle and risk transcription errors. Anyone
// who wants to verify can download from https://shattered.io and run
// shasum/openssl locally.
//
// Instead, the lesson:
//   1. Shows the published SHAttered hash as a fact.
//   2. Lets the user hash SMALL test data with sha1Hash() to confirm Web
//      Crypto SHA-1 is wired up correctly (e.g. sha1("abc") =
//      a9993e364706816aba3e25717850c26c9cd0d89d).
//   3. Points to shattered.io for the live collision files.
//
// This is the honest version. SHAttered was a real attack producing real
// colliding artifacts; the artifacts are too large to embed; the published
// hash IS the lesson.
// ============================================================================

// Published SHA-1 digest shared by shattered-1.pdf and shattered-2.pdf.
export const SHATTERED_PUBLISHED_HASH = "38762cf7f55934b34d179ae6a4c80cadccbb7f0a";

// Sizes of the two PDFs (bytes) as published by shattered.io. Identical:
// the differential is in 2 × 64-byte blocks ("near-collision blocks"), and
// the rest of the files share length.
export const SHATTERED_PDF_BYTES = 422435;

// Convenience accessor for the lesson UI.
export function getSha1CollidingFactSheet() {
  return {
    publishedHash: SHATTERED_PUBLISHED_HASH,
    pdfBytes: SHATTERED_PDF_BYTES,
    downloadUrl: "https://shattered.io",
    paperUrl:    "https://shattered.io/static/shattered.pdf",
    // What the user can verify in their own terminal:
    verifyCommand: "shasum -a 1 shattered-1.pdf shattered-2.pdf",
  };
}

// Count of differing bytes between two equal-length Uint8Arrays. Used by
// the lesson UI to show "these blobs differ in N bytes — and yet they hash
// the same."
export function byteDiffCount(a, b) {
  if (a.length !== b.length) {
    throw new Error("blobs must be the same length");
  }
  let count = 0;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) count++;
  }
  return count;
}
