// Toy memory-hard mixer for the yescrypt and argon2id lessons.
//
// IMPORTANT — this file does NOT implement yescrypt or argon2. Real yescrypt
// has no maintained JS port and a WASM argon2 build would add ~100 KB and
// block the main thread. What we CAN make real in a browser is the thing
// bcrypt's lesson couldn't: the MEMORY. This mixer genuinely allocates the
// chosen number of mebibytes and genuinely touches every byte — a sequential
// fill pass, then a data-dependent random-read pass (the two-loop shape of
// scrypt's ROMix, which is the ancestor of both yescrypt and argon2's
// block-mixing schedule). The mixing function itself is a toy (xorshift32),
// so the wall-time constant factor is wrong; the CITED_* tables carry honest
// numbers from real implementations (libxcrypt yescrypt and argon2-cffi with
// t=3, p=4 on a typical 2024 laptop, single run, rounded).
//
// Node >=19-compatible: no browser globals required.

export const ALLOWED_MEMORY_MIB = [1, 4, 16, 64];
export const BLOCK_WORDS = 256; // 256 × 4-byte words = 1 KiB per block

export const CITED_YESCRYPT_MS = { 1: 3, 4: 12, 16: 50, 64: 210 };
export const CITED_ARGON2ID_MS = { 1: 6, 4: 24, 16: 95, 64: 380 };

function nowMs() {
  if (typeof performance !== "undefined" && typeof performance.now === "function") {
    return performance.now();
  }
  return Date.now();
}

// FNV-1a over the password string → 32-bit seed. Deterministic so the
// digest is testable; NOT a KDF, and never presented as one.
function fnv1a(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

function xorshift32(x) {
  x ^= x << 13; x >>>= 0;
  x ^= x >>> 17;
  x ^= x << 5; x >>>= 0;
  return x >>> 0;
}

export function mixMemory(password, memoryMiB) {
  if (!ALLOWED_MEMORY_MIB.includes(memoryMiB)) {
    throw new Error(`memoryMiB must be one of ${ALLOWED_MEMORY_MIB.join(", ")}`);
  }
  const nBlocks = memoryMiB * 1024; // 1-KiB blocks
  let v;
  try {
    v = new Uint32Array(nBlocks * BLOCK_WORDS);
  } catch {
    return { allocationFailed: true };
  }

  const t0 = nowMs();

  // Pass 1 — sequential fill (ROMix loop 1 shape).
  let x = fnv1a(password) || 1;
  for (let i = 0; i < v.length; i++) {
    x = xorshift32(x);
    v[i] = x;
  }

  // Pass 2 — data-dependent random block reads (ROMix loop 2 shape). The
  // NEXT block index depends on data just read, which is exactly what makes
  // time-memory trade-offs expensive for attackers.
  let a = x, b = 0x9e3779b9, c = 0x85ebca6b, d = 0xc2b2ae35;
  for (let r = 0; r < nBlocks; r++) {
    const base = (a % nBlocks) * BLOCK_WORDS;
    for (let w = 0; w < BLOCK_WORDS; w += 4) {
      a = (a ^ v[base + w]) >>> 0;
      b = (b ^ v[base + w + 1]) >>> 0;
      c = (c ^ v[base + w + 2]) >>> 0;
      d = (d ^ v[base + w + 3]) >>> 0;
    }
    a = xorshift32(a);
  }

  const ms = nowMs() - t0;
  const digestHex = [a, b, c, d]
    .map((w) => (w >>> 0).toString(16).padStart(8, "0"))
    .join("");
  return {
    allocationFailed: false,
    ms,
    blocks: nBlocks,
    bytesTouched: (v.length + nBlocks * BLOCK_WORDS) * 4, // fill + read pass
    digestHex,
  };
}
