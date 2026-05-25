// SHA-256 (FIPS 180-4) — pure JS, with intermediate state EXPOSED.
//
// Why this file exists. Web Crypto's `crypto.subtle.digest("SHA-256", ...)`
// is fine for honest hashing but useless for the length-extension lesson:
// it never lets the caller see, save, or re-inject the chaining state.
// Length extension is *exactly* the attack of resuming a hash from a
// partially-computed state, so we need an implementation that surrenders
// that state on demand.
//
// What this exports:
//   - class Sha256
//       new Sha256()                    // start from IV
//       .update(bytes: Uint8Array)      // absorb input (any length)
//       .finalize(): Uint8Array(32)     // pad, finish, return the digest
//       .clone(): Sha256                // snapshot mid-stream
//       Sha256.fromState(stateBytes32, totalBytesProcessed): Sha256
//                                       // resume from a known mid-stream
//                                       //   state. totalBytesProcessed
//                                       //   MUST be a multiple of 64 (the
//                                       //   block size) — i.e. the state
//                                       //   we're resuming from is one
//                                       //   that sat at a block boundary,
//                                       //   like the finalized output of
//                                       //   H(secret||msg) does after
//                                       //   internal padding pushed the
//                                       //   total to a block boundary.
//   - computeGluePadding(messageLength): Uint8Array
//       // The bytes SHA-256 would append to a message of the given total
//       // length to produce its internal padding: 0x80, then enough 0x00s
//       // to leave 8 bytes of room in the final block, then the
//       // big-endian 64-bit bit-length of the message.
//
// Invariant. After finalize(), the returned 32 bytes ARE the internal
// chaining state H0..H7 serialized big-endian. That equality is the
// entire reason Merkle-Damgard hashes are vulnerable to length extension:
// the public output IS the secret internal state.

// ---- constants ----

// IV — first 32 bits of fractional parts of square roots of primes 2..19
const _IV = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

// K — first 32 bits of fractional parts of cube roots of primes 2..311
const _K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

// ---- 32-bit helpers ----

// JS bit-ops are signed-32; ">>> 0" coerces to unsigned. SHA-256 wants
// all rotates / shifts to be 32-bit unsigned.
const _rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;

// ---- compression ----

// Process one 64-byte block. Mutates `H` (8 uint32 state words) in place.
function _compress(H, block) {
  const W = new Uint32Array(64);
  // First 16 words: read block as big-endian uint32s.
  for (let i = 0; i < 16; i++) {
    W[i] =
      ((block[i * 4] << 24) |
        (block[i * 4 + 1] << 16) |
        (block[i * 4 + 2] << 8) |
        block[i * 4 + 3]) >>>
      0;
  }
  // Remaining 48 words: message schedule.
  for (let i = 16; i < 64; i++) {
    const s0 = _rotr(W[i - 15], 7) ^ _rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3);
    const s1 = _rotr(W[i - 2], 17) ^ _rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10);
    W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
  }

  let a = H[0], b = H[1], c = H[2], d = H[3];
  let e = H[4], f = H[5], g = H[6], h = H[7];

  for (let i = 0; i < 64; i++) {
    const S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25);
    const ch = (e & f) ^ (~e & g);
    const t1 = (h + S1 + ch + _K[i] + W[i]) >>> 0;
    const S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22);
    const mj = (a & b) ^ (a & c) ^ (b & c);
    const t2 = (S0 + mj) >>> 0;
    h = g;
    g = f;
    f = e;
    e = (d + t1) >>> 0;
    d = c;
    c = b;
    b = a;
    a = (t1 + t2) >>> 0;
  }

  H[0] = (H[0] + a) >>> 0;
  H[1] = (H[1] + b) >>> 0;
  H[2] = (H[2] + c) >>> 0;
  H[3] = (H[3] + d) >>> 0;
  H[4] = (H[4] + e) >>> 0;
  H[5] = (H[5] + f) >>> 0;
  H[6] = (H[6] + g) >>> 0;
  H[7] = (H[7] + h) >>> 0;
}

// ---- public API ----

export class Sha256 {
  constructor() {
    // Internal chaining state. Initialised to SHA-256's IV.
    this._H = new Uint32Array(_IV);
    // Buffer for the trailing partial block (0..63 bytes).
    this._buf = new Uint8Array(64);
    this._bufLen = 0;
    // Total bytes ABSORBED into this hash so far — includes any
    // already-processed prefix (for fromState), plus everything passed to
    // update() since.
    this._totalBytes = 0;
    // Finalize() locks the instance — subsequent update() throws.
    this._finalized = false;
  }

  // Absorb bytes into the running hash.
  update(bytes) {
    if (this._finalized) {
      throw new Error("Sha256: update() after finalize()");
    }
    if (!(bytes instanceof Uint8Array)) {
      throw new Error("Sha256.update: expected Uint8Array");
    }
    let off = 0;
    const n = bytes.length;
    // Fill the partial buffer first if one is open.
    if (this._bufLen > 0) {
      const need = 64 - this._bufLen;
      const take = Math.min(need, n);
      this._buf.set(bytes.subarray(off, off + take), this._bufLen);
      this._bufLen += take;
      off += take;
      if (this._bufLen === 64) {
        _compress(this._H, this._buf);
        this._bufLen = 0;
      }
    }
    // Process whole blocks directly from input.
    while (n - off >= 64) {
      _compress(this._H, bytes.subarray(off, off + 64));
      off += 64;
    }
    // Stash any remainder.
    if (off < n) {
      this._buf.set(bytes.subarray(off, n), 0);
      this._bufLen = n - off;
    }
    this._totalBytes += n;
    return this;
  }

  // Finish — apply Merkle-Damgard padding, return the 32-byte digest.
  // After finalize() the digest IS the serialized H0..H7. That equality
  // is the foundation of the length-extension attack.
  finalize() {
    if (this._finalized) {
      throw new Error("Sha256: finalize() called twice");
    }
    this._finalized = true;

    // Padding: append 0x80, then enough 0x00s, then 64-bit big-endian
    // length-in-BITS such that the total length is a multiple of 64
    // bytes.
    const totalBits = this._totalBytes * 8;
    // First we must finish whatever partial block we have.
    this._buf[this._bufLen++] = 0x80;
    if (this._bufLen > 56) {
      // No room for the 8-byte length in this block; pad with zeros and
      // process, then start a fresh block.
      while (this._bufLen < 64) this._buf[this._bufLen++] = 0;
      _compress(this._H, this._buf);
      this._bufLen = 0;
    }
    while (this._bufLen < 56) this._buf[this._bufLen++] = 0;
    // Big-endian 64-bit bit length. JS numbers handle the top 32 bits
    // fine for sane message sizes (we'd lose precision above ~2^53 bits =
    // ~10^15 bytes; not a concern in this lesson).
    const hi = Math.floor(totalBits / 0x100000000) >>> 0;
    const lo = (totalBits >>> 0);
    this._buf[56] = (hi >>> 24) & 0xff;
    this._buf[57] = (hi >>> 16) & 0xff;
    this._buf[58] = (hi >>> 8) & 0xff;
    this._buf[59] = hi & 0xff;
    this._buf[60] = (lo >>> 24) & 0xff;
    this._buf[61] = (lo >>> 16) & 0xff;
    this._buf[62] = (lo >>> 8) & 0xff;
    this._buf[63] = lo & 0xff;
    _compress(this._H, this._buf);
    this._bufLen = 0;

    // Serialize H0..H7 big-endian.
    const out = new Uint8Array(32);
    for (let i = 0; i < 8; i++) {
      out[i * 4]     = (this._H[i] >>> 24) & 0xff;
      out[i * 4 + 1] = (this._H[i] >>> 16) & 0xff;
      out[i * 4 + 2] = (this._H[i] >>> 8) & 0xff;
      out[i * 4 + 3] = this._H[i] & 0xff;
    }
    return out;
  }

  // Snapshot. Useful for tests that branch on a partial hash.
  clone() {
    const c = new Sha256();
    c._H = new Uint32Array(this._H);
    c._buf = new Uint8Array(this._buf);
    c._bufLen = this._bufLen;
    c._totalBytes = this._totalBytes;
    c._finalized = this._finalized;
    return c;
  }

  // The whole point of this module. Resume a SHA-256 from a known
  // mid-stream state.
  //
  // stateBytes:           32 bytes — the serialized H0..H7 you want to
  //                       resume from. Typically this is `originalSig`
  //                       in the length-extension attack: the published
  //                       SHA-256 output IS the internal state at the
  //                       moment the original hasher finalized.
  // totalBytesProcessed:  How many bytes of input the resumed-from hash
  //                       had already absorbed at the point the state
  //                       was captured. MUST be a multiple of 64 (the
  //                       block size) — i.e. we're resuming from a
  //                       block boundary. In the length-extension attack
  //                       the boundary is reached because the original
  //                       hash had already done its own padding before
  //                       finalizing.
  static fromState(stateBytes, totalBytesProcessed) {
    if (!(stateBytes instanceof Uint8Array) || stateBytes.length !== 32) {
      throw new Error("Sha256.fromState: stateBytes must be Uint8Array(32)");
    }
    if (
      !Number.isInteger(totalBytesProcessed) ||
      totalBytesProcessed < 0 ||
      totalBytesProcessed % 64 !== 0
    ) {
      throw new Error(
        "Sha256.fromState: totalBytesProcessed must be a non-negative multiple of 64"
      );
    }
    const h = new Sha256();
    for (let i = 0; i < 8; i++) {
      h._H[i] =
        ((stateBytes[i * 4] << 24) |
          (stateBytes[i * 4 + 1] << 16) |
          (stateBytes[i * 4 + 2] << 8) |
          stateBytes[i * 4 + 3]) >>>
        0;
    }
    h._bufLen = 0;
    h._totalBytes = totalBytesProcessed;
    return h;
  }
}

// One-shot convenience: SHA-256(bytes) -> Uint8Array(32).
export function sha256(bytes) {
  return new Sha256().update(bytes).finalize();
}

// The "glue padding" that SHA-256 would have appended to a message of
// the given total length. This is the padding the attacker must include
// between the original message and the appended extension so that the
// hashing the server does (H(secret || original || gluePadding ||
// extension)) lines up at a block boundary with the captured signature
// — i.e. the attacker's resumed hash starts at the same block boundary
// the original hash finalized at.
//
// Returns a Uint8Array of length 64 - (messageLength % 64) if the
// remainder leaves room for the 8-byte length field in the same block,
// otherwise 128 - (messageLength % 64).
export function computeGluePadding(messageLength) {
  if (!Number.isInteger(messageLength) || messageLength < 0) {
    throw new Error("computeGluePadding: messageLength must be a non-negative integer");
  }
  const totalBits = messageLength * 8;
  // We append: one 0x80, then K zero bytes, then 8 bytes of length, where
  // K is chosen so that (messageLength + 1 + K + 8) is a multiple of 64.
  // Equivalently: K = (56 - 1 - messageLength) mod 64 = (55 - messageLength) mod 64.
  let zeros = (55 - (messageLength % 64));
  if (zeros < 0) zeros += 64;
  const out = new Uint8Array(1 + zeros + 8);
  out[0] = 0x80;
  // zeros bytes of 0x00 are already 0 (Uint8Array default).
  const hi = Math.floor(totalBits / 0x100000000) >>> 0;
  const lo = (totalBits >>> 0);
  const lenOff = 1 + zeros;
  out[lenOff]     = (hi >>> 24) & 0xff;
  out[lenOff + 1] = (hi >>> 16) & 0xff;
  out[lenOff + 2] = (hi >>> 8) & 0xff;
  out[lenOff + 3] = hi & 0xff;
  out[lenOff + 4] = (lo >>> 24) & 0xff;
  out[lenOff + 5] = (lo >>> 16) & 0xff;
  out[lenOff + 6] = (lo >>> 8) & 0xff;
  out[lenOff + 7] = lo & 0xff;
  return out;
}

// ---- byte/hex helpers (also used by sibling modules) ----

export function bytesToHex(arr) {
  return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(hex) {
  const clean = String(hex || "").replace(/\s+/g, "").toLowerCase();
  if (!/^[0-9a-f]*$/.test(clean) || clean.length % 2 !== 0) {
    throw new Error("invalid hex");
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    out[i / 2] = parseInt(clean.slice(i, i + 2), 16);
  }
  return out;
}
