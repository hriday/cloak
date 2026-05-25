// Web Crypto wrappers for the cipher-modes lesson.
//
// ECB has no native Web Crypto support (deliberately — it's an anti-pattern).
// We simulate it by encrypting each 16-byte block with AES-CBC and a zero IV.
// That is mathematically equivalent to ECB for one block: AES-CBC of one block
// with IV=0 is `E_K(0 ⊕ P) = E_K(P)`, which is ECB.
//
// CBC and the 3-block walk use real Web Crypto AES-CBC.

function bytesToHex(arr) {
  return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Procedurally draw a 32×32 two-tone silhouette: an oval body and a smaller
// circle head, plus two contrasting "feet" rectangles. Returned as 1024 bytes
// of grayscale (one byte per pixel). Deterministic — same output every call.
//
// The silhouette spans 64 AES blocks of 16 bytes each. Long horizontal runs
// of the same byte value encrypt to identical ciphertext blocks under ECB,
// so the outline survives "encryption". That's the whole pedagogical point.
export function drawSilhouette() {
  const W = 32;
  const H = 32;
  const FG = 0x20; // dark gray
  const BG = 0xE0; // light gray
  const buf = new Uint8Array(W * H).fill(BG);

  // Body: filled oval centered at (16, 20), rx=10, ry=8.
  const bodyCx = 16, bodyCy = 20, bodyRx = 10, bodyRy = 8;
  // Head: filled circle centered at (16, 8), r=5.
  const headCx = 16, headCy = 8, headR = 5;

  for (let y = 0; y < H; y++) {
    for (let x = 0; x < W; x++) {
      const dxB = (x - bodyCx) / bodyRx;
      const dyB = (y - bodyCy) / bodyRy;
      const inBody = dxB * dxB + dyB * dyB <= 1;

      const dxH = x - headCx;
      const dyH = y - headCy;
      const inHead = dxH * dxH + dyH * dyH <= headR * headR;

      if (inBody || inHead) buf[y * W + x] = FG;
    }
  }

  // Two feet rectangles, contrasting color to break the body outline.
  const FOOT = 0x60;
  for (let y = 28; y < 30; y++) {
    for (let x = 10; x < 14; x++) buf[y * W + x] = FOOT;
    for (let x = 18; x < 22; x++) buf[y * W + x] = FOOT;
  }
  return buf;
}

// Simulate ECB by encrypting each 16-byte block via AES-CBC with a zero IV.
// `plaintext` must be a multiple of 16 bytes. Returns Uint8Array of equal length.
export async function ecbEncrypt(plaintext, key) {
  if (plaintext.length % 16 !== 0) {
    throw new Error(`ecbEncrypt requires plaintext multiple of 16 bytes (got ${plaintext.length})`);
  }
  const ck = await crypto.subtle.importKey("raw", key, { name: "AES-CBC" }, false, ["encrypt"]);
  const zeroIv = new Uint8Array(16);
  const out = new Uint8Array(plaintext.length);
  for (let i = 0; i < plaintext.length; i += 16) {
    const block = plaintext.subarray(i, i + 16);
    // Web Crypto AES-CBC always pads with PKCS#7 (one extra block when input
    // is block-aligned). We discard that padding block and keep only the first
    // 16 bytes, which equals E_K(block) — exactly the ECB encryption of this
    // block.
    const ctBuf = await crypto.subtle.encrypt({ name: "AES-CBC", iv: zeroIv }, ck, block);
    out.set(new Uint8Array(ctBuf, 0, 16), i);
  }
  return out;
}

// 3-block CBC walk: chains each block via XOR with the previous ciphertext
// (or IV, for the first block). Returns the per-block hex ciphertexts plus
// the IV used for each XOR step (so the template can render the chain).
export async function cbcEncrypt(plaintext, iv, key) {
  if (plaintext.length !== 48) {
    throw new Error(`cbcEncrypt walk expects exactly 48 bytes (3 blocks); got ${plaintext.length}`);
  }
  const ck = await crypto.subtle.importKey("raw", key, { name: "AES-CBC" }, false, ["encrypt"]);
  const zeroIv = new Uint8Array(16);
  const blocks = [];
  let chain = iv;
  for (let i = 0; i < 3; i++) {
    const p = plaintext.subarray(i * 16, (i + 1) * 16);
    const xored = new Uint8Array(16);
    for (let j = 0; j < 16; j++) xored[j] = p[j] ^ chain[j];
    // Encrypt one block via AES-CBC with zero IV (pure E_K of the XOR result).
    const ctBuf = await crypto.subtle.encrypt({ name: "AES-CBC", iv: zeroIv }, ck, xored);
    const ct = new Uint8Array(ctBuf, 0, 16);
    blocks.push(bytesToHex(ct));
    chain = ct;
  }
  return { blocks, iv_hex: bytesToHex(iv) };
}

// Top-level helper: fresh random key + IV, "YELLOW SUBMARINE" × 3 plaintext.
// Returns everything the lesson needs to render and to write into state.
export async function runCbcWalk() {
  const plaintextStr = "YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE";
  const plaintext = new TextEncoder().encode(plaintextStr);
  const key = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const { blocks, iv_hex } = await cbcEncrypt(plaintext, iv, key);
  return {
    iv_hex,
    plaintext: plaintextStr,
    ct_blocks: blocks,
  };
}
