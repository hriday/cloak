// Toy 2-round XOR cipher standing in for 2DES. The real attack pattern (MITM)
// transfers directly to DES — only the key size differs.

export function toyEncrypt(plaintext, k1, k2) {
  return ((plaintext ^ k1) ^ k2) & 0xFF;
}

// Meet-in-the-middle search: find all (K1, K2) pairs that encrypt plaintext to ciphertext.
// Time complexity: O(2 * 2^N) where N is the key bit-width (8 here). For real DES (N=56),
// the same pattern would be O(2 * 2^56) — far less than the naive O(2^112) for 2DES.
export function mitmFind(plaintext, ciphertext) {
  // Forward lookup: E(K1, plaintext) -> K1, for every K1 in 0..255
  const fwd = new Map();
  for (let k1 = 0; k1 < 256; k1++) {
    fwd.set((plaintext ^ k1) & 0xFF, k1);
  }
  // Try every K2: compute D(K2, ciphertext) (= ciphertext^K2 for XOR cipher) and look it up
  const matches = [];
  for (let k2 = 0; k2 < 256; k2++) {
    const intermediate = (ciphertext ^ k2) & 0xFF;
    if (fwd.has(intermediate)) matches.push([fwd.get(intermediate), k2]);
  }
  return matches;
}
