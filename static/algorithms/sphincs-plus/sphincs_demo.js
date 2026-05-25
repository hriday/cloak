// Toy SPHINCS+ — WOTS+ one-time signatures stacked under a Merkle tree.
//
// This is a *teaching* implementation. Real SPHINCS+ (NIST FIPS 205, August
// 2024 — formally SLH-DSA) is ~1000 lines of structured-PRF, hypertree, and
// FORS code with a parameter table whose smallest signature is ~7.8 KB.
// What you see here is the load-bearing skeleton:
//
//   1. WOTS+ one-time signatures (chains of SHA-256)
//   2. A single Merkle tree of 8 WOTS+ keys
//   3. Sign by picking a deterministic leaf from H(message); WOTS+ that leaf
//      to the message; ship (leaf_index, WOTS+ sig, Merkle authentication path).
//   4. Verify by reconstructing the WOTS+ public key from the signature,
//      hashing it into a leaf, climbing the Merkle path, and checking
//      against the root.
//
// The pedagogical claim is that the *shape* — one-time signatures lifted to
// many-time signatures by committing to many one-time public keys under a
// single Merkle root — is exactly what real SPHINCS+ does, just with more
// layers (a hypertree of Merkle trees) and an extra few-time signature
// scheme (FORS) at the bottom for the actual message. The security
// argument is the same in both: nothing but the hash function. No lattice,
// no number theory.
//
// Parameters (toy):
//   - Hash: SHA-256 (truncated to 16 bytes — n = 128 bits)
//   - Winternitz parameter w = 16 (so each message chunk is a nibble 0..15)
//   - len = 8 WOTS+ chains (we hash the message to 32 bits = 8 nibbles)
//   - Merkle tree height h = 3 (2^3 = 8 leaves = 8 WOTS+ keys)
//
// Real SLH-DSA-SHA2-128s uses n=16, w=16, len=35 (with checksum), and a
// 63-deep hypertree. Same primitives — just scaled.

// Use globalThis.crypto so the module works under both browsers and Node ≥19.
const subtle = (() => {
  if (typeof globalThis.crypto === "undefined" || !globalThis.crypto.subtle) {
    throw new Error("Web Crypto API (crypto.subtle) is not available");
  }
  return globalThis.crypto.subtle;
})();

// ---- byte / hex helpers ---------------------------------------------------

export function bytesToHex(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) {
    s += bytes[i].toString(16).padStart(2, "0");
  }
  return s;
}

export function hexToBytes(hex) {
  const clean = hex.replace(/\s+/g, "").toLowerCase();
  if (!/^[0-9a-f]*$/.test(clean) || clean.length % 2 !== 0) {
    throw new Error("invalid hex");
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    out[i / 2] = parseInt(clean.slice(i, i + 2), 16);
  }
  return out;
}

function concatBytes(...arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

// ---- hash primitives ------------------------------------------------------
//
// Real SPHINCS+ uses domain-separated hash chains (`F`, `H`, `T_l`, `PRF`)
// to defeat multi-target attacks. The toy uses plain SHA-256 truncated to
// 16 bytes for every primitive — that's enough to teach the structure
// without painting an FIPS-205 PRF tree on screen. The truncation models
// SPHINCS+'s n=16 (128-bit) security level.

export const N_BYTES = 16; // truncated SHA-256 output size

export async function sha256(bytes) {
  const digest = await subtle.digest("SHA-256", bytes);
  return new Uint8Array(digest).slice(0, N_BYTES);
}

// One step of the WOTS+ hash chain. Real SPHINCS+ folds in an address +
// public seed; the toy keeps it plain so the chain math is visible.
async function hashChainStep(value) {
  return sha256(value);
}

// Iterate the chain `count` times. count=0 returns input unchanged.
export async function chain(value, count) {
  let v = value;
  for (let i = 0; i < count; i++) {
    v = await hashChainStep(v);
  }
  return v;
}

// ---- message → chunks -----------------------------------------------------
//
// Hash the message with SHA-256, take the first 4 bytes (32 bits), split
// into 8 nibbles (0..15 each). Each nibble drives one WOTS+ chain.
//
// Note: real WOTS+ appends a checksum to defend against an attacker who
// changes a message chunk from 5 to 7 (revealing more chain elements
// "downstream" — fine on its own — combined with changing another chunk
// from 7 to 5 — would let them forge). The toy omits the checksum to keep
// the code under one screen; the test suite verifies a *random different
// message* fails, which is enough to demonstrate the chain-position binding.

export const NUM_CHUNKS = 8;
export const W = 16; // Winternitz parameter

export async function messageChunks(messageBytes) {
  const digest = await sha256(messageBytes);
  // First 4 bytes = 8 nibbles. nibble[i] = high nibble of byte (i/2) if even,
  // low nibble if odd.
  const out = new Array(NUM_CHUNKS);
  for (let i = 0; i < NUM_CHUNKS; i++) {
    const byte = digest[i >> 1];
    out[i] = (i & 1) === 0 ? (byte >> 4) & 0xf : byte & 0xf;
  }
  return out;
}

// ---- WOTS+ keygen / sign / verify -----------------------------------------
//
// One WOTS+ keypair signs one message. The secret key is `NUM_CHUNKS` random
// 16-byte values. The public key is each secret value hashed `w-1 = 15` times.
// To sign chunk c_i, reveal the value at position c_i along the i-th chain
// (i.e. apply `chain(sk[i], c_i)`). Verifying re-hashes `w-1 - c_i` more
// times and checks against the i-th public key element.
//
// `seed` is an optional 16-byte seed for deterministic keygen; if omitted,
// `crypto.getRandomValues` provides fresh randomness. Deterministic mode
// is what the Merkle-tree construction uses so the same composite public
// key is recoverable across page reloads in tests.

function getRandomBytes(n) {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

// Derive 8 secret chain-starts from a 16-byte seed using SHA-256(seed || i).
async function deriveSecretsFromSeed(seed) {
  const out = new Array(NUM_CHUNKS);
  for (let i = 0; i < NUM_CHUNKS; i++) {
    const idx = new Uint8Array([i]);
    out[i] = await sha256(concatBytes(seed, idx));
  }
  return out;
}

export async function wotsKeygen(seed) {
  const sk = seed
    ? await deriveSecretsFromSeed(seed)
    : (() => {
        const out = new Array(NUM_CHUNKS);
        for (let i = 0; i < NUM_CHUNKS; i++) out[i] = getRandomBytes(N_BYTES);
        return out;
      })();

  const pk = new Array(NUM_CHUNKS);
  for (let i = 0; i < NUM_CHUNKS; i++) {
    pk[i] = await chain(sk[i], W - 1);
  }
  return { sk, pk };
}

export async function wotsSign(messageBytes, sk) {
  const chunks = await messageChunks(messageBytes);
  const sig = new Array(NUM_CHUNKS);
  for (let i = 0; i < NUM_CHUNKS; i++) {
    sig[i] = await chain(sk[i], chunks[i]);
  }
  return { sig, chunks };
}

// Recompute the WOTS+ public-key elements from a signature. The verifier
// can do this without knowing the secret: it hashes the i-th signature
// element `W - 1 - c_i` more times and gets back the i-th pk element.
// Returns the recomputed pk vector (8 elements). The caller compares.
export async function wotsRecoverPk(messageBytes, sig) {
  const chunks = await messageChunks(messageBytes);
  const pk = new Array(NUM_CHUNKS);
  for (let i = 0; i < NUM_CHUNKS; i++) {
    pk[i] = await chain(sig[i], W - 1 - chunks[i]);
  }
  return pk;
}

export async function wotsVerify(messageBytes, sig, pk) {
  const recovered = await wotsRecoverPk(messageBytes, sig);
  return bytesEqualArray(recovered, pk);
}

function bytesEqualArray(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i].length !== b[i].length) return false;
    for (let j = 0; j < a[i].length; j++) {
      if (a[i][j] !== b[i][j]) return false;
    }
  }
  return true;
}

// Compress a WOTS+ public key (8 hashes) into one leaf hash. This is how
// the Merkle tree "sees" each WOTS+ key — one 16-byte commitment per leaf.
export async function wotsPkToLeaf(pk) {
  return sha256(concatBytes(...pk));
}

// ---- Merkle tree ----------------------------------------------------------
//
// Binary Merkle tree over `leaves` (each leaf is a 16-byte hash). Node
// height 0 = leaves; height h = root. At each internal node we hash the
// concatenation of its left and right children.
//
// Returns:
//   - root:   16-byte Uint8Array
//   - levels: levels[0] is the leaves; levels[k] is the k-th internal layer
//             going up; levels[h] === [root]. Stored so we can pull
//             authentication paths in O(log n).

export async function merkleTree(leaves) {
  if (leaves.length === 0 || (leaves.length & (leaves.length - 1)) !== 0) {
    throw new Error("merkleTree: leaves.length must be a power of 2 ≥ 1");
  }
  const levels = [leaves.slice()];
  let current = leaves;
  while (current.length > 1) {
    const next = new Array(current.length / 2);
    for (let i = 0; i < current.length; i += 2) {
      next[i / 2] = await sha256(concatBytes(current[i], current[i + 1]));
    }
    levels.push(next);
    current = next;
  }
  return { root: levels[levels.length - 1][0], levels };
}

// Authentication path for `leafIndex`: the sibling hashes along the path
// from the leaf up to (but not including) the root. Length = log2(n).
//
// Order: index 0 is the sibling at the leaf level; index h-1 is the
// sibling just below the root. Combined with the leaf and its index, the
// verifier can recompute the root.
export function merkleProof(tree, leafIndex) {
  const proof = [];
  let idx = leafIndex;
  for (let lvl = 0; lvl < tree.levels.length - 1; lvl++) {
    const sibling = idx ^ 1; // flip the low bit
    proof.push(tree.levels[lvl][sibling]);
    idx >>= 1;
  }
  return proof;
}

// Recompute the root from a leaf, its index, and an authentication path.
// Returns the candidate root; the caller compares to the known root.
export async function merkleVerify(leaf, proof, leafIndex) {
  let h = leaf;
  let idx = leafIndex;
  for (const sibling of proof) {
    if ((idx & 1) === 0) {
      // we're the left child, sibling is on the right
      h = await sha256(concatBytes(h, sibling));
    } else {
      // we're the right child, sibling is on the left
      h = await sha256(concatBytes(sibling, h));
    }
    idx >>= 1;
  }
  return h;
}

// ---- composite (toy SPHINCS-like) -----------------------------------------
//
// Keygen: derive 8 WOTS+ keypairs from a master seed. Compute each leaf =
// hash(pk) and build the Merkle tree. Public key is the root; secret key
// is the 8 WOTS+ secret-key vectors + the cached leaves so we can build
// proofs cheaply.
//
// Sign: hash the message to pick a leaf index (the bottom 3 bits of the
// SHA-256 of the message — h=3 → 2^3 = 8 leaves). Sign the message with
// that leaf's WOTS+ key. Bundle (leaf_index, WOTS+ sig, Merkle path).
//
// Verify: recompute the WOTS+ pk from the sig+message, compress to a leaf,
// climb the Merkle path with that leaf and the claimed index, and compare
// the resulting root to the known public root.
//
// Real SPHINCS+ picks the leaf via a *keyed* PRF over (sk_seed, message)
// so different keys land on different leaves for the same message, which
// prevents adaptive birthday-style attacks. The toy uses the public hash
// for clarity — the security argument shifts but the demonstration of
// "one-time signature, lifted by Merkle to many-time" is unchanged.

export const NUM_LEAVES = 8; // 2^3 — matches the lesson's height-3 Merkle tree
export const TREE_HEIGHT = 3;

export async function sphincsKeygen(masterSeed) {
  // Derive a per-leaf WOTS+ seed from the master seed: H(masterSeed || leaf_idx).
  // Each derived seed produces a WOTS+ keypair via deriveSecretsFromSeed.
  const wotsKeys = new Array(NUM_LEAVES);
  const leaves = new Array(NUM_LEAVES);
  for (let i = 0; i < NUM_LEAVES; i++) {
    const idx = new Uint8Array([i]);
    const leafSeed = await sha256(concatBytes(masterSeed, idx));
    const kp = await wotsKeygen(leafSeed);
    wotsKeys[i] = kp;
    leaves[i] = await wotsPkToLeaf(kp.pk);
  }
  const tree = await merkleTree(leaves);
  return {
    pk: { root: tree.root },
    sk: { masterSeed, wotsKeys, leaves, tree },
  };
}

// Pick a leaf index deterministically from the message. We use bits 0..2
// of SHA-256(message)[0] (= 3 bits → 0..7).
export async function leafIndexForMessage(messageBytes) {
  const h = await sha256(messageBytes);
  return h[0] & 0x7;
}

export async function sphincsSign(messageBytes, sk) {
  const leafIndex = await leafIndexForMessage(messageBytes);
  const { sig: wotsSig } = await wotsSign(messageBytes, sk.wotsKeys[leafIndex].sk);
  const authPath = merkleProof(sk.tree, leafIndex);
  return { leafIndex, wotsSig, authPath };
}

export async function sphincsVerify(messageBytes, signature, pk) {
  const { leafIndex, wotsSig, authPath } = signature;
  // Re-derive the leaf index from the message; if it disagrees with the
  // one in the signature, an attacker has tampered the message → reject.
  const expectedIndex = await leafIndexForMessage(messageBytes);
  if (expectedIndex !== leafIndex) return false;
  if (authPath.length !== TREE_HEIGHT) return false;
  // Recover the WOTS+ pk, compress to a leaf, climb the Merkle path.
  const recoveredPk = await wotsRecoverPk(messageBytes, wotsSig);
  const recoveredLeaf = await wotsPkToLeaf(recoveredPk);
  const recoveredRoot = await merkleVerify(recoveredLeaf, authPath, leafIndex);
  // Compare to the known root.
  if (recoveredRoot.length !== pk.root.length) return false;
  for (let i = 0; i < recoveredRoot.length; i++) {
    if (recoveredRoot[i] !== pk.root[i]) return false;
  }
  return true;
}

// ---- lesson-frozen master seed --------------------------------------------
//
// The interactive step regenerates a keypair on mount. We pin one seed
// string so the same root shows up on every visit and across the test
// suite — drift in the derive function or the SHA truncation surfaces
// immediately.

export const LESSON_SEED_STRING = "cloak-sphincs-v1";

export async function lessonSeedBytes() {
  return sha256(new TextEncoder().encode(LESSON_SEED_STRING));
}
