// Birthday-attack demo — brute-force collision search on a truncated
// SHA-256.
//
// Pedagogy. The lesson teaches the generic sqrt(N) attack on N-output
// hash functions. To make it tangible in a browser, we truncate
// SHA-256 to a small number of bits (16, by default) and brute-force
// a collision. With 16-bit output we expect a collision in
// ~sqrt(2^16) = 256 attempts; the cap of 1M attempts is a safety net
// for an unlucky run.
//
// We deliberately do NOT use any clever cycle-finding tricks (no
// Floyd, no Pollard's rho). The point is to show that the BIRTHDAY
// bound, sqrt(N), is the relevant work figure — and pure random
// trials already exhibit it. The reader sees the attempt count, sees
// it land near sqrt(N), and reads the math step that explained why.
//
// `findCollision(hashBits, progressCallback)`:
//   - hashBits: number of bits to truncate SHA-256 to. Tested at 8 and
//     16 in the unit tests; 16 is the default used by the lesson UI.
//   - progressCallback: optional, invoked every ~100 attempts with
//     `{attempts}`. Use this to drive a live counter in the page UI.
//   - returns {inputA, inputB, hash, attempts} where inputA != inputB
//     and truncatedHash(inputA) == truncatedHash(inputB) == hash.
//   - throws if no collision is found within 1_000_000 attempts (a
//     pathological run for hashBits <= 24; effectively never hits for
//     hashBits <= 16).
//
// `expectedAttempts(hashBits)`:
//   - returns 1.18 * sqrt(2 ** hashBits). The 1.18 factor comes from
//     setting the no-collision probability to 0.5 and solving for k.

const MAX_ATTEMPTS = 1_000_000;

// Convert a Uint8Array to a lowercase hex string. Inlined here so the
// module is self-contained — sha_demo.js has a copy, but importing
// across algorithms would couple unrelated lessons together.
function bytesToHex(arr) {
  let out = "";
  for (let i = 0; i < arr.length; i++) {
    out += arr[i].toString(16).padStart(2, "0");
  }
  return out;
}

// Generate a random 8-char base36 string. We just want unique inputs
// — the actual character set doesn't matter, only that we don't
// repeat ourselves (and Math.random over 8 chars gives ~10^12
// distinct strings, plenty for any reasonable hashBits).
function randomInput() {
  // Two random doubles concatenated; the trailing slice keeps it 8
  // chars even when the random value is short.
  return (Math.random().toString(36).slice(2, 6) +
          Math.random().toString(36).slice(2, 6)).padEnd(8, "0").slice(0, 8);
}

// Truncate SHA-256(message) to the first `hashBits` bits and return
// that as a lowercase hex string. We always truncate at a byte
// boundary in the unit tests (8, 16), but the function handles any
// bit count up to 256 by zero-masking the trailing bits of the last
// byte we keep.
async function truncatedHashHex(message, hashBits) {
  const bytes = new TextEncoder().encode(message);
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  const full = new Uint8Array(buf);
  const fullBytes = Math.ceil(hashBits / 8);
  const out = full.slice(0, fullBytes);
  // Mask trailing bits in the last byte if hashBits isn't a multiple
  // of 8. (e.g. 12 bits -> keep top 4 bits of byte index 1.)
  const rem = hashBits % 8;
  if (rem !== 0) {
    const mask = (0xff << (8 - rem)) & 0xff;
    out[out.length - 1] = out[out.length - 1] & mask;
  }
  return bytesToHex(out);
}

export async function findCollision(hashBits, progressCallback) {
  if (!Number.isInteger(hashBits) || hashBits < 1 || hashBits > 32) {
    throw new RangeError("hashBits must be an integer in [1, 32]");
  }
  const seen = new Map();
  let attempts = 0;
  while (attempts < MAX_ATTEMPTS) {
    const input = randomInput();
    attempts += 1;
    const hash = await truncatedHashHex(input, hashBits);
    const prior = seen.get(hash);
    if (prior !== undefined && prior !== input) {
      // Collision! Two distinct inputs hash to the same truncated
      // value. (We guard against the same input being picked twice
      // — randomInput collisions on 36^8 are negligible but possible.)
      return { inputA: prior, inputB: input, hash, attempts };
    }
    if (prior === undefined) {
      seen.set(hash, input);
    }
    if (progressCallback && attempts % 100 === 0) {
      progressCallback({ attempts });
    }
  }
  throw new Error(
    `No collision found after ${MAX_ATTEMPTS} attempts. ` +
    `Either hashBits is too large for brute force, or you got staggeringly unlucky.`
  );
}

export function expectedAttempts(hashBits) {
  return 1.18 * Math.sqrt(2 ** hashBits);
}

// Exported for tests so we can verify the truncation logic
// independently of the search loop.
export { truncatedHashHex };
