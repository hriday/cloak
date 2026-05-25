// Toy RSA parameters for the Bleichenbacher demo.
//
// Choice rationale:
//
//   * k = 8 bytes. PKCS#1 v1.5 with k = 8 supports messages up to 4 bytes
//     long (|M| = k - 3 - |PS| with |PS| ≥ 1). We pick the message "hi!!"
//     so the lesson can claim it's recovering a recognisable string. The
//     real Bleichenbacher attack against TLS recovers a 48-byte premaster
//     secret; this lesson scales the same algorithm down to 4 bytes so it
//     can finish in seconds in a browser.
//
//   * n in [2^56, 2^64). Concretely: n ≈ 2^60. p, q are 30-bit primes —
//     small enough that modPow runs in microseconds, large enough that
//     `P(random m is conforming) = 2B/n ≈ 2^49/2^60 ≈ 1/2048` makes the
//     algorithm's "find first conforming s" step take ~2K queries on
//     average. (Bigger n → exponentially more queries before the attack
//     finishes; smaller n → attack converges too fast to feel like the
//     real thing.)
//
//   * e = 17. Coprime to (p-1)(q-1) for our chosen primes. Small enough
//     to make modPow fast; not 3 (which is sometimes a special case in
//     toy RSA implementations).
//
//   * Plaintext "hi!!" (4 bytes). Encoded as a single k=8-byte PKCS#1 v1.5
//     block:
//
//         0x00 0x02 <PS byte> 0x00 'h' 'i' '!' '!'
//
//     The PS byte must be nonzero (so the 0x00 separator at position 3
//     unambiguously delimits PS from M). We use 0x42 — the "deterministic
//     random nonzero byte" — to keep the lesson reproducible.
//
//     (Real PKCS#1 v1.5 requires |PS| ≥ 8 bytes for security, but the
//     Bleichenbacher attack only depends on the (0x00 0x02) prefix check.
//     We elide the |PS| ≥ 8 requirement here so the modulus can stay
//     small enough to demo in a browser.)
//
// All BigInt — JS Number can't hold a 60-bit integer without loss of
// precision beyond ~2^53. The attack module needs full big-integer math
// throughout.

function _egcd(a, b) {
  if (b === 0n) return { g: a, x: 1n, y: 0n };
  const r = _egcd(b, a % b);
  return { g: r.g, x: r.y, y: r.x - (a / b) * r.y };
}
function _modInv(a, m) {
  const r = _egcd(((a % m) + m) % m, m);
  if (r.g !== 1n) throw new Error(`no modular inverse: gcd(${a}, ${m}) = ${r.g}`);
  return ((r.x % m) + m) % m;
}
function _modPow(base, exp, mod) {
  let r = 1n;
  base = ((base % mod) + mod) % mod;
  while (exp > 0n) {
    if (exp & 1n) r = (r * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return r;
}

// Two ~30-bit primes. Hand-verified to be prime and to yield
// gcd(17, (p-1)(q-1)) = 1. n = p · q lies in (2^59, 2^60) so the byte
// length k = 8.
const P = 1073741827n;  // = 2^30 + 3, prime
const Q = 1073741831n;  // = 2^30 + 7, prime
const N = P * Q;        // = 1152921512714829637, byte length 8
const PHI = (P - 1n) * (Q - 1n);
const E = 17n;
const D = _modInv(E, PHI);
const K = 8;

// PKCS#1 v1.5 encoding of "hi!!" under k = 8 bytes:
//   00 02 42 00 68 69 21 21
const PLAINTEXT_STRING = "hi!!";
const PADDED_BYTES = [0x00, 0x02, 0x42, 0x00, 0x68, 0x69, 0x21, 0x21];

let _m = 0n;
for (const b of PADDED_BYTES) _m = (_m << 8n) | BigInt(b);
const TARGET_M = _m;
const TARGET_CT = _modPow(TARGET_M, E, N);

export const _bleichConfig = {
  p: P,
  q: Q,
  n: N,
  e: E,
  d: D,
  k: K,
  plaintext: PLAINTEXT_STRING,
  paddedBytes: PADDED_BYTES,
  paddedInt: TARGET_M,
  targetCt: TARGET_CT,
};
