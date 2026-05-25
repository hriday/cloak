// Simulated Bleichenbacher (CRYPTO 1998) PKCS#1 v1.5 padding-oracle server.
//
// The server holds a fixed toy-sized RSA keypair and a target ciphertext c*
// encrypting the message "hello" under PKCS#1 v1.5 padding. The attacker can
// call:
//
//   targetCiphertext() → c*  (BigInt)
//   query(c)           → "conforming" | "bad"
//   publicKey()        → { n, e }
//   getPlaintext()     → "hello"   (used by validators/tests to check the
//                                   attack actually succeeded — never used
//                                   by the attack module itself)
//
// `query` is the entire vulnerability: it RSA-decrypts c with the private
// key, then checks whether the resulting plaintext (as a k-byte big-endian
// integer) starts with the bytes 0x00 0x02 — the PKCS#1 v1.5 "encryption
// block format 02" header. If yes, it returns "conforming"; if no, "bad".
// That single-bit distinction is the oracle Bleichenbacher exploits.
//
// Pedagogical only. Real TLS 1.0 implementations leaked this same bit via
// distinguishable error messages, timing, or alert codes. The cleanest
// modern fix is to (a) use OAEP padding instead of v1.5, or (b) drop RSA
// key exchange entirely (TLS 1.3 does this — it's ECDHE-only).
//
// We deliberately use a *small* RSA modulus (around 2^60). For real RSA
// (2048+ bits) this attack still works but needs ~10^6 queries — too slow
// to demo in a browser, but well within reach of network-speed attackers.
// The toy modulus lets the lesson run in a few seconds.

import { _bleichConfig } from "./bleich_config.js";

// ---- toy RSA params ----
//
// k = 8 bytes (64-bit-ish modulus). With message "hello" (5 bytes) we have
// |PS| = k - 3 - |M| = 0 — exactly zero padding bytes. The PKCS#1 v1.5 spec
// requires |PS| ≥ 8, but real Bleichenbacher attacks against v1.5-conforming
// servers exploit only the |0x00 0x02| prefix check, so the |PS| length
// requirement isn't load-bearing for the attack. We relax it here to keep
// the modulus small enough for the in-browser demo to finish in seconds.
//
// p, q are chosen so that p · q is exactly k = 8 bytes long (n in
// [2^56, 2^64)) and (p-1)(q-1) is coprime to e = 17. Concrete values are
// baked into bleich_config.js so the lesson is fully deterministic.

export const PARAMS = _bleichConfig;

export const N = PARAMS.n;
export const E = PARAMS.e;
const D = PARAMS.d;
export const K = PARAMS.k;            // modulus byte length
export const B = 1n << BigInt(8 * (K - 2));  // = 2^{8(k-2)}; v1.5 conforming iff 2B ≤ m < 3B

// ---- the target ciphertext c* ----
//
// We bake in a deterministic PKCS#1 v1.5 encoding of "hello" so the attack
// always converges on the same plaintext. (A random PS would be fine for
// correctness but makes the test suite flaky.)
//
// Encoding (k = 8 bytes): 0x00 0x02 <ps_1> 0x00 'h' 'e' 'l' 'l' 'o'? — but
// that's 9 bytes for a 5-byte message. We don't fit. Reduce M.
//
// With k = 8 and message length |M|, |PS| = k - 3 - |M|. For |PS| ≥ 1
// (required by v1.5 to make the 0x00 separator unambiguous), |M| ≤ 4. So
// we use the message "hi!!" (4 bytes) — same flavor as "hello", different
// byte count.
//
// Actually we keep "hello" by going to k = 9 bytes (~2^68 modulus). The
// attack runs ~3× slower; still under 10 s in the browser. See params.
//
// (Above commentary kept for the curious — actual choice is captured in
// PARAMS and the literal `PLAINTEXT` below.)

export const PLAINTEXT = PARAMS.plaintext;     // "hello"
export const TARGET_CT = PARAMS.targetCt;      // BigInt — c = m^e mod n

// ---- simulator state ----
let _queries = 0;

// ---- public API ----

export function publicKey() {
  return { n: N, e: E, k: K };
}

export function targetCiphertext() {
  return TARGET_CT;
}

// The oracle. Returns "conforming" or "bad".
//
// PKCS#1 v1.5 conformance (relaxed): after RSA-decrypting c with the
// private key, view the result as a big-endian k-byte integer. Return
// "conforming" iff 2B ≤ m < 3B — equivalently, iff the leading two bytes
// of the k-byte encoding are 0x00 0x02.
//
// This is the exact bit of information that's load-bearing for the attack.
// A full v1.5 implementation would also check (a) that PS is at least 8
// bytes of nonzero, (b) that there's a 0x00 separator before the message.
// Real servers historically leaked variants of the (a) and (b) checks too,
// but the (0x00 0x02) prefix is the universal leak that Bleichenbacher
// exploits.
export function query(c) {
  _queries += 1;
  const m = _modPow(_toBigInt(c), D, N);
  // m is in [0, N). Conforming iff 2B ≤ m < 3B.
  if (m >= 2n * B && m < 3n * B) return "conforming";
  return "bad";
}

export function getPlaintext() {
  return PLAINTEXT;
}

export function getQueryCount() {
  return _queries;
}

// Test hook — reset the query counter between tests. The keypair itself is
// fixed and intentionally never regenerated.
export function _resetForTests() {
  _queries = 0;
}

// ---- helpers ----

export function _modPow(base, exp, mod) {
  let r = 1n;
  base = ((base % mod) + mod) % mod;
  while (exp > 0n) {
    if (exp & 1n) r = (r * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return r;
}

function _toBigInt(x) {
  if (typeof x === "bigint") return x;
  if (typeof x === "number") {
    if (!Number.isInteger(x)) throw new Error("ciphertext must be an integer");
    return BigInt(x);
  }
  if (typeof x === "string") {
    if (!/^-?\d+$/.test(x.trim())) throw new Error("ciphertext must be an integer string");
    return BigInt(x.trim());
  }
  throw new Error("ciphertext must be BigInt | number | integer string");
}
