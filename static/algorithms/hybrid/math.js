// Re-export RSA's number-theory helpers so hybrid lesson code can pull
// everything from one place without reaching across algorithm directories.
export { modPow, modInv, gcd, isPrime, phi } from "../rsa/math.js";

// Byte-wise XOR of an ASCII string with a single-byte key.
// Self-inverse: xorBytes(xorBytes(s, k).map(String.fromCharCode).join(""), k)
// recovers the original byte sequence.
export function xorBytes(text, key) {
  const k = Number(key);
  const out = [];
  for (let i = 0; i < text.length; i++) {
    out.push(text.charCodeAt(i) ^ k);
  }
  return out;
}
