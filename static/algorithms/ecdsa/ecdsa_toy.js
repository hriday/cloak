// Toy ECDSA on the curve y^2 = x^3 + x + 6 (mod 11), generator G = (2, 7),
// prime order n = 13. Stallings, *Cryptography and Network Security* 7e §10.4.
//
// Tiny enough that every value fits in a Number, but big enough that the
// full PS3 attack (recover the per-signature nonce k from two signatures
// that share it, then recover the private key d) is computable by hand.
//
// All arithmetic uses plain Number ops because p = 11 and n = 13 — no risk
// of overflow. Production ECDSA on P-256 / secp256k1 would need BigInt.

export const P = 11;     // field prime
export const A = 1;      // curve coefficient a
export const B = 6;      // curve coefficient b
export const G = { x: 2, y: 7 };
export const N = 13;     // group order

// Helper: bring a possibly-negative integer into [0, m).
function mod(a, m) {
  const r = a % m;
  return r < 0 ? r + m : r;
}

// Extended Euclidean algorithm — returns a^{-1} mod n, or throws if gcd != 1
// (which happens iff a ≡ 0 mod n).
export function modInverse(a, n) {
  const aa = mod(a, n);
  if (aa === 0) throw new Error(`no modular inverse for 0 mod ${n}`);
  let [old_r, r] = [aa, n];
  let [old_s, s] = [1, 0];
  while (r !== 0) {
    const q = Math.floor(old_r / r);
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  if (old_r !== 1) throw new Error(`${a} has no inverse mod ${n}`);
  return mod(old_s, n);
}

// Point addition on the short Weierstrass curve y^2 = x^3 + ax + b (mod p).
// Returns null for the point at infinity (P + (-P) = O, or doubling a point
// with y = 0). Handles P + P (doubling) and P + Q (distinct) separately
// because the slope formula differs.
export function addPoints(P1, Q) {
  if (P1 === null) return Q;
  if (Q === null) return P1;

  if (P1.x === Q.x) {
    if (mod(P1.y + Q.y, P) === 0) return null;   // P + (-P) = O
    // Doubling: slope = (3x^2 + a) / (2y)
    const num = mod(3 * P1.x * P1.x + A, P);
    const den = modInverse(2 * P1.y, P);
    const lam = mod(num * den, P);
    const x3 = mod(lam * lam - 2 * P1.x, P);
    const y3 = mod(lam * (P1.x - x3) - P1.y, P);
    return { x: x3, y: y3 };
  }

  // Distinct: slope = (y2 - y1) / (x2 - x1)
  const num = mod(Q.y - P1.y, P);
  const den = modInverse(Q.x - P1.x, P);
  const lam = mod(num * den, P);
  const x3 = mod(lam * lam - P1.x - Q.x, P);
  const y3 = mod(lam * (P1.x - x3) - P1.y, P);
  return { x: x3, y: y3 };
}

// Scalar multiplication via double-and-add. Returns null for k = 0
// (the point at infinity).
export function scalarMul(k, Pt) {
  if (k === 0 || Pt === null) return null;
  let kk = mod(k, N);          // scalars live mod n
  if (kk === 0) return null;
  let result = null;
  let addend = Pt;
  while (kk > 0) {
    if (kk & 1) result = addPoints(result, addend);
    addend = addPoints(addend, addend);
    kk >>= 1;
  }
  return result;
}

// Toy ECDSA sign with explicit nonce k (so we can recreate the PS3 reuse).
// Returns { r, s }. Mirrors real ECDSA: r = (k·G).x mod n; s = k^{-1}·(e + r·d) mod n.
// Caller is responsible for keeping k ∈ [1, n-1].
export function signToy(d, k, e) {
  const R = scalarMul(k, G);
  if (R === null) throw new Error("k·G is the point at infinity — pick a different k");
  const r = mod(R.x, N);
  if (r === 0) throw new Error("r = 0 — pick a different k");
  const kInv = modInverse(k, N);
  const s = mod(kInv * (mod(e, N) + mod(r * d, N)), N);
  if (s === 0) throw new Error("s = 0 — pick a different k");
  return { r, s };
}

// The PS3 attack: given two signatures (r, s1) and (r, s2) on messages with
// hashes e1 and e2 — same r because the same k was reused — recover k.
//   s1 - s2 ≡ k^{-1} · (e1 - e2)  (mod n)
//   k ≡ (e1 - e2) · (s1 - s2)^{-1} (mod n)
export function recoverKFromReusedNonce(s1, s2, e1, e2, n = N) {
  const num = mod(e1 - e2, n);
  const denInv = modInverse(mod(s1 - s2, n), n);
  return mod(num * denInv, n);
}

// Once k is known, recover the private scalar d from any single signature.
//   s = k^{-1} · (e + r·d)  ⇒  d = r^{-1} · (s·k - e)  (mod n)
export function recoverDFromK(k, r, s, e, n = N) {
  const rInv = modInverse(r, n);
  return mod(rInv * mod(s * k - e, n), n);
}
