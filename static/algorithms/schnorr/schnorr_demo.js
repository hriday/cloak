// Schnorr signatures on a toy discrete-log group.
//
// Group parameters:
//   p = 467   (prime)
//   q = 233   (prime; q | (p-1), in fact (p-1)/q = 2 — Sophie-Germain style)
//   g = 4     (generator of the order-q subgroup of (Z/pZ)*)
//
// We pick g = 4 because 4 = 2² is a quadratic residue mod 467, hence lives in
// the unique order-(p-1)/2 = order-233 subgroup. Concretely g^q ≡ 1 (mod p),
// and g has order exactly q since q is prime and g ≠ 1.
//
// The math is exactly the same as Schnorr-on-an-elliptic-curve (BIP-340):
//   private x ∈ [1, q-1]
//   public  X = g^x mod p
//   sign(m): pick k; R = g^k mod p; e = H(R ‖ X ‖ m) mod q; s = (k + e·x) mod q
//   verify : check g^s ≡ R · X^e (mod p)
//
// Real BIP-340 Schnorr lives on secp256k1 with X a curve point — but the
// arithmetic is structurally identical. This toy group keeps every value
// fitting in three decimal digits so the verification equation can be
// checked by hand.
//
// Everything is BigInt so the modexp doesn't overflow.

export const P = 467n;
export const G = 4n;
export const Q = 233n;

// Bring n into [0, m).
function mod(n, m) {
  const r = n % m;
  return r < 0n ? r + m : r;
}

// Modular exponentiation. Square-and-multiply.
export function modPow(base, exp, modulus) {
  if (modulus === 1n) return 0n;
  let result = 1n;
  let b = mod(base, modulus);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % modulus;
    e >>= 1n;
    b = (b * b) % modulus;
  }
  return result;
}

// Extended Euclidean — returns a⁻¹ mod m, or throws if gcd(a, m) ≠ 1.
// Not strictly needed for sign/verify (the response equation is just a
// linear combination, no inverses) — exported for tests and for any
// derivative construction that needs it.
export function modInv(a, m) {
  const aa = mod(a, m);
  if (aa === 0n) throw new Error(`no modular inverse for 0 mod ${m}`);
  let [old_r, r] = [aa, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  if (old_r !== 1n) throw new Error(`${a} has no inverse mod ${m}`);
  return mod(old_s, m);
}

// Pick a uniformly-random scalar in [1, Q-1]. Web-Crypto-backed if available,
// Math.random fallback for the unit-test environment.
function randomScalar() {
  let n;
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    // 32 bytes is plenty; reduce mod (Q-1) then add 1.
    const buf = new Uint8Array(32);
    crypto.getRandomValues(buf);
    n = 0n;
    for (const byte of buf) n = (n << 8n) | BigInt(byte);
  } else {
    n = BigInt(Math.floor(Math.random() * 1e15));
  }
  return mod(n, Q - 1n) + 1n;
}

// Generate a Schnorr keypair. Accepts an optional `seed` scalar — if given,
// `x = (seed mod (Q-1)) + 1` so the keypair is deterministic. Useful for
// tests, fixed-demo modes, and the page's "regenerate" flow if we ever
// want it.
export function generateKeypair(seed) {
  let x;
  if (seed !== undefined && seed !== null) {
    const s = typeof seed === "bigint" ? seed : BigInt(seed);
    x = mod(s, Q - 1n) + 1n;
  } else {
    x = randomScalar();
  }
  const X = modPow(G, x, P);
  return { x, X };
}

// SHA-256(R ‖ X ‖ message) mod q, returning a BigInt in [0, q).
//
// Encoding: R and X are serialized as 2-byte big-endian (they fit in [0, p)
// with p = 467 ⇒ 9 bits), message as UTF-8. Length-prefixing isn't strictly
// necessary at this size, but we use a fixed 2-byte width for R and X so the
// hash domain is unambiguous.
export async function hashChallenge(R, X, message) {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    throw new Error("Web Crypto SHA-256 not available");
  }
  const enc = new TextEncoder();
  const msgBytes = enc.encode(message);
  const buf = new Uint8Array(2 + 2 + msgBytes.length);
  // R as 2-byte big-endian
  buf[0] = Number((R >> 8n) & 0xffn);
  buf[1] = Number(R & 0xffn);
  // X as 2-byte big-endian
  buf[2] = Number((X >> 8n) & 0xffn);
  buf[3] = Number(X & 0xffn);
  buf.set(msgBytes, 4);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
  let n = 0n;
  for (const byte of digest) n = (n << 8n) | BigInt(byte);
  return mod(n, Q);
}

// Schnorr sign. Pass an explicit `nonceK` to make signing deterministic
// (tests need this; production code would derive k = H(x ‖ m) à la RFC 6979,
// but the brief asks us to mirror the textbook presentation: pick a random
// nonce per signature).
//
// Returns { R, s, e, k } — R and s are the signature proper; e and k are
// exposed so the lesson template can render the intermediate values.
export async function sign(x, message, nonceK) {
  const xx = typeof x === "bigint" ? x : BigInt(x);
  const k = nonceK !== undefined && nonceK !== null
    ? (typeof nonceK === "bigint" ? mod(nonceK, Q) : mod(BigInt(nonceK), Q))
    : randomScalar();
  if (k === 0n) throw new Error("nonce k = 0; pick another");

  const X = modPow(G, xx, P);
  const R = modPow(G, k, P);
  const e = await hashChallenge(R, X, message);
  const s = mod(k + e * xx, Q);
  return { R, s, e, k };
}

// Schnorr verify. Recomputes the challenge e from (R, X, message), then
// returns the verdict and both sides of the verification equation so the
// template can render them.
export async function verify(X, message, signature) {
  const XX = typeof X === "bigint" ? X : BigInt(X);
  const R = typeof signature.R === "bigint" ? signature.R : BigInt(signature.R);
  const s = typeof signature.s === "bigint" ? signature.s : BigInt(signature.s);

  // Reject obviously out-of-range components — a real implementation would
  // also reject R = 0 and s ∉ [0, q).
  if (R <= 0n || R >= P) return { valid: false, lhs: 0n, rhs: 0n, e: 0n };
  if (s < 0n || s >= Q) return { valid: false, lhs: 0n, rhs: 0n, e: 0n };

  const e = await hashChallenge(R, XX, message);
  const lhs = modPow(G, s, P);                            // g^s mod p
  const rhs = mod(R * modPow(XX, e, P), P);               // R · X^e mod p
  return { valid: lhs === rhs, lhs, rhs, e };
}
