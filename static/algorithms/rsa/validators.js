import { isPrime, gcd, modInv, modPow, phi as phiFn } from "./math.js";

function _parseInt(s) {
  if (s === null || s === undefined) return null;
  const t = String(s).trim();
  if (!/^-?\d+$/.test(t)) return null;
  return BigInt(t);
}

function _ok(value) {
  // Convert BigInts in value to Number for JSON-safe storage in localStorage / DB.
  const out = {};
  for (const [k, val] of Object.entries(value)) {
    out[k] = typeof val === "bigint" ? Number(val) : val;
  }
  return { ok: true, value: out };
}

export function pick_pq(input, _state) {
  const p = _parseInt(input?.p);
  const q = _parseInt(input?.q);
  if (p === null || q === null) return { ok: false, hint: "Enter whole numbers for both p and q." };
  if (p === q) return { ok: false, hint: "p and q must be different primes." };
  if (!(2n <= p && p <= 999n && 2n <= q && q <= 999n)) {
    return { ok: false, hint: "p and q must be at most 3 digits (between 2 and 999)." };
  }
  if (!isPrime(p)) return { ok: false, hint: `${p} is not prime.` };
  if (!isPrime(q)) return { ok: false, hint: `${q} is not prime.` };
  return _ok({ p, q });
}

export function compute_n(input, state) {
  const got = _parseInt(input);
  if (got === null) return { ok: false, hint: "Enter a whole number." };
  const expected = BigInt(state.p) * BigInt(state.q);
  if (got !== expected) return { ok: false, hint: `n = p · q. With p=${state.p}, q=${state.q}.` };
  return _ok({ n: got });
}

export function compute_phi(input, state) {
  const got = _parseInt(input);
  if (got === null) return { ok: false, hint: "Enter a whole number." };
  const expected = phiFn(BigInt(state.p), BigInt(state.q));
  if (got !== expected) return { ok: false, hint: `φ(n) = (p-1)(q-1). With p=${state.p}, q=${state.q}.` };
  return _ok({ phi: got });
}

export function pick_e(input, state) {
  const got = _parseInt(input);
  if (got === null) return { ok: false, hint: "Enter a whole number." };
  if (!(1n < got && got < BigInt(state.phi))) {
    return { ok: false, hint: `e must satisfy 1 < e < φ(n) = ${state.phi}.` };
  }
  if (gcd(got, BigInt(state.phi)) !== 1n) {
    return { ok: false, hint: `e must be coprime to φ(n). gcd(${got}, ${state.phi}) ≠ 1.` };
  }
  return _ok({ e: got });
}

export function compute_d(input, state) {
  const got = _parseInt(input);
  if (got === null) return { ok: false, hint: "Enter a whole number." };
  const expected = modInv(BigInt(state.e), BigInt(state.phi));
  if (got !== expected) {
    return { ok: false, hint: `d satisfies (d · e) ≡ 1 (mod φ). With e=${state.e}, φ=${state.phi}.` };
  }
  return _ok({ d: got });
}

export function pick_message(input, state) {
  const got = _parseInt(input);
  if (got === null) return { ok: false, hint: "Enter a whole number." };
  if (!(0n <= got && got < BigInt(state.n))) {
    return { ok: false, hint: `Message must satisfy 0 ≤ m < n = ${state.n}.` };
  }
  return _ok({ m: got });
}

export function encrypt(input, state) {
  const got = _parseInt(input);
  if (got === null) return { ok: false, hint: "Enter a whole number." };
  const expected = modPow(BigInt(state.m), BigInt(state.e), BigInt(state.n));
  if (got !== expected) {
    return { ok: false, hint: `c = m^e mod n. With m=${state.m}, e=${state.e}, n=${state.n}.` };
  }
  return _ok({ c: got });
}

export function decrypt(input, state) {
  const got = _parseInt(input);
  if (got === null) return { ok: false, hint: "Enter a whole number." };
  const expected = modPow(BigInt(state.c), BigInt(state.d), BigInt(state.n));
  if (got !== expected) {
    return { ok: false, hint: `m = c^d mod n. With c=${state.c}, d=${state.d}, n=${state.n}.` };
  }
  return _ok({ m_decrypted: got });
}

export function info(_input, _state) {
  return { ok: true, value: {} };
}
