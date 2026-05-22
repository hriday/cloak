export function isPrime(n) {
  if (n < 2n) return false;
  if (n < 4n) return true;
  if (n % 2n === 0n) return false;
  let i = 3n;
  while (i * i <= n) {
    if (n % i === 0n) return false;
    i += 2n;
  }
  return true;
}

export function gcd(a, b) {
  a = a < 0n ? -a : a;
  b = b < 0n ? -b : b;
  while (b) { [a, b] = [b, a % b]; }
  return a;
}

export function phi(p, q) {
  return (p - 1n) * (q - 1n);
}

function _egcd(a, b) {
  if (b === 0n) return { g: a, x: 1n, y: 0n };
  const r = _egcd(b, a % b);
  return { g: r.g, x: r.y, y: r.x - (a / b) * r.y };
}

export function modInv(a, m) {
  const r = _egcd(((a % m) + m) % m, m);
  if (r.g !== 1n) throw new Error(`no modular inverse: gcd(${a}, ${m}) = ${r.g}`);
  return ((r.x % m) + m) % m;
}

export function modPow(base, exp, mod) {
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

export function coprimeCandidates(phiN, limit = 12) {
  const out = [];
  let e = 3n;
  while (out.length < limit && e < phiN) {
    if (gcd(e, phiN) === 1n) out.push(e);
    e += 2n;
  }
  return out;
}
