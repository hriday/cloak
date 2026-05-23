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

function _pickEDeterministic(phi) {
  let e = 3n;
  while (gcd(e, phi) !== 1n) e++;
  return e;
}

export function pick_pq_big(input, _state) {
  const p = _parseInt(input?.p);
  const q = _parseInt(input?.q);
  if (p === null || q === null) return { ok: false, hint: "Enter whole numbers for both p and q." };
  if (p < 17n || q < 17n) return { ok: false, hint: "For real text, both primes need to be at least 17 so n ≥ 256." };
  if (p === q) return { ok: false, hint: "p and q must be different primes." };
  if (!isPrime(p)) return { ok: false, hint: `${p} is not prime.` };
  if (!isPrime(q)) return { ok: false, hint: `${q} is not prime.` };
  const n2 = p * q;
  if (n2 < 256n) return { ok: false, hint: "n must be at least 256 to fit any ASCII character." };
  const phi2 = (p - 1n) * (q - 1n);
  const e2 = _pickEDeterministic(phi2);
  const d2 = modInv(e2, phi2);
  return _ok({ p2: p, q2: q, n2, phi2, e2, d2 });
}

export function pick_sentence(input, _state) {
  const s = input == null ? "" : String(input);
  if (s.length === 0) return { ok: false, hint: "Type at least one character." };
  if (s.length > 500) return { ok: false, hint: "Keep it under 500 characters." };
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code < 32 || code > 126) {
      return { ok: false, hint: `Only printable ASCII for now — no emoji, accents, tabs, or newlines. Found: '${s[i]}'.` };
    }
  }
  return { ok: true, value: { sentence: s } };
}

// ---- Walkthroughs ----------------------------------------------------------
// Each returns an array of escalating hint strings (method → worked example → answer).
// Wizard reveals one rung per click of the "I don't know how" button.
// Use **bold** for inline emphasis; newlines render as line breaks.

function _modInvSearch(e, phi) {
  for (let d = 1n; d < phi * 100n; d++) {
    if ((d * e) % phi === 1n) return d;
  }
  return null;
}

export const walkthroughs = {
  compute_n: (state) => {
    const p = state.p, q = state.q;
    return [
      `**The method:** n is just p × q. Multiply your two primes.`,
      `p = ${p}, q = ${q}, so n = ${p} × ${q}.`,
      `**n = ${p * q}.**`,
    ];
  },

  compute_phi: (state) => {
    const p = state.p, q = state.q;
    return [
      `**The method:** For two primes, φ(n) = (p − 1)(q − 1). Subtract one from each prime, then multiply.`,
      `p − 1 = ${p - 1}, q − 1 = ${q - 1}, so φ = ${p - 1} × ${q - 1}.`,
      `**φ = ${(p - 1) * (q - 1)}.**`,
    ];
  },

  compute_d: (state) => {
    const e = BigInt(state.e), phi = BigInt(state.phi);
    const answer = _modInvSearch(e, phi);
    // Show a few non-solution rows so rung 2 shows the WORK without giving the answer.
    // Skip the row where d === answer; rung 3 is where the answer lives.
    const rows = [];
    const maxRows = 3n;
    for (let d = 1n; d < phi && BigInt(rows.length) < maxRows; d++) {
      if (d === answer) continue;
      const prod = d * e;
      rows.push(`d=${d}: ${d}×${e} = ${prod}, mod ${phi} = ${prod % phi}`);
    }
    return [
      `**The method:** Try d = 1, 2, 3, … For each one, compute (d × ${e}) mod ${phi}. Stop when the result is 1.`,
      `**Walking the work:**\n${rows.join("\n")}\n…keep going until one of them gives remainder 1.`,
      `**d = ${answer}.** Check: ${answer} × ${e} = ${answer * e}, and ${answer * e} mod ${phi} = 1. ✓`,
    ];
  },

  pick_message: (state) => {
    const n = state.n;
    return [
      `**The method:** Pick any whole number from 0 up to n − 1. Smaller numbers are easier to follow by hand.`,
      `With n = ${n}, any value 0 ≤ m < ${n} works. Something like 5 or 7 keeps the arithmetic manageable.`,
      `Try **m = ${Math.min(7, Math.max(2, Math.floor(Number(n) / 3)))}** — works for this n.`,
    ];
  },

  encrypt: (state) => {
    const m = BigInt(state.m), e = BigInt(state.e), n = BigInt(state.n);
    const raw = m ** e;
    return [
      `**The method:** c = m^e mod n. Raise m to the e power, then take the remainder when divided by n.`,
      `m = ${m}, e = ${e}, n = ${n}. So ${m}^${e} = ${raw}. Then ${raw} mod ${n} = ?`,
      `**c = ${raw % n}.**`,
    ];
  },

  decrypt: (state) => {
    const c = BigInt(state.c), d = BigInt(state.d), n = BigInt(state.n);
    const raw = c ** d;
    const tooBig = raw.toString().length > 40;
    return [
      `**The method:** m = c^d mod n. Raise c to the d power, then take the remainder when divided by n. (Same shape as encrypt, just with d instead of e.)`,
      tooBig
        ? `c = ${c}, d = ${d}, n = ${n}. ${c}^${d} is enormous — in Python, use \`pow(c, d, n)\` so it doesn't compute the huge intermediate.`
        : `c = ${c}, d = ${d}, n = ${n}. So ${c}^${d} = ${raw}. Then ${raw} mod ${n} = ?`,
      `**m = ${raw % n}.** Should match the message you encrypted.`,
    ];
  },
};
