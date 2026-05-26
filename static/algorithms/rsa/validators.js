import { isPrime, gcd, modInv, modPow, phi as phiFn } from "./math.js";
import { pollardRho, brentVariant, DEMO_N } from "./rho_demo.js";

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
  // φ = (p-1)(q-1) must leave room for at least one valid e (1 < e < φ with gcd(e,φ)=1).
  // The only pair where φ < 4 is (2, 3) → φ = 2, which has no valid e at all.
  const phiVal = (p - 1n) * (q - 1n);
  if (phiVal < 4n) {
    return { ok: false, hint: `φ = (p-1)(q-1) = ${phiVal} is too small to find a valid e. Pick larger primes (try p=3 and q=5 as the smallest pair).` };
  }
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

// ---- Pollard's rho factoring (button-driven on step 13) -------------------
// Runs both Floyd's tortoise-and-hare and Brent's variant on the fixed demo
// modulus DEMO_N and writes the iteration counts + discovered factor into
// state so the lesson template can render the comparison panel. The
// `_input` is ignored — the actual click handler is in the template and
// triggers `runRhoAnimation` for the visual, then calls `check()`.
export function factor_pollard_rho(_input, _state) {
  const n = DEMO_N;
  const rho = pollardRho(n);
  if (!rho.factor) {
    return { ok: false, hint: "Pollard's rho didn't converge on this N — would normally retry with a different constant c. (This shouldn't happen on the demo modulus.)" };
  }
  const brent = brentVariant(n);
  return _ok({
    rsa_rho_n: n,
    rsa_rho_factor: rho.factor,
    rsa_rho_iterations: rho.iterations,
    rsa_brent_iterations: brent.factor ? brent.iterations : rho.iterations,
    rsa_rho_trajectory_length: rho.trajectory.length,
  });
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
  return { ok: true, value: { sentence: s, first_char: s[0], first_code: s.charCodeAt(0) } };
}

export function encrypt_sentence_head(input, state) {
  const got = _parseInt(input);
  if (got === null) return { ok: false, hint: "Enter a whole number." };
  const sentence = state?.sentence || "";
  if (!sentence) return { ok: false, hint: "No sentence in state — go back and type one first." };
  const e2 = BigInt(state.e2);
  const n2 = BigInt(state.n2);
  const firstCode = BigInt(sentence.charCodeAt(0));
  const expectedFirst = modPow(firstCode, e2, n2);
  if (got !== expectedFirst) {
    return { ok: false, hint: `c = m^e mod n. With m=${firstCode} (the ASCII of '${sentence[0]}'), e=${e2}, n=${n2}.` };
  }
  const encrypted = [];
  for (let i = 0; i < sentence.length; i++) {
    encrypted.push(Number(modPow(BigInt(sentence.charCodeAt(i)), e2, n2)));
  }
  return { ok: true, value: { encrypted, first_encrypted: encrypted[0] } };
}

export function decrypt_sentence_head(input, state) {
  const got = _parseInt(input);
  if (got === null) return { ok: false, hint: "Enter a whole number." };
  const encrypted = state?.encrypted;
  if (!Array.isArray(encrypted) || encrypted.length === 0) {
    return { ok: false, hint: "No encrypted text in state — go back and encrypt first." };
  }
  const d2 = BigInt(state.d2);
  const n2 = BigInt(state.n2);
  const firstC = BigInt(encrypted[0]);
  const expectedFirst = modPow(firstC, d2, n2);
  if (got !== expectedFirst) {
    return { ok: false, hint: `m = c^d mod n. With c=${firstC}, d=${d2}, n=${n2}.` };
  }
  const decoded = encrypted.map((c) => Number(modPow(BigInt(c), d2, n2)));
  const decrypted = decoded.map((code) => String.fromCharCode(code)).join("");
  return { ok: true, value: { decrypted } };
}

// ---- Cheat code -----------------------------------------------------------
// Returns the state + step order to jump to when the user enters the Konami
// code. Skips the toy math entirely and lands at step 12 (type-sentence) with
// both keypairs pre-filled so the playground is fully wired.

export function cheatState() {
  return {
    targetStepOrder: 12,
    state: {
      // Toy keypair (smallest workable: p=3, q=5)
      p: 3, q: 5, n: 15, phi: 8, e: 7, d: 7,
      m: 2, c: 8, m_decrypted: 2,
      // Bigger keypair for text encryption (p=17, q=19)
      p2: 17, q2: 19, n2: 323, phi2: 288, e2: 5, d2: 173,
    },
  };
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

  pick_pq_big: (_state) => [
    `**The method:** Pick two different primes, each at least 17. We need n = p × q ≥ 256 so any ASCII character fits.`,
    `**Why 17?** 17 × 19 = 323, which is the smallest product ≥ 256 with two distinct primes both ≥ 17. Anything smaller and you can't encrypt a space (ASCII 32).`,
    `**A pair that works: p = 17, q = 19.** That gives n = 323, φ = 288. (Try p = 19, q = 23 if you want a slightly bigger key.)`,
  ],

  encrypt_sentence_head: (state) => {
    const sentence = state?.sentence || "";
    const ch = sentence[0] || "?";
    const code = BigInt(sentence.charCodeAt(0) || 0);
    const e = BigInt(state?.e2 || 0);
    const n = BigInt(state?.n2 || 1);
    const result = modPow(code, e, n);
    return [
      `**The method:** Same as the toy encrypt — c = m^e mod n. Here m is the ASCII code of the first character.`,
      `For '${ch}', m = ${code}. So compute ${code}^${e} mod ${n}.`,
      `**Answer: ${result}.** (In Python: \`pow(${code}, ${e}, ${n})\`.)`,
    ];
  },

  decrypt_sentence_head: (state) => {
    const encrypted = Array.isArray(state?.encrypted) ? state.encrypted : [0];
    const c = BigInt(encrypted[0]);
    const d = BigInt(state?.d2 || 0);
    const n = BigInt(state?.n2 || 1);
    const result = modPow(c, d, n);
    const ch = String.fromCharCode(Number(result));
    return [
      `**The method:** Same shape as decryption you already did — m = c^d mod n. Here c is the first encrypted number.`,
      `c = ${c}, d = ${d}, n = ${n}. Compute ${c}^${d} mod ${n}.`,
      `**Answer: ${result}.** That's the ASCII code for '${ch}'. (In Python: \`pow(${c}, ${d}, ${n})\`.)`,
    ];
  },

  factor_pollard_rho: (_state) => [
    `**The cycle:** Define f(x) = x² + 1 mod N. Iterating f produces a sequence x₀, x₁, x₂, … Since there are only N possible values, the sequence must eventually repeat — and modulo any prime factor p of N, it repeats much sooner (after ~√p steps, by the birthday paradox).`,
    `**The gcd trick:** Run two pointers through the sequence — *tortoise* (one f-step per round) and *hare* (two). When tortoise ≡ hare (mod p), their difference is a multiple of p but NOT of N. So **gcd(|tortoise − hare|, N) = p**, the factor falls out. No need to know p in advance; gcd is fast.`,
    `**Why this scales: the brick wall.** Pollard's rho costs ~√p f-evaluations, where p is the SMALLER prime factor. For 64-bit primes (~10¹⁹), that's ~10⁹·⁵ ops — minutes on a laptop. For 1024-bit primes (~10³⁰⁸), it's ~10¹⁵⁴ ops — longer than the age of the universe. That asymmetry — toy primes break in milliseconds, real primes are unfactorable — is the entire security argument for using huge primes in production RSA.`,
  ],
};
