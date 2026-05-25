// Bleichenbacher's adaptive chosen-ciphertext attack on RSA PKCS#1 v1.5
// (CRYPTO 1998). The attack uses the fact that RSA is multiplicatively
// homomorphic:
//
//     (m · s)^e ≡ m^e · s^e ≡ c · s^e   (mod n)
//
// So the attacker can construct a new ciphertext c' = c · s^e mod n whose
// decryption is m · s mod n, for any s of their choice. The padding oracle
// tells them whether m · s mod n is PKCS#1 v1.5 conforming — i.e. lies in
// [2B, 3B). Each "conforming" answer is a linear constraint on m:
//
//     2B ≤ m · s − r · n < 3B   for some non-negative integer r
//   ⇒ (2B + r · n) / s ≤ m ≤ (3B − 1 + r · n) / s
//
// The attack iterates: find an s such that c · s^e is conforming, intersect
// the resulting interval(s) with the running set M of candidates for m,
// repeat. The intervals halve in width roughly every iteration. After
// ~log₂(B) ≈ 56 narrowing iterations the interval collapses to a single
// value — which is m.
//
// Pseudocode (Section 3.2 of the paper):
//
//   Step 1: Blinding. Pick s₀ such that c · s₀^e is conforming. If c
//           itself is conforming (our case — the target IS the encryption
//           of a real PKCS-padded message), set s₀ = 1 and c₀ = c.
//   Step 2: Searching for PKCS conforming messages.
//     2.a:  First conforming s. Start s = ⌈n / (3B)⌉; increment until
//           c₀ · s^e is conforming.
//     2.b:  After finding ≥1 conforming s, if |M| > 1, increment the
//           previous s by 1 until conforming.
//     2.c:  If |M| = 1, with M = {[a, b]}: search r ≥ ⌈2(b·s − 2B)/n⌉,
//           and for each r, search s in [⌈(2B+rn)/b⌉, ⌊(3B+rn)/a⌋] until
//           conforming. Narrows much faster than the 2.b sweep when the
//           interval is small.
//   Step 3: Narrowing intervals. For each [a,b] in M, for each r in
//           [⌈(a·s−3B+1)/n⌉, ⌊(b·s−2B)/n⌋]: intersect [a,b] with
//           [⌈(2B+rn)/s⌉, ⌊(3B−1+rn)/s⌋].
//   Step 4: Done. When M = {[a, a]}, recover m = a · s₀⁻¹ mod n.
//
// For our toy parameters (k=8, n ≈ 2^60), the attack typically converges
// in 8K–40K queries. Real 2048-bit Bleichenbacher attacks need ~10^6.

import {
  query,
  targetCiphertext,
  publicKey,
  N,
  E,
  K,
  B,
  _modPow,
} from "./bleich_simulator.js";

// ---- BigInt helpers ----

function _ceilDiv(a, b) {
  // Both BigInt. Assumes b > 0.
  return (a + b - 1n) / b;
}
function _floorDiv(a, b) {
  // Both BigInt. Assumes b > 0. JS BigInt division truncates toward zero,
  // which equals floor for non-negative numerator and positive denominator.
  return a / b;
}

function _modInv(a, m) {
  // Standard extended Euclidean. a, m: BigInt.
  let [oldR, r] = [((a % m) + m) % m, m];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== 1n) throw new Error(`no modular inverse: gcd(${a}, ${m}) = ${oldR}`);
  return ((oldS % m) + m) % m;
}

// ---- the attack ----

// runAttack:
//   server          — object with the API { query, targetCiphertext,
//                     publicKey } matching bleich_simulator.js. In
//                     production the in-process simulator is used; tests
//                     pass it explicitly so they can substitute mocks.
//   progressCallback — optional async function called every ~100 queries
//                     with { totalQueries, conformingFound, intervalLow,
//                     intervalHigh, intervalCount }. Lets the UI animate.
//   options         — { maxQueries, progressEvery } — defaults 200_000 and
//                     100 respectively. maxQueries throws if exceeded
//                     (defensive — should never happen for our toy params).
//
// Returns { plaintext, paddedInt, totalQueries, conformingSValues }.
//
//   plaintext        — Uint8Array(k) of recovered PKCS#1 v1.5 padded bytes
//                      (starts with 00 02). Caller strips padding to get M.
//   paddedInt        — the BigInt value of the recovered padded message.
//   totalQueries     — how many oracle calls the attack made.
//   conformingSValues — array of all s values that produced "conforming"
//                      responses (useful for tests and pedagogical UI).
export async function runAttack(server, progressCallback, options) {
  const opts = options || {};
  const maxQueries = opts.maxQueries || 200000;
  const progressEvery = opts.progressEvery || 100;

  const srv = server || _defaultServer();
  const pk = srv.publicKey();
  const n = pk.n;
  const e = pk.e;
  const kBytes = pk.k;
  const Blocal = 1n << BigInt(8 * (kBytes - 2));
  const c = srv.targetCiphertext();

  let queries = 0;
  const conforming = [];

  // Wrapped oracle that counts queries and enforces the maxQueries cap.
  const ask = (cVal) => {
    if (queries >= maxQueries) {
      throw new Error(`bleichenbacher: exceeded maxQueries=${maxQueries}`);
    }
    queries += 1;
    return srv.query(cVal);
  };

  // ---- Step 1: blinding. ----
  //
  // For the standard lesson, c IS the encryption of a properly-PKCS-padded
  // message — so it's already conforming, and s₀ = 1 suffices. We still
  // verify this with one oracle query (it's the first thing the algorithm
  // would do). If a future version of this lesson encrypts non-conforming
  // c, replace this with a sweep over random s₀ until conforming.
  let s0 = 1n;
  let c0 = c;
  if (ask(c0) !== "conforming") {
    // Blinding sweep. We use the deterministic s₀ = 2, 3, … which keeps
    // tests reproducible. For the toy modulus this terminates well within
    // the maxQueries budget.
    s0 = 2n;
    while (true) {
      const candidate = (c * _modPow(s0, e, n)) % n;
      if (ask(candidate) === "conforming") {
        c0 = candidate;
        break;
      }
      s0 += 1n;
    }
  }

  // M = list of disjoint intervals [a, b] (inclusive) that bound the
  // value of m₀ = m · s₀ mod n. Initially M = {[2B, 3B - 1]} because
  // m₀ is PKCS-conforming by construction.
  let M = [[2n * Blocal, 3n * Blocal - 1n]];
  let s = _ceilDiv(n, 3n * Blocal);    // Step 2.a initial guess

  // Progress emission helper.
  let lastEmittedAt = 0;
  const emit = async () => {
    if (typeof progressCallback !== "function") return;
    if (queries - lastEmittedAt < progressEvery) return;
    lastEmittedAt = queries;
    const [lo, hi] = M.length > 0 ? M[0] : [0n, 0n];
    try {
      await progressCallback({
        totalQueries: queries,
        conformingFound: conforming.length,
        intervalLow: lo,
        intervalHigh: hi,
        intervalCount: M.length,
      });
    } catch (_e) {
      // Swallow UI errors — they mustn't kill the attack.
    }
  };

  // ---- Steps 2–4: iterate. ----
  let i = 1;
  while (true) {
    if (i === 1) {
      // Step 2.a — first conforming s starting from ⌈n / (3B)⌉.
      while (true) {
        const cTry = (c0 * _modPow(s, e, n)) % n;
        const r = ask(cTry);
        await emit();
        if (r === "conforming") {
          conforming.push(s);
          break;
        }
        s += 1n;
      }
    } else if (M.length > 1) {
      // Step 2.b — incremental search.
      s += 1n;
      while (true) {
        const cTry = (c0 * _modPow(s, e, n)) % n;
        const r = ask(cTry);
        await emit();
        if (r === "conforming") {
          conforming.push(s);
          break;
        }
        s += 1n;
      }
    } else {
      // Step 2.c — narrow single-interval search. M = {[a, b]}.
      const [a, b] = M[0];
      let r = _ceilDiv(2n * (b * s - 2n * Blocal), n);
      // We may have to try multiple r values before finding a conforming s.
      let found = false;
      while (!found) {
        const sLow = _ceilDiv(2n * Blocal + r * n, b);
        const sHigh = _floorDiv(3n * Blocal + r * n, a);
        if (sLow > sHigh) {
          r += 1n;
          continue;
        }
        for (let sCand = sLow; sCand <= sHigh; sCand += 1n) {
          const cTry = (c0 * _modPow(sCand, e, n)) % n;
          const resp = ask(cTry);
          await emit();
          if (resp === "conforming") {
            s = sCand;
            conforming.push(s);
            found = true;
            break;
          }
        }
        if (!found) r += 1n;
      }
    }

    // ---- Step 3: narrow the intervals. ----
    const newM = [];
    for (const [a, b] of M) {
      const rLow = _ceilDiv(a * s - 3n * Blocal + 1n, n);
      const rHigh = _floorDiv(b * s - 2n * Blocal, n);
      for (let r = rLow; r <= rHigh; r += 1n) {
        const lo = _maxBig(a, _ceilDiv(2n * Blocal + r * n, s));
        const hi = _minBig(b, _floorDiv(3n * Blocal - 1n + r * n, s));
        if (lo <= hi) {
          // Insert / merge into newM (kept sorted by lo).
          _insertMerge(newM, [lo, hi]);
        }
      }
    }

    if (newM.length === 0) {
      // Shouldn't happen for a well-formed run. Guard against pathological
      // inputs (e.g. malicious server) by throwing rather than infinite-loop.
      throw new Error(
        `bleichenbacher: intervals collapsed to empty at iteration ${i} ` +
        `(s=${s}, queries=${queries})`
      );
    }

    M = newM;

    // ---- Step 4: done? ----
    if (M.length === 1 && M[0][0] === M[0][1]) {
      const m0 = M[0][0];
      // Recover m = m₀ · s₀⁻¹ mod n.
      const s0Inv = _modInv(s0, n);
      const m = (m0 * s0Inv) % n;

      // Final progress emission.
      if (typeof progressCallback === "function") {
        try {
          await progressCallback({
            totalQueries: queries,
            conformingFound: conforming.length,
            intervalLow: m,
            intervalHigh: m,
            intervalCount: 1,
            done: true,
          });
        } catch (_e) {
          // ignore UI errors
        }
      }

      return {
        plaintext: _bigIntToBytes(m, kBytes),
        paddedInt: m,
        totalQueries: queries,
        conformingSValues: conforming,
      };
    }

    i += 1;
  }
}

// Strip PKCS#1 v1.5 padding from a recovered plaintext.
// Returns the message bytes (Uint8Array). Throws if the input isn't
// PKCS#1 v1.5 well-formed (00 02 <PS nonzero≥1> 00 <M>).
export function stripPadding(paddedBytes) {
  if (!(paddedBytes instanceof Uint8Array)) {
    throw new Error("stripPadding expects Uint8Array");
  }
  if (paddedBytes.length < 4) {
    throw new Error("paddedBytes too short for PKCS#1 v1.5");
  }
  if (paddedBytes[0] !== 0x00 || paddedBytes[1] !== 0x02) {
    throw new Error(
      `not PKCS#1 v1.5 conforming: leading bytes ${paddedBytes[0].toString(16)} ${paddedBytes[1].toString(16)}`
    );
  }
  let sep = -1;
  for (let i = 2; i < paddedBytes.length; i++) {
    if (paddedBytes[i] === 0x00) { sep = i; break; }
  }
  if (sep < 3) {
    throw new Error("PKCS#1 v1.5: 0x00 separator missing or PS empty");
  }
  return paddedBytes.slice(sep + 1);
}

// ---- internal helpers ----

function _defaultServer() {
  return {
    query,
    targetCiphertext,
    publicKey,
  };
}

function _bigIntToBytes(m, k) {
  const out = new Uint8Array(k);
  let x = m;
  for (let i = k - 1; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

function _maxBig(a, b) { return a > b ? a : b; }
function _minBig(a, b) { return a < b ? a : b; }

function _insertMerge(list, intv) {
  // Insert [lo, hi] into a list of disjoint intervals (sorted by lo),
  // merging overlapping or adjacent intervals.
  let [lo, hi] = intv;
  let inserted = false;
  const out = [];
  for (const [a, b] of list) {
    if (b + 1n < lo) {
      out.push([a, b]);
    } else if (hi + 1n < a) {
      if (!inserted) { out.push([lo, hi]); inserted = true; }
      out.push([a, b]);
    } else {
      // overlap — merge
      lo = a < lo ? a : lo;
      hi = b > hi ? b : hi;
    }
  }
  if (!inserted) out.push([lo, hi]);
  // Keep `list` reference equal — copy results back.
  list.length = 0;
  for (const iv of out) list.push(iv);
}
