// Synthetic bcrypt timing demo for the bcrypt lesson.
//
// IMPORTANT — this file does NOT implement bcrypt. A faithful JS bcrypt
// (e.g. `bcryptjs`) is ~30 KB of code and locks the main thread for half a
// second per hash at cost 12. Shipping that just to plot a bar chart is too
// heavy. Instead we use **PBKDF2-HMAC-SHA-256 with iterations = 1000 * 2^cost**
// as a stand-in. The shape is right:
//
//   - cost +1 doubles the work, exactly like real bcrypt's exponential factor.
//   - cost 4 → cost 14 is a ~1024× slowdown, matching the cited bcrypt curve.
//
// The actual ms numbers will not match real bcrypt exactly (PBKDF2 and the
// Blowfish key schedule have different constant factors), so step 4 also
// surfaces the *cited* real-bcrypt timings via `compareWithReal()`.
//
// Cited reference values come from `bcrypt` (Python, C-backed) benchmarks
// on a typical 2024 laptop:
//   cost  4 ≈   1 ms
//   cost  8 ≈  16 ms
//   cost 10 ≈  65 ms
//   cost 12 ≈ 260 ms
//   cost 14 ≈  1 s
//   cost 16 ≈  4 s
//
// Node >=19 ships crypto.subtle globally, so this module is unit-testable
// without a browser.

function bytesToHex(arr) {
  return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function nowMs() {
  if (typeof performance !== "undefined" && typeof performance.now === "function") {
    return performance.now();
  }
  return Date.now();
}

// Cited real-bcrypt timings (ms) from published benchmarks of the `bcrypt`
// Python library (C backend) on a typical 2024 laptop CPU. Keyed by cost
// factor so the step-4 UI can render the cited curve next to the synthetic
// one. Costs not listed double from the nearest neighbour.
export const CITED_BCRYPT_MS = {
  4: 1,
  5: 2,
  6: 4,
  7: 8,
  8: 16,
  9: 32,
  10: 65,
  11: 130,
  12: 260,
  13: 520,
  14: 1040,
  15: 2080,
  16: 4160,
};

// Bounds enforced by the lesson UI. Real bcrypt accepts 4-31, but we cap the
// synthetic demo at 14 because PBKDF2 at iter=16M takes 5-10 seconds in the
// browser and blocks the main thread.
export const MIN_COST = 4;
export const MAX_COST = 14;

// Convert a bcrypt cost factor to the PBKDF2 iteration count we use as the
// synthetic stand-in. cost c → 1000 * 2^c iterations:
//   cost  4 →  16,000 iterations
//   cost  8 → 256,000 iterations
//   cost 10 → 1,024,000 iterations
//   cost 12 → 4,096,000 iterations
//   cost 14 → 16,384,000 iterations
// The "1000" base factor was picked so cost 12 lands in the 200-400 ms range
// on a 2024 laptop — the same ballpark as real bcrypt cost 12 (~260 ms).
export function costToIterations(cost) {
  return 1000 * Math.pow(2, cost);
}

// hashWithCost — synthetic bcrypt-style hash for a (password, cost) pair.
//
// Returns {hash, ms, cost, iterations} where:
//   hash       — 64-hex-char PBKDF2-HMAC-SHA256 output (not a real bcrypt hash)
//   ms         — wall-clock time for the derivation
//   cost       — the cost factor that was used
//   iterations — the PBKDF2 iter count we mapped that cost to
//
// The hash field is intentionally NOT formatted as `$2b$<cost>$<salt><hash>`
// — that would mislead learners into thinking we computed a real bcrypt hash.
// Step 5 (salt-and-format) explains the real format separately.
export async function hashWithCost(password, cost) {
  const c = Number(cost);
  if (!Number.isInteger(c) || c < MIN_COST || c > MAX_COST) {
    throw new Error(`cost must be an integer in [${MIN_COST}, ${MAX_COST}]`);
  }
  if (typeof password !== "string") {
    throw new Error("password must be a string");
  }

  const iterations = costToIterations(c);
  const pwBytes = new TextEncoder().encode(password);
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);

  const t0 = nowMs();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    pwBytes,
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    baseKey,
    256
  );
  const t1 = nowMs();

  return {
    hash: bytesToHex(new Uint8Array(bits)),
    ms: t1 - t0,
    cost: c,
    iterations,
  };
}

// compareWithReal — run hashWithCost(password, cost) and pair it with the
// cited real-bcrypt timing for the same cost. The UI uses this to draw a
// "synthetic ms vs cited real-bcrypt ms" comparison on the bar chart, so
// learners see both the *shape* of the curve (which our synthetic gets
// right) and the *absolute numbers* (which only the cited row gets right).
export async function compareWithReal(password, cost) {
  const result = await hashWithCost(password, cost);
  const cited_real_ms = CITED_BCRYPT_MS[result.cost] ?? null;
  return {
    ...result,
    cited_real_ms,
    note: "Synthetic ms uses PBKDF2-SHA256 with iter=1000*2^cost. Real bcrypt iterates the Blowfish key schedule — same exponential shape, different constant factor.",
  };
}
