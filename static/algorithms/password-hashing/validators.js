// Password Hashing lesson validators.
//
// Step 3 (pbkdf2)        — pbkdf2_compute. Input: {password, iterations}.
//                          Runs PBKDF2 via Web Crypto, captures wall time,
//                          writes pw_pbkdf2_* keys.
// Step 6 (compare-hashes) — compare_all. Input: {password}.
//                          Runs compareAll(), writes pw_compare_results.
// Other steps             — info validator (always ok).

import { pbkdf2Hex, compareAll } from "./pw_demo.js";

const ALLOWED_ITER = [1000, 10000, 100000, 1000000];

// Shared ASCII / length guard for password strings. Returns null if ok, else
// a hint string. Allows printable ASCII only — same shape as HMAC.
function checkPassword(password) {
  if (typeof password !== "string" || password.length === 0) {
    return "Type a password (any string).";
  }
  if (password.length > 200) {
    return "Keep it under 200 characters for the demo.";
  }
  for (let i = 0; i < password.length; i++) {
    const code = password.charCodeAt(i);
    if (code < 32 || code > 126) {
      return "Stick to printable ASCII for the demo.";
    }
  }
  return null;
}

// Step 3 — derive a 32-byte key via PBKDF2-HMAC-SHA256 with a random 16-byte
// salt, the user's password, and an iteration count from the dropdown. Writes
// {pw_pbkdf2_password, pw_pbkdf2_iter, pw_pbkdf2_hex, pw_pbkdf2_salt,
// pw_pbkdf2_ms}. The salt is exposed by design — it's not a secret, and
// seeing it next to the hash is part of the pedagogy.
export async function pbkdf2_compute(input, _state) {
  const password = input?.password == null ? "" : String(input.password);
  const hint = checkPassword(password);
  if (hint) return { ok: false, hint };

  const iter = Number(input?.iterations);
  if (!ALLOWED_ITER.includes(iter)) {
    return { ok: false, hint: "Pick an iteration count from the dropdown." };
  }

  let result = null;
  let cryptoError = null;
  try {
    if (typeof crypto !== "undefined" && crypto.subtle) {
      result = await pbkdf2Hex(password, iter);
    }
  } catch (e) {
    cryptoError = String(e.message || e);
  }

  if (cryptoError) {
    return {
      ok: false,
      hint: "PBKDF2 failed. This step requires a modern browser over HTTPS.",
    };
  }

  return {
    ok: true,
    value: {
      pw_pbkdf2_password: password,
      pw_pbkdf2_iter: iter,
      pw_pbkdf2_hex: result ? result.hex : null,
      pw_pbkdf2_salt: result ? result.salt_hex : null,
      pw_pbkdf2_ms: result ? result.ms : null,
    },
  };
}

// Step 6 — fan out across SHA-256 + PBKDF2-1k + PBKDF2-100k (live) plus
// bcrypt-12 + Argon2id-default (cited). Writes pw_compare_results, the
// list the bar chart renders.
export async function compare_all(input, _state) {
  const password = input?.password == null
    ? "correct horse battery staple"
    : String(input.password);
  const hint = checkPassword(password);
  if (hint) return { ok: false, hint };

  let results = null;
  let cryptoError = null;
  try {
    if (typeof crypto !== "undefined" && crypto.subtle) {
      results = await compareAll(password);
    }
  } catch (e) {
    cryptoError = String(e.message || e);
  }

  if (cryptoError) {
    return {
      ok: false,
      hint: "One of the timing rows failed. Refresh and retry.",
    };
  }

  if (results == null) {
    // Crypto-less Node test path: still let the step pass with an empty
    // result list rather than blocking lesson navigation.
    return { ok: true, value: { pw_compare_results: [] } };
  }

  return { ok: true, value: { pw_compare_results: results } };
}

export function info(_input, _state) {
  return { ok: true, value: {} };
}

export const walkthroughs = {
  pbkdf2_compute: (_state) => [
    `**The construction:** PBKDF2 (RFC 8018) iterates HMAC-SHA-256 over (password, salt) N times. The output is your derived key — 32 bytes here. The salt is fresh per-user and stored alongside the hash in your DB; it's not a secret, it just defeats rainbow tables.`,
    `**Why iterate?** A single hash takes microseconds; a GPU can guess ~10⁹/s. Iterating slows each guess by the same factor for the legitimate verifier and the attacker. At 100,000 iterations a single check is ~100 ms — annoying to crack, invisible at login. OWASP recommends 600,000+ for PBKDF2-HMAC-SHA-256 as of 2023.`,
    `**Try this:** type any password, pick an iteration count, hit submit. Watch the ms scale roughly linearly: 10k ≈ 10× the cost of 1k, 100k ≈ 100×. The hex output is 64 chars (256 bits) — what you'd actually store in your DB, next to the salt.`,
  ],
  compare_all: (_state) => [
    `**The setup:** the same password (\`"correct horse battery staple"\`) gets hashed five different ways. SHA-256, PBKDF2-1k, and PBKDF2-100k run live in your browser via Web Crypto. bcrypt-12 and Argon2id-default report cited timings from published benchmarks on a typical 2024 laptop — real JS/WASM builds are 30-150 KB and would block the page.`,
    `**Read the chart on a log scale.** SHA-256 finishes in microseconds; Argon2id takes half a second. On a linear axis SHA-256 would be invisible. That gap is exactly the point — a fast hash is the wrong primitive for storing passwords.`,
    `**The takeaway:** Argon2id at default parameters costs ~500 ms per guess, which means an attacker with a GPU farm can try ~2 per second per core — not ~10⁹ as with raw SHA-256. That's a 5-billion-× slowdown of the attacker for the same fraction-of-a-second cost at login.`,
  ],
};
