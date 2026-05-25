// bcrypt lesson validators.
//
// Step 4 (time-the-cost) — time_cost. Input: {password, cost}. Runs the
// synthetic bcrypt-style hash via bcrypt_demo.hashWithCost, captures wall
// time, writes bcrypt_* state keys. The state-key prefix avoids conflicts
// with the password-hashing lesson (which uses pw_pbkdf2_*) and any future
// Blowfish state (bf_*).
//
// All other steps use the info validator (always ok).

import { hashWithCost, MIN_COST, MAX_COST, CITED_BCRYPT_MS } from "./bcrypt_demo.js";

// Allowed cost factors in the dropdown. Picked to span the full
// "feels instant" → "feels broken" range so learners can FEEL the
// exponential cost curve, not just read about it.
const ALLOWED_COSTS = [4, 8, 10, 12, 14];

// Shared ASCII / length guard for password strings. Returns null if ok, else
// a hint string. Matches the password-hashing lesson's shape so the two
// lessons feel consistent. The 72-byte bcrypt truncation limit is mentioned
// in step 5 (salt-and-format) but not enforced here — passwords up to 200
// chars are accepted so learners can paste long inputs and the step still
// proceeds.
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

// Step 4 — time the cost factor.
//
// Input shape: {password: string, cost: number}.
// Writes: {bcrypt_password, bcrypt_cost, bcrypt_hash, bcrypt_hash_ms,
//          bcrypt_iterations, bcrypt_cited_real_ms}.
//
// `bcrypt_hash` is the synthetic PBKDF2 output (64 hex chars), NOT a real
// bcrypt hash. The lesson text in step 5 explains the real `$2b$...` format
// separately so learners don't conflate the two.
export async function time_cost(input, _state) {
  const password = input?.password == null ? "" : String(input.password);
  const hint = checkPassword(password);
  if (hint) return { ok: false, hint };

  const cost = Number(input?.cost);
  if (!Number.isInteger(cost) || !ALLOWED_COSTS.includes(cost)) {
    return {
      ok: false,
      hint: `Pick a cost factor from the dropdown (${ALLOWED_COSTS.join(", ")}).`,
    };
  }

  let result = null;
  let cryptoError = null;
  try {
    if (typeof crypto !== "undefined" && crypto.subtle) {
      result = await hashWithCost(password, cost);
    }
  } catch (e) {
    cryptoError = String(e.message || e);
  }

  if (cryptoError) {
    return {
      ok: false,
      hint: "PBKDF2 (used as the bcrypt timing stand-in) failed. This step requires a modern browser over HTTPS.",
    };
  }

  return {
    ok: true,
    value: {
      bcrypt_password: password,
      bcrypt_cost: cost,
      bcrypt_hash: result ? result.hash : null,
      bcrypt_hash_ms: result ? result.ms : null,
      bcrypt_iterations: result ? result.iterations : null,
      bcrypt_cited_real_ms: CITED_BCRYPT_MS[cost] ?? null,
    },
  };
}

export function info(_input, _state) {
  return { ok: true, value: {} };
}

export const walkthroughs = {
  time_cost: (_state) => [
    `**The construction:** bcrypt's cost factor is logarithmic — cost \`c\` means \`2^c\` iterations of the Blowfish key schedule (the slow setup phase you saw briefly in the [Blowfish lesson](/algorithms/blowfish/learn/feistel-rounds/)). Each \`+1\` to the cost factor doubles the work. The widget here uses PBKDF2-HMAC-SHA-256 with iterations \`= 1000 * 2^cost\` as a synthetic stand-in — same exponential shape, different constant factor.`,
    `**Try this:** pick cost 4, hit submit, note the ms. Now pick cost 14 — it should take ~1024× longer (cost 4 → 14 is 10 doublings). The cited column shows what real bcrypt takes for the same cost on a 2024 laptop. cost 12 (the modern default) is ~260 ms — invisible at login, ruinous for an attacker guessing billions of times.`,
    `**Practical numbers:** Ruby on Rails and most PHP frameworks default to cost 10-12. Bump to 13 or 14 if you can afford the latency. Each \`+1\` doubles both your login latency and an attacker's cost — pick the highest your login UX can absorb.`,
  ],
};
