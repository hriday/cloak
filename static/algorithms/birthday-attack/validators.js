// Validators for the birthday-attack lesson.
//
// One substantive validator:
//   find_collision — button-press. Runs `findCollision(16)` and
//                    writes the result (the two colliding inputs,
//                    their shared 16-bit truncated hash, and the
//                    attempt count) into state for the page UI.
//                    Should land near sqrt(2^16) = 256 attempts.
//
// Plus the conventional pass-through `info` validator and a
// `walkthroughs` object for the 3-rung help panel.

import { findCollision } from "./bday_demo.js";

// Default hashBits for the in-page collision search. 16 bits =
// 65,536-entry hash space, expected ~256 attempts.
const DEFAULT_HASH_BITS = 16;

// ---- find_collision ------------------------------------------------------

// Button-press validator. Input is ignored — the page just clicks
// "Find a collision" and we run the brute-force search end-to-end.
// State carries the two colliding inputs (distinct strings), their
// shared 16-bit truncated hash, the attempt count, and the hash size
// used. The codegen step uses these to seed the Python script with
// the same scenario the user just watched.

export async function find_collision(_input, _state) {
  let result;
  try {
    result = await findCollision(DEFAULT_HASH_BITS);
  } catch (e) {
    return {
      ok: false,
      hint:
        "Collision search failed mid-run — refresh and retry. " +
        "Original: " + (e && e.message ? e.message : String(e)),
    };
  }

  // Sanity guard. findCollision() promises distinct inputs that hash
  // to the same value, but defense-in-depth in case the search loop
  // ever regresses: surface that bug to the page rather than silently
  // claiming success.
  if (result.inputA === result.inputB) {
    return {
      ok: false,
      hint:
        "Bug: the collision finder returned the SAME input twice. " +
        "This should never happen. Please report this lesson page as broken.",
    };
  }

  return {
    ok: true,
    value: {
      bday_collision_a: result.inputA,
      bday_collision_b: result.inputB,
      bday_collision_hash: result.hash,
      bday_attempts: result.attempts,
      bday_hash_bits: DEFAULT_HASH_BITS,
    },
  };
}

// ---- info ----------------------------------------------------------------

export function info(_input, _state) {
  return { ok: true, value: {} };
}

// ---- walkthroughs --------------------------------------------------------

export const walkthroughs = {
  find_collision: (_state) => [
    `**The setup:** SHA-256 produces a 256-bit digest. Truncate it to the first **16 bits** and you have a toy hash function whose output space is just 2^16 = 65,536 possible values. By the birthday bound, the EXPECTED work to find ANY two inputs that collide is ~1.18 * sqrt(2^16) ≈ 302 attempts. (Not 65,536 — that's the cost of finding an input that hits a SPECIFIC target.)`,
    `**The method:** Pure brute force. Generate a random 8-character string. Hash it with SHA-256. Keep the first 16 bits. Look that up in a Map of {hash -> input we already tried}. If it's already there, we found two distinct inputs with the same truncated hash — a collision. Otherwise, store it and keep going.`,
    `**What to watch for:** The attempt count when the page reports SUCCESS. Run it a few times. You'll see numbers like 80, 250, 400, 700 — all in the same ballpark as 256, almost never the full 65,536. That's the birthday bound made tangible. Now scale: 16-bit took ~256 work; 64-bit (4 billion) is a GPU-day; 80-bit needs a cluster; 128-bit (MD5) needed nation-state budget but it has been done. SHA-256 at 2^128 sqrt-work is still infeasible. **An n-bit hash gives only n/2 bits of collision resistance.** Pick hashes 2x bigger than your security target.`,
  ],
};
