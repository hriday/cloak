// yescrypt lesson validators.
//
// Step 3 (feel-the-memory) — memory_cost. Input: {password, memoryMiB}.
// Runs the toy mixer from memhard_demo.js (which really allocates and
// touches the memory — see that file's header for what is and isn't real),
// captures wall time, writes ys_* state keys. All other steps use the
// info validator (always ok).

import { mixMemory, ALLOWED_MEMORY_MIB, CITED_YESCRYPT_MS } from "./memhard_demo.js";

// Same guard shape as bcrypt's checkPassword so the hash-family lessons
// feel consistent.
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

export function memory_cost(input, _state) {
  const password = input?.password == null ? "" : String(input.password);
  const hint = checkPassword(password);
  if (hint) return { ok: false, hint };

  const memoryMiB = Number(input?.memoryMiB);
  if (!ALLOWED_MEMORY_MIB.includes(memoryMiB)) {
    return {
      ok: false,
      hint: `Pick a memory size from the buttons (${ALLOWED_MEMORY_MIB.join(", ")} MiB).`,
    };
  }

  const result = mixMemory(password, memoryMiB);
  if (result.allocationFailed) {
    return {
      ok: false,
      hint: "Your browser refused the memory allocation — pick a smaller size.",
    };
  }

  return {
    ok: true,
    value: {
      ys_password: password,
      ys_memory_mib: memoryMiB,
      ys_blocks: result.blocks,
      ys_bytes_touched: result.bytesTouched,
      ys_ms: result.ms,
      ys_digest: result.digestHex,
      ys_cited_real_ms: CITED_YESCRYPT_MS[memoryMiB] ?? null,
    },
  };
}

export function info(_input, _state) {
  return { ok: true, value: {} };
}

export const walkthroughs = {
  memory_cost: (_state) => [
    `**The construction:** scrypt (and yescrypt after it) forces two passes over a big array: fill it sequentially, then read it back in a data-dependent random order. The widget really does both passes over the memory size you pick — watch **bytes touched** double the memory size. What's toy here is the mixing function; the cited column shows real libxcrypt yescrypt timings for the same memory.`,
    `**Try this:** run 1 MiB, then 64 MiB. Time should scale roughly linearly with memory — that's the point. A GPU cracker with 10,000 cores doesn't have 10,000 × 64 MiB of fast RAM per core, so the memory knob hurts attackers far more than the CPU-time knob bcrypt offers.`,
    `**Practical numbers:** libxcrypt's default (the \`j9T\` you'll see in step 4) is 16 MiB and ~50 ms per login on a 2024 laptop. Nobody notices at login; a cracking rig notices immediately.`,
  ],
};
