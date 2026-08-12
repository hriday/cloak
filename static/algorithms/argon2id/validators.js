// argon2id lesson validators.
//
// Step 4 (feel-the-memory) — memory_cost: same toy mixer as the yescrypt
// lesson (imported from ../yescrypt/memhard_demo.js — see that header for
// what is and isn't real), writing a2_* state keys.
// Step 6 (tuning) — tuning_math: pure arithmetic on the m/t/p parameters.

import { mixMemory, ALLOWED_MEMORY_MIB, CITED_ARGON2ID_MS } from "../yescrypt/memhard_demo.js";

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
      a2_password: password,
      a2_memory_mib: memoryMiB,
      a2_blocks: result.blocks,
      a2_bytes_touched: result.bytesTouched,
      a2_ms: result.ms,
      a2_digest: result.digestHex,
      a2_cited_real_ms: CITED_ARGON2ID_MS[memoryMiB] ?? null,
    },
  };
}

// Step 6 — the RAM bill for m=65536 KiB, t=3, p=4. The teaching point:
// m is the TOTAL memory regardless of t (extra passes over the same
// memory) and p (lanes split it, they don't multiply it).
export function tuning_math(input, _state) {
  const raw = String(input ?? "").trim();
  const v = Number(raw);
  if (raw === "" || !Number.isFinite(v)) {
    return { ok: false, hint: "Enter a number of MiB." };
  }
  if (v === 65536) {
    return { ok: false, hint: "That's the raw m value — but m counts KiB. Convert to MiB." };
  }
  if (v !== 64) {
    return {
      ok: false,
      hint: "m = 65536 KiB total. 65536 / 1024 = ? MiB. (t re-walks the same memory; p splits it into lanes — neither adds RAM.)",
    };
  }
  return { ok: true, value: { a2_tuning_mib: 64 } };
}

export function info(_input, _state) {
  return { ok: true, value: {} };
}

export const walkthroughs = {
  memory_cost: (_state) => [
    `**The construction:** argon2 fills m KiB of 1-KiB blocks (arranged in p lanes), then re-mixes them for t passes, each block mixed via Blake2b from a previous block and a reference block. In argon2**id**, reference indexes are data-independent for the first half-pass (side-channel safety), data-dependent after (cracking resistance). The widget really allocates and touches your chosen memory; the mixing function is a toy — the cited column has real argon2-cffi numbers (t=3, p=4).`,
    `**Try this:** 1 MiB vs 64 MiB — roughly linear scaling. Then compare the cited column against bcrypt's cost-12 ~260 ms: argon2id at 64 MiB costs an attacker 64 MiB of RAM *per guess in flight*, which is what melts GPU cracking farms.`,
  ],
  tuning_math: (_state) => [
    `**The three knobs:** m (memory, KiB) is the security workhorse; t (passes) adds time without RAM; p (lanes) adds parallelism within one hash. RAM per login = m, full stop. 65536 KiB / 1024 = **64 MiB** — multiply by your peak concurrent logins before you copy OWASP's numbers onto a small VPS.`,
  ],
};
