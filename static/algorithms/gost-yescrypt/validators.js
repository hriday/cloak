// gost-yescrypt lesson validators.
//
// Step 4 (spot-the-difference) — spot_difference. The step's prompt shows
// the same password hashed as $y$ and $gy$ with identical salt + params;
// the learner picks which field actually changed. Input is one of the
// three button values (a plain string via inputValue).

const CORRECT = "prefix-and-hash";

export function spot_difference(input, _state) {
  const choice = String(input ?? "").trim();
  if (!choice) return { ok: false, hint: "Pick one of the three options." };
  if (choice === "salt") {
    return {
      ok: false,
      hint: "Look again — both strings carry the exact same salt field. The salt doesn't care which hash function mixes it.",
    };
  }
  if (choice === "params") {
    return {
      ok: false,
      hint: "Both strings say j9T — same N, same r, same 16 MiB. The GOST wrapper changes the hash function, not the memory-hardness parameters.",
    };
  }
  if (choice !== CORRECT) {
    return { ok: false, hint: "Pick one of the three options." };
  }
  return { ok: true, value: { gy_choice: choice } };
}

export function info(_input, _state) {
  return { ok: true, value: {} };
}

export const walkthroughs = {
  spot_difference: (_state) => [
    `**What changed:** the method prefix (\`$y$\` → \`$gy$\`) and every byte of the final hash field. gost-yescrypt runs the same yescrypt engine, then keys an HMAC built from Streebog (GOST R 34.11-2012) into the result — different outer function, different output bytes.`,
    `**What didn't:** salt and params. Compliance wrappers deliberately leave the cost machinery alone — that's the whole trick: satisfy the regulator by using the national-standard hash, keep the battle-tested KDF underneath.`,
  ],
};
