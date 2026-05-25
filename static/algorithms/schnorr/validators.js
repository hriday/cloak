import { sign, verify, generateKeypair } from "./schnorr_demo.js";

// Permissive validator for the Schnorr sign-and-verify step. Multi-mode
// dispatch by `op`. Shape mirrors the Ed25519 lesson's ed25519_operation
// exactly so the template branch can be shared (or sibling-branched).
//
// Input: { op: "sign" | "verify", message, signature? }
//   For sign: signs `message` with the page's resident keypair, returns R, s.
//   For verify: verifies a user-pasted signature against the page's public
//   key. `signature` is the JSON string "R,s" (two decimal integers) or
//   "{R,s}" — both forms accepted because the template may render either.
//
// State carries the toy keypair across steps. If state.schnorr_keypair_x
// isn't set yet, we generate one deterministically from a fixed seed so the
// public key in the lesson template matches what the tests assert.
//
// Exploratory by design — verify=false is information, not an error.
// ok:true with verdict on state so the wizard renders a pill (green
// "valid" / red "invalid") below the inputs.

// Fixed seed used the first time a user lands on the sign-and-verify step.
// Picked to give a "non-trivial" looking public key (not 1, not g, not g²)
// so the lesson feels like real crypto. Computed from the seed by
// generateKeypair: x = (SCHNORR_DEFAULT_SEED mod (Q-1)) + 1 = 100.
const SCHNORR_DEFAULT_SEED = 99n;

function parseSignature(raw) {
  if (typeof raw !== "string") return null;
  const cleaned = raw.replace(/[{}()\s]/g, "");
  if (!cleaned) return null;
  // Accept either "R,s" or "R=…,s=…" (best-effort tolerance).
  const parts = cleaned.split(/[,;]/).map((p) => p.replace(/^[Rs]=?/i, "").trim());
  if (parts.length !== 2) return null;
  if (!/^\d+$/.test(parts[0]) || !/^\d+$/.test(parts[1])) return null;
  return { R: BigInt(parts[0]), s: BigInt(parts[1]) };
}

function ensureKeypair(state) {
  if (state && state.schnorr_keypair_x != null && state.schnorr_keypair_X != null) {
    return { x: BigInt(state.schnorr_keypair_x), X: BigInt(state.schnorr_keypair_X) };
  }
  return generateKeypair(SCHNORR_DEFAULT_SEED);
}

export async function schnorr_operation(input, state) {
  const op = input?.op;
  const message = (input?.message ?? "").trim();
  const signatureRaw = (input?.signature ?? "").trim();

  if (op !== "sign" && op !== "verify") {
    return { ok: false, hint: "Pick an operation: sign or verify." };
  }
  if (!message) {
    return { ok: false, hint: "Type something to sign or verify." };
  }

  let parsedSig = null;
  if (op === "verify") {
    if (!signatureRaw) {
      return { ok: false, hint: "Verify needs the signature too — paste R,s from a prior sign." };
    }
    parsedSig = parseSignature(signatureRaw);
    if (!parsedSig) {
      return { ok: false, hint: "Signature should be two integers like \"R,s\" (the Sign step printed them above)." };
    }
  }

  // Toy-group sign/verify. Falls back gracefully when crypto.subtle isn't
  // available (Node tests without Web Crypto) — returns ok with null values
  // mirroring the Ed25519 fallback.
  let R = null, s = null, verifyResult = null, lhs = null, rhs = null, opError = null;
  const { x, X } = ensureKeypair(state);

  try {
    if (typeof crypto !== "undefined" && crypto.subtle) {
      if (op === "sign") {
        const sig = await sign(x, message);
        R = sig.R.toString();
        s = sig.s.toString();
      } else {
        const result = await verify(X, message, parsedSig);
        verifyResult = result.valid;
        lhs = result.lhs.toString();
        rhs = result.rhs.toString();
      }
    }
  } catch (e) {
    opError = String(e?.message || e);
  }

  return {
    ok: true,
    value: {
      schnorr_keypair_x: x.toString(),
      schnorr_keypair_X: X.toString(),
      schnorr_last_op: op,
      schnorr_last_input: message,
      schnorr_last_R: R,
      schnorr_last_s: s,
      schnorr_verify_result: verifyResult,
      schnorr_eq_lhs: lhs,
      schnorr_eq_rhs: rhs,
      schnorr_op_error: opError,
    },
  };
}

export function info(_input, _state) {
  return { ok: true, value: {} };
}

export const walkthroughs = {
  schnorr_operation: (_state) => [
    `**The method:** Schnorr sign is four lines on the toy group p=467, g=4, q=233. Pick a nonce \`k\`. Compute the commitment \`R = g^k mod 467\`. Hash to a challenge \`e = SHA-256(R ‖ X ‖ m) mod 233\`. Compute the response \`s = (k + e·x) mod 233\`. The signature is the pair (R, s) — two integers in the 0..466 range.`,
    `Try this: pick **Sign**, type 'hello', submit — the page prints \`R = …, s = …\`. Pick **Verify**, paste the same message and \`R,s\`, submit → 'valid'. Under the hood the page recomputed \`e\`, then checked \`g^s ≡ R · X^e (mod 467)\` — both sides shown so you can verify the algebra by hand on a calculator. Flip one digit of \`s\` and re-verify → 'invalid', the equation collapses.`,
    `**The point:** verification is one equation, \`g^s = R · X^e mod p\`. The signer is the only party who can produce a valid \`s\` because the equation requires the secret \`x = log_g X\` — and computing \`x\` from \`X\` is the discrete logarithm problem, which is the ~233-element-group version of the same hard problem secp256k1 leans on for Bitcoin Taproot. Same algorithm, bigger group, real money on top.`,
  ],
};
