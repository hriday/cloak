import { sign, verify } from "./ed25_simulator.js";

// Permissive validator for the sign-and-verify step. Multi-mode dispatch
// by `op`. Shape mirrors the HSM lesson's hsm_operation exactly so the
// template branch can be shared (or sibling-branched).
//
// Input: { op: "sign" | "verify", message, signature? }
// On verify, signature must be 128 hex chars (64 bytes).
//
// Like hsm_operation, this is exploratory — verify=false is information,
// not an error. We return ok:true with the result on state so the wizard
// renders a pill (green "valid" / red "invalid") below the inputs.
export async function ed25519_operation(input, _state) {
  const op = input?.op;
  const message = (input?.message ?? "").trim();
  const signature = (input?.signature ?? "").trim().toLowerCase();

  if (op !== "sign" && op !== "verify") {
    return { ok: false, hint: "Pick an operation: sign or verify." };
  }
  if (!message) {
    return { ok: false, hint: "Type something to sign or verify." };
  }
  if (op === "verify") {
    if (!signature) {
      return { ok: false, hint: "Verify needs the signature too — paste the hex output from a prior sign." };
    }
    // Ed25519 signatures are always 64 bytes ⇒ 128 hex chars. Catching
    // the wrong-length case early gives a better error than letting
    // Web Crypto reject opaque bytes.
    if (!/^[0-9a-f]{128}$/.test(signature)) {
      return { ok: false, hint: "Ed25519 signatures are exactly 64 bytes (128 hex characters)." };
    }
  }

  // Run via the simulator. In Node test runs without crypto.subtle, degrade
  // gracefully — return ok with null values so unit tests don't need a
  // browser shim. Mirrors the HSM validator's no-crypto fallback.
  let lastSignature = null;
  let verifyResult = null;
  let opError = null;
  try {
    if (typeof crypto !== "undefined" && crypto.subtle) {
      if (op === "sign") {
        lastSignature = await sign(message);
      } else {
        try {
          verifyResult = await verify(message, signature);
        } catch (e) {
          // Malformed hex bytes or Web Crypto rejected the signature —
          // present as "invalid" rather than exposing the raw error.
          verifyResult = false;
        }
      }
    }
  } catch (e) {
    opError = String(e?.message || e);
  }

  return {
    ok: true,
    value: {
      ed25_last_op: op,
      ed25_last_input: message,
      ed25_last_signature: lastSignature,
      ed25_verify_result: verifyResult,
      ed25_op_error: opError,
    },
  };
}

export function info(_input, _state) {
  return { ok: true, value: {} };
}

export const walkthroughs = {
  ed25519_operation: (_state) => [
    `**The method:** Ed25519 produces a 64-byte signature from your private key and the message. The signature is *deterministic* — the same key + same message always produces the same bytes. That's the design's response to the Sony PS3 ECDSA disaster, where reusing one random nonce across two signatures let attackers recover the console signing key. Ed25519 derives its nonce from \`SHA-512(prefix ‖ message) mod L\` — no RNG, no nonce reuse possible.`,
    `Try this: pick **Sign**, type 'hello', click Check. The output is 128 hex chars (exactly 64 bytes — small!). Now pick **Verify**, paste the same 'hello' and the signature → 'valid'. Flip one hex character of the signature → 'invalid'. Same key, same message, same bytes every time — try signing 'hello' twice and you'll get identical output.`,
    `**The point:** anyone with the public key (64 hex chars above) can verify your signature; only you (with the private key) can produce one. That's the asymmetric property that separates a signature from a MAC — MAC verification needs the shared secret. SSH (default key type since 2014), Git commit signing, Solana, Cardano, NEAR, and JWT-EdDSA all use these same 64-byte signatures. The math walked in steps 2–4 is the same code path running in your browser right now.`,
  ],
};
