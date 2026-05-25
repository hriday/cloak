import { sign, verify } from "./rsapss_simulator.js";

// Permissive validator for the RSA-PSS sign-and-verify step. Multi-mode
// dispatch by `op`. Same shape as the Ed25519 validator so the wizard
// template branch can be shared (or sibling-branched).
//
// Input: { op: "sign" | "verify", message, signature? }
// On verify, signature must be 512 hex chars (256 bytes — fixed length
// equal to modulus / 8 for a 2048-bit RSA key, regardless of message
// length or salt).
//
// Exploratory: verify=false is information, not an error. We return
// ok:true with the result on state so the wizard renders a pill (green
// "valid" / red "invalid") below the inputs.
export async function rsapss_operation(input, _state) {
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
    // RSA-PSS-2048 signatures are always 256 bytes ⇒ 512 hex chars.
    // Catching the wrong-length case early gives a better error than
    // letting Web Crypto reject opaque bytes.
    if (!/^[0-9a-f]{512}$/.test(signature)) {
      return { ok: false, hint: "RSA-PSS-2048 signatures are exactly 256 bytes (512 hex characters)." };
    }
  }

  // Run via the simulator. In Node test runs without crypto.subtle, degrade
  // gracefully — return ok with null values so unit tests don't need a
  // browser shim. Mirrors the Ed25519 validator's no-crypto fallback.
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
      rsapss_last_op: op,
      rsapss_last_input: message,
      rsapss_signature: lastSignature,
      rsapss_verify_result: verifyResult,
      rsapss_op_error: opError,
    },
  };
}

export function info(_input, _state) {
  return { ok: true, value: {} };
}

export const walkthroughs = {
  rsapss_operation: (_state) => [
    `**The method:** RSA-PSS produces a 256-byte signature (for a 2048-bit modulus) regardless of input length. Internally: hash the message with SHA-256, mix it with a 32-byte random *salt* into the EMSA-PSS encoded message, raise that block to the private exponent mod n. The signature is *probabilistic* — the fresh salt makes every call produce different bytes. That's the modern fix for PKCS#1 v1.5's deterministic padding, which fed the Bleichenbacher class of attacks.`,
    `Try this: pick **Sign**, type 'hello', click Check. The output is 512 hex chars (256 bytes — 4× larger than an Ed25519 signature). Click Sign **again** with the same message → totally different hex! Same key, same input, fresh salt. Now pick **Verify**, paste either signature with the same message → 'valid'. Flip one hex character → 'invalid'. The verifier extracts the salt from the decrypted signature; it never needed to be told what it was.`,
    `**The point:** RSA-PSS is what TLS uses when you see \`rsa_pss_rsae_sha256\` in a TLS 1.3 CertificateVerify. 80%+ of server certs on the public web in 2025 are RSA, and PSS is the only RSA signature padding TLS 1.3 actually allows — the old PKCS#1 v1.5 sign is forbidden. The RSA primitive \`sig = EM^d mod n\` is identical to textbook RSA from step 2; the *padding* is what makes it secure. Ed25519 (next lesson over) is the deterministic alternative — same job, ~40× smaller keys.`,
  ],
};
