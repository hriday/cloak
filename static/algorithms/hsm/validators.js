import { sign, verify } from "./hsm_simulator.js";

// Permissive validator for the simulated-hsm step. There's no "right answer";
// this is an exploratory step. The validator runs the user's chosen operation
// and writes the result to state for display.
export async function hsm_operation(input, _state) {
  const op = input?.op;
  const message = (input?.message ?? "").trim();
  const signature = (input?.signature ?? "").trim();

  if (op !== "sign" && op !== "verify") {
    return { ok: false, hint: "Pick an operation: sign or verify." };
  }
  if (!message) {
    return { ok: false, hint: "Type a message — can't sign or verify an empty string." };
  }
  if (op === "verify" && !signature) {
    return { ok: false, hint: "Verify needs the signature too — paste the hex output from a prior sign." };
  }

  // Run the operation against the simulated vault. In Node tests, crypto.subtle
  // may not be available — degrade gracefully so validation tests still pass.
  let output = null;
  let verifyResult = null;
  let opError = null;
  try {
    if (typeof crypto !== "undefined" && crypto.subtle) {
      if (op === "sign") {
        output = await sign(message);
      } else {
        verifyResult = await verify(message, signature);
        output = verifyResult ? "valid" : "invalid";
      }
    }
  } catch (e) {
    opError = String(e.message || e);
  }

  return {
    ok: true,
    value: {
      hsm_last_op: op,
      hsm_last_input: message,
      hsm_last_output: output,
      hsm_verify_result: verifyResult,
      hsm_op_error: opError,
    },
  };
}

export async function pick_hsm_message(input, _state) {
  const s = input == null ? "" : String(input);
  if (s.length === 0) return { ok: false, hint: "Type at least one character." };
  if (s.length > 500) return { ok: false, hint: "Keep it under 500 characters." };
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code < 32 || code > 126) {
      return { ok: false, hint: `Only printable ASCII for now — no emoji, accents, tabs, or newlines. Found: '${s[i]}'.` };
    }
  }
  return { ok: true, value: { hsm_message: s } };
}

export function info(_input, _state) {
  return { ok: true, value: {} };
}

export const walkthroughs = {
  hsm_operation: (_state) => [
    `**The method:** The simulated HSM holds an RSA-PSS keypair that was generated with extractable:false — meaning Web Crypto refuses to ever export the private key. You can ask the vault to sign with it (your input goes in, a signature comes out). You can ask it to verify a signature. You cannot ask "what's the private key?" — that API doesn't exist.`,
    `Try this: pick 'sign', type 'hello', click Check. The output is a hex signature ~512 chars long (2048-bit RSA). Then pick 'verify', paste the same 'hello' + the signature → 'valid'. Change one character in the message or signature → 'invalid'.`,
    `**The point:** real HSMs enforce this property in hardware (tamper-evident chips that zeroize keys if pried open). Web Crypto's extractable:false is the same idea at the API level. Even with full devtools access in this browser, you cannot recover the private key from this lesson's vault.`,
  ],
};
