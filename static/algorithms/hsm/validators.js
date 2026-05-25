import { sign, verify } from "./hsm_simulator.js";
import * as pinSim from "./pin_translation.js";

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

// Permissive validator for the pin-translation step. Like hsm_operation, this
// is exploratory — there's no "wrong" PIN, the user is demonstrating the
// zone-translation pattern. We always return ok:true on parseable input so
// the wizard shows the result panel (success or error) below the inputs.
export async function pin_translation(input, _state) {
  // Tolerate either a bare PIN string or a {pin, pan} object.
  let pin, pan;
  if (typeof input === "string") {
    pin = input;
    pan = "4111111111111111";
  } else if (input && typeof input === "object") {
    pin = (input.pin ?? "").toString().trim();
    pan = (input.pan ?? "").toString().trim() || "4111111111111111";
  } else {
    return { ok: false, hint: "PIN must be 4–12 digits." };
  }

  if (!/^\d{4,12}$/.test(pin)) {
    return { ok: false, hint: "PIN must be 4–12 digits." };
  }
  if (!/^\d{13,19}$/.test(pan)) {
    return { ok: false, hint: "PAN must be 13–19 digits." };
  }

  // Run the simulator. In Node tests crypto.subtle may be missing — degrade
  // gracefully so unit tests don't require a browser shim.
  let tpkCt = null, zpk1Ct = null, zpk2Ct = null;
  let matched = null;
  let fps = null;
  let pinError = null;
  try {
    if (typeof crypto !== "undefined" && crypto.subtle) {
      await pinSim.ensureZoneKeys();
      const block = pinSim.buildPinBlock(pin, pan);
      tpkCt = await pinSim.terminalEncrypt(block);
      zpk1Ct = await pinSim.translate(tpkCt, "tpk", "zpk1");
      zpk2Ct = await pinSim.translate(zpk1Ct, "zpk1", "zpk2");
      matched = await pinSim.issuerVerify(zpk2Ct, pin, pan);
      fps = await pinSim.keyFingerprints();
    }
  } catch (e) {
    pinError = String(e.message || e);
    tpkCt = null;
    zpk1Ct = null;
    zpk2Ct = null;
    matched = null;
    fps = null;
  }

  return {
    ok: true,
    value: {
      pin_value: pin,
      pin_pan: pan,
      pin_terminal_ct: tpkCt,
      pin_zpk1_ct: zpk1Ct,
      pin_zpk2_ct: zpk2Ct,
      pin_verify_result: matched,
      pin_keys: fps,
      pin_error: pinError,
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
  pin_translation: (_state) => [
    `**The PIN block:** ISO 9564 Format 0 packs your PIN into 8 bytes by XOR-ing two fields. The first is \`0L PPPP...FFF\` — a format marker, the PIN length, the PIN digits, and F-padding to 16 nibbles. The second is the rightmost 12 digits of the PAN (excluding the check digit), zero-prefixed. XOR-ing them means the same PIN on a different card produces a different block — so an attacker who steals one encrypted PIN block can't replay it on another account.`,
    `**Why three keys?** PCI DSS requires that each "zone" between parties use a different key. The terminal and the acquirer share TPK. The acquirer and the network share ZPK1. The network and the issuer share ZPK2. The acquirer HSM decrypts under TPK and immediately re-encrypts under ZPK1 in a single operation — the cleartext PIN block exists only inside the HSM for microseconds. Same at the network boundary. The issuer is the only party that ever sees the PIN in cleartext, and only long enough to compare.`,
    `**Real hardware:** On a Thales payShield 10K or Atalla AT1000, this translation runs entirely inside a FIPS 140-2 Level 3 tamper-evident enclosure. The cleartext PIN block never crosses the silicon boundary — it lives in tamper-reactive SRAM that zeroizes if the case is opened, the temperature changes, or the voltage glitches. The HSM exposes the translate command but offers no "decrypt and return cleartext" primitive at all, no matter what credentials you present. We're using AES-CBC with a zero IV in the browser; production uses 3DES with DUKPT (per-transaction keys) and a fresh IV per operation.`,
  ],
};
