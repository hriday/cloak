import { computeHmac, verifyHmac } from "./hmac_demo.js";

// Shared input checker. Returns null if ok, else a hint string.
function checkAsciiBounds(label, s) {
  if (s.length === 0) {
    return label === "key"
      ? "Type a secret key. Any non-empty string works for the demo."
      : "Type a message to MAC.";
  }
  if (s.length > 500) {
    return "Keep key and message under 500 printable ASCII characters.";
  }
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code < 32 || code > 126) {
      return `Only printable ASCII (no emoji, accents, tabs, or newlines). Found in ${label}: '${s[i]}'.`;
    }
  }
  return null;
}

// Step 5: compute HMAC. Input: {key, message}. On success writes
// hm_key + hm_message + hm_mac_hex so step 6 can verify against them.
export async function compute_hmac(input, _state) {
  const key = input?.key == null ? "" : String(input.key);
  const message = input?.message == null ? "" : String(input.message);

  const keyHint = checkAsciiBounds("key", key);
  if (keyHint) return { ok: false, hint: keyHint };
  const msgHint = checkAsciiBounds("message", message);
  if (msgHint) return { ok: false, hint: msgHint };

  // Compute via Web Crypto. In Node tests crypto.subtle may be missing —
  // degrade gracefully, matching the HSM lesson's pattern.
  let macHex = null;
  let cryptoError = null;
  try {
    if (typeof crypto !== "undefined" && crypto.subtle) {
      macHex = await computeHmac(key, message);
    }
  } catch (e) {
    cryptoError = String(e.message || e);
  }

  if (cryptoError) {
    return {
      ok: false,
      hint: "HMAC computation failed. This step requires a modern browser with Web Crypto.",
    };
  }

  return {
    ok: true,
    value: {
      hm_key: key,
      hm_message: message,
      hm_mac_hex: macHex,
    },
  };
}

// Step 6: verify-and-tamper. Input: {verifyAction: "verify" | "tamper"}.
// Reads hm_key, hm_message, hm_mac_hex from prior state. On "verify" we
// re-verify the unchanged message; on "tamper" we mutate one byte of the
// message, re-verify (should fail), and surface the tampered string.
// Writes hm_verify_result + hm_tampered + hm_tampered_message.
export async function verify_hmac(input, state) {
  const action = input?.verifyAction;
  if (action !== "verify" && action !== "tamper") {
    return { ok: false, hint: "Click Verify or Tamper." };
  }

  const key = state?.hm_key;
  const message = state?.hm_message;
  const macHex = state?.hm_mac_hex;
  if (!key || !message || !macHex) {
    return {
      ok: false,
      hint: "Complete step 5 first — we need a key and MAC to verify against.",
    };
  }

  // Determine what we're verifying.
  const tampered = action === "tamper";
  let messageToCheck = message;
  let tamperedMessage = null;
  if (tampered) {
    // Mutate one byte: flip the last character's low bit (printable ASCII
    // stays printable for almost all characters; if we'd leave printable
    // ASCII we fall back to replacing the last char with 'X' or 'Y').
    const lastIdx = message.length - 1;
    const lastChar = message.charCodeAt(lastIdx);
    let flipped = lastChar ^ 1;
    if (flipped < 32 || flipped > 126) {
      flipped = lastChar === 88 ? 89 : 88; // 'X' or 'Y'
    }
    tamperedMessage =
      message.slice(0, lastIdx) + String.fromCharCode(flipped);
    messageToCheck = tamperedMessage;
  }

  let verifyResult = null;
  let cryptoError = null;
  try {
    if (typeof crypto !== "undefined" && crypto.subtle) {
      verifyResult = await verifyHmac(key, messageToCheck, macHex);
    }
  } catch (e) {
    cryptoError = String(e.message || e);
  }

  if (cryptoError) {
    return {
      ok: false,
      hint: "Verification failed to run; refresh and retry.",
    };
  }

  return {
    ok: true,
    value: {
      hm_verify_result: verifyResult,
      hm_tampered: tampered,
      hm_tampered_message: tamperedMessage,
    },
  };
}

export function info(_input, _state) {
  return { ok: true, value: {} };
}

export const walkthroughs = {
  compute_hmac: (_state) => [
    `**The construction:** HMAC isn't \`H(key || message)\` — that's the broken naive MAC from step 2. The real definition is two nested hashes: \`HMAC(K, m) = H( (K' XOR opad) || H( (K' XOR ipad) || m ) )\`. \`K'\` is your key zero-padded out to the hash's block size (64 bytes for SHA-256), or hashed-then-padded if too long. \`ipad\` is the byte \`0x36\` repeated 64 times; \`opad\` is \`0x5C\` repeated 64 times.`,
    `**Why two hashes?** The inner hash \`H((K' XOR ipad) || m)\` produces a 32-byte digest. The outer hash sees only that digest — not the chaining state that produced it. A length-extension attacker who somehow learned the inner output still couldn't extend the message, because the outer hash starts fresh from a different prefix. Two layers, two different key-derived prefixes (\`ipad\` for inner, \`opad\` for outer), and Merkle-Damgard's vulnerability vanishes.`,
    `**Try this:** type any non-empty key and message. Web Crypto's \`subtle.importKey({name:"HMAC", hash:"SHA-256"})\` does the padding and the two-pass hashing for you; you get back a 64-hex-char (256-bit) MAC. The same (key, message) always produces the same MAC — that's what lets the receiver re-derive and compare. Change one bit of either input and the MAC changes completely (the avalanche property comes from SHA-256, not from HMAC).`,
  ],
};
