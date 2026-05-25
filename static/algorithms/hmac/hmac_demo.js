// HMAC demo helpers.
//
// Web Crypto wrapper: HMAC-SHA256 compute + verify. Plus a SIMULATED
// length-extension attack used by the lesson's step-3 widget.
//
// On simulation: A real Merkle-Damgard length extension takes only the
// original MAC and the original-message length — the attacker never sees
// the key. We can't ship a faithful exploit in the browser because Web
// Crypto's SHA-256 won't expose the chaining state mid-compression. So the
// "attack" here cheats: the page already holds the secret (it's the
// demonstrator), so simulateLengthExtension() honestly computes
// SHA-256(key || originalMessage || extension). The output the user sees —
// "a valid forged MAC on extended data, produced without the server's
// blessing" — is exactly what a real attacker produces. Only the under-the-
// hood mechanic is fudged. Lesson copy MUST disclose this.

function bytesToHex(arr) {
  return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  const clean = String(hex || "").replace(/\s+/g, "").toLowerCase();
  if (!/^[0-9a-f]*$/.test(clean) || clean.length % 2 !== 0) {
    throw new Error("invalid hex");
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    out[i / 2] = parseInt(clean.slice(i, i + 2), 16);
  }
  return out;
}

async function importHmacKey(keyString) {
  const keyBytes = new TextEncoder().encode(keyString);
  return await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

// Compute HMAC-SHA256(key, message). Returns lowercase hex.
export async function computeHmac(key, message) {
  const cryptoKey = await importHmacKey(key);
  const data = new TextEncoder().encode(message);
  const sig = await crypto.subtle.sign({ name: "HMAC" }, cryptoKey, data);
  return bytesToHex(new Uint8Array(sig));
}

// Verify HMAC-SHA256(key, message) ?= macHex. Returns boolean.
export async function verifyHmac(key, message, macHex) {
  let sigBytes;
  try {
    sigBytes = hexToBytes(macHex);
  } catch {
    return false;
  }
  const cryptoKey = await importHmacKey(key);
  const data = new TextEncoder().encode(message);
  return await crypto.subtle.verify({ name: "HMAC" }, cryptoKey, sigBytes, data);
}

// SIMULATED length-extension attack. See file header for the simplification.
// Returns: {
//   originalMessage, originalMac,            // what the attacker started with
//   extension,                               // what they wanted to append
//   forgedMessage, forgedMac,                // the forgery they'd produce
//   simulated: true,                         // honesty flag for the UI
//   construction: "naive H(key || message)", // the broken MAC we're attacking
// }
//
// The lesson uses this to illustrate why H(key || m) is not a MAC: a real
// attacker — with NEITHER the key NOR access to honestly compute the
// extended hash — can still produce forgedMac, because Merkle-Damgard's
// internal state IS the output. We're faking the mechanic, not the outcome.
export async function simulateLengthExtension(originalMessage, originalMac, extension, secretKey) {
  const forgedMessage = String(originalMessage) + String(extension);
  // The "naive MAC" the lesson attacks is SHA-256(key || message). Compute
  // honestly here, since the wizard holds the key.
  const keyBytes = new TextEncoder().encode(String(secretKey));
  const msgBytes = new TextEncoder().encode(forgedMessage);
  const combined = new Uint8Array(keyBytes.length + msgBytes.length);
  combined.set(keyBytes, 0);
  combined.set(msgBytes, keyBytes.length);
  const digest = await crypto.subtle.digest("SHA-256", combined);
  const forgedMac = bytesToHex(new Uint8Array(digest));
  return {
    originalMessage: String(originalMessage),
    originalMac: String(originalMac),
    extension: String(extension),
    forgedMessage,
    forgedMac,
    simulated: true,
    construction: "naive H(key || message)",
  };
}

// Helper for the defender side of the length-extension demo: compute the
// naive MAC honestly given a key + message.
export async function naiveMac(key, message) {
  const keyBytes = new TextEncoder().encode(String(key));
  const msgBytes = new TextEncoder().encode(String(message));
  const combined = new Uint8Array(keyBytes.length + msgBytes.length);
  combined.set(keyBytes, 0);
  combined.set(msgBytes, keyBytes.length);
  const digest = await crypto.subtle.digest("SHA-256", combined);
  return bytesToHex(new Uint8Array(digest));
}
