// Ed25519 simulator: a thin Web Crypto wrapper.
//
// Web Crypto added native Ed25519 in Chrome 110, Safari 17, Firefox 130
// (Sept 2024). Older browsers throw on generateKey — call ensureKeypair()
// up front so the caller can fall back gracefully.
//
// Unlike the HSM lesson, the private key here is EXTRACTABLE — Ed25519 is
// being taught as a signature primitive, not as a vault, so there's no
// pedagogical reason to lock it down. The (still ephemeral) keypair lives
// at module scope and is reused across sign / verify calls for the duration
// of the page session.

export const WEB_CRYPTO_UNAVAILABLE = "WEB_CRYPTO_UNAVAILABLE";

let _keypairPromise = null;

function bytesToHex(arr) {
  return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  const clean = hex.replace(/\s+/g, "").toLowerCase();
  if (!/^[0-9a-f]*$/.test(clean) || clean.length % 2 !== 0) {
    throw new Error("invalid hex");
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    out[i / 2] = parseInt(clean.slice(i, i + 2), 16);
  }
  return out;
}

async function generate() {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    throw new Error(WEB_CRYPTO_UNAVAILABLE);
  }
  try {
    return await crypto.subtle.generateKey(
      { name: "Ed25519" },
      true,                   // extractable — we want to show the public key as hex
      ["sign", "verify"]
    );
  } catch (e) {
    // Older Chromium, Firefox <130, Safari <17 — surface a sentinel so the
    // caller can render a "needs a 2024+ browser" fallback panel.
    const err = new Error(WEB_CRYPTO_UNAVAILABLE);
    err.cause = e;
    throw err;
  }
}

// Idempotent. First call generates and caches the keypair; subsequent calls
// return the same one. Throws WEB_CRYPTO_UNAVAILABLE if Ed25519 isn't
// supported in this runtime.
export async function ensureKeypair() {
  if (!_keypairPromise) {
    _keypairPromise = generate().catch((e) => {
      // Clear cache so a later call can retry (useful in tests).
      _keypairPromise = null;
      throw e;
    });
  }
  const { publicKey } = await _keypairPromise;
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", publicKey));
  return { publicKeyHex: bytesToHex(raw) };
}

// Sign a UTF-8 string. Returns 128-char hex (64-byte signature).
export async function sign(message) {
  await ensureKeypair();
  const { privateKey } = await _keypairPromise;
  const data = new TextEncoder().encode(message);
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, privateKey, data);
  return bytesToHex(new Uint8Array(sig));
}

// Verify a UTF-8 message + hex signature. Returns boolean.
// Throws if the hex is malformed — callers should catch and render "invalid".
export async function verify(message, sigHex) {
  await ensureKeypair();
  const { publicKey } = await _keypairPromise;
  const data = new TextEncoder().encode(message);
  const sigBytes = hexToBytes(sigHex);
  return await crypto.subtle.verify({ name: "Ed25519" }, publicKey, sigBytes, data);
}

// Hex of the 32-byte raw public key.
export async function publicKeyHex() {
  const { publicKeyHex: hex } = await ensureKeypair();
  return hex;
}

// Test-only: reset the cached keypair. Not exported for browser use.
export function _resetForTests() {
  _keypairPromise = null;
}
