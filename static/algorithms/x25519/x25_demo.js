// Web Crypto X25519 wrapper for the key-exchange lesson.
//
// Alice and Bob each generate a Curve25519 keypair, exchange public keys,
// and independently derive the same 32-byte shared secret. The whole point
// of the lesson is that both sides land on identical bytes — this module
// makes that happen and exposes the resulting hex for the page to render.
//
// Web Crypto X25519 is recent: Chrome 110+ (Feb 2023), Firefox 125+ (Apr
// 2024), Safari 17+ (Sep 2023). Older browsers throw on the generateKey
// call; this module catches that and falls back to the RFC 7748 §6.1
// canonical test vectors so the lesson still teaches the symmetry.
//
// The fallback hex below is not made-up: it's the worked example in the
// RFC, so even the bytes the learner sees are pedagogically grounded.

// RFC 7748 §6.1 canonical X25519 test vectors. The private keys are the
// exact strings from the RFC; the expected_shared is what both sides
// derive when you run the curve math on them.
export const RFC7748_FALLBACK = Object.freeze({
  alicePrivHex: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  alicePubHex:  "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
  bobPrivHex:   "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
  bobPubHex:    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
  sharedHex:    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
});

// Tag used on the Error thrown when Web Crypto X25519 isn't available.
// Callers can branch on this to choose between live keys and the fallback.
export const WEB_CRYPTO_UNAVAILABLE = "WEB_CRYPTO_UNAVAILABLE";

// Module-level holders for the two generated keypairs. Kept here so a page
// can call generateAlice() / generateBob() in separate awaits and then ask
// for the derived secret without juggling the CryptoKey objects.
let _alice = null;
let _bob   = null;

function _bytesToHex(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let out = "";
  for (let i = 0; i < arr.length; i++) {
    out += arr[i].toString(16).padStart(2, "0");
  }
  return out;
}

function _hasWebCryptoX25519() {
  return (
    typeof globalThis !== "undefined" &&
    typeof globalThis.crypto !== "undefined" &&
    globalThis.crypto.subtle &&
    typeof globalThis.crypto.subtle.generateKey === "function"
  );
}

async function _generateOne() {
  if (!_hasWebCryptoX25519()) {
    const e = new Error("Web Crypto X25519 not available in this environment");
    e.tag = WEB_CRYPTO_UNAVAILABLE;
    throw e;
  }
  try {
    return await crypto.subtle.generateKey(
      { name: "X25519" },
      true,            // extractable so we can show the public bytes
      ["deriveBits"]
    );
  } catch (err) {
    // Browser has crypto.subtle but no X25519 algorithm support (pre-Chrome 110, etc).
    const e = new Error(
      "Web Crypto rejected X25519 — browser likely too old. Original: " +
        (err && err.message ? err.message : String(err))
    );
    e.tag = WEB_CRYPTO_UNAVAILABLE;
    throw e;
  }
}

export async function generateAlice() {
  _alice = await _generateOne();
  return _alice;
}

export async function generateBob() {
  _bob = await _generateOne();
  return _bob;
}

async function _derive(privateKey, peerPublicKey) {
  // 256 bits = 32 bytes — the X25519 shared secret size.
  const bits = await crypto.subtle.deriveBits(
    { name: "X25519", public: peerPublicKey },
    privateKey,
    256
  );
  return _bytesToHex(new Uint8Array(bits));
}

export async function deriveSharedFromAlice() {
  if (!_alice || !_bob) {
    throw new Error("Generate both keypairs before deriving the shared secret");
  }
  return _derive(_alice.privateKey, _bob.publicKey);
}

export async function deriveSharedFromBob() {
  if (!_alice || !_bob) {
    throw new Error("Generate both keypairs before deriving the shared secret");
  }
  return _derive(_bob.privateKey, _alice.publicKey);
}

export async function exportPublic(side) {
  const pair = side === "alice" ? _alice : side === "bob" ? _bob : null;
  if (!pair) {
    throw new Error("Unknown side '" + side + "' — expected 'alice' or 'bob'");
  }
  const raw = await crypto.subtle.exportKey("raw", pair.publicKey);
  return _bytesToHex(new Uint8Array(raw));
}

// Convenience: generate both keypairs, derive the shared secret from each
// side, and assert agreement. Returns the four hex blobs plus a `match`
// flag (always true on the success path — if it ever flipped to false the
// underlying Web Crypto implementation would be broken). If Web Crypto
// X25519 isn't available, swaps to the RFC 7748 §6.1 fallback set so the
// page still has bytes to render.
export async function runExchange() {
  try {
    await generateAlice();
    await generateBob();
    const alicePubHex        = await exportPublic("alice");
    const bobPubHex          = await exportPublic("bob");
    const sharedHexFromAlice = await deriveSharedFromAlice();
    const sharedHexFromBob   = await deriveSharedFromBob();
    return {
      alicePubHex,
      bobPubHex,
      sharedHexFromAlice,
      sharedHexFromBob,
      match: sharedHexFromAlice === sharedHexFromBob,
      usedFallback: false,
    };
  } catch (err) {
    if (err && err.tag === WEB_CRYPTO_UNAVAILABLE) {
      // Reset module-level keypairs since generation failed.
      _alice = null;
      _bob   = null;
      const f = RFC7748_FALLBACK;
      return {
        alicePubHex:        f.alicePubHex,
        bobPubHex:          f.bobPubHex,
        sharedHexFromAlice: f.sharedHex,
        sharedHexFromBob:   f.sharedHex,
        match: true,
        usedFallback: true,
      };
    }
    throw err;
  }
}

// Test hook: lets the validator-fallback test reset module state between runs.
export function _reset() {
  _alice = null;
  _bob   = null;
}
