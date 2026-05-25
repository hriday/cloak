// RSA-PSS simulator: a thin Web Crypto wrapper.
//
// PKCS#1 v2.1 / RFC 8017 EMSA-PSS-encoded RSA signatures. Web Crypto has
// shipped RSA-PSS in every major browser since ~2017 (much earlier than
// Ed25519), but we still surface a WEB_CRYPTO_UNAVAILABLE sentinel for
// the no-subtle Node test path so callers can render a fallback panel.
//
// Unlike Ed25519, RSA keygen is expensive (~100ms for 2048-bit on a
// modern laptop) — we generate exactly once at module scope and cache
// the promise so the rest of the page reuses the same keypair. The
// private key is extractable for parity with the Ed25519 lesson, though
// we never actually export it.

export const WEB_CRYPTO_UNAVAILABLE = "WEB_CRYPTO_UNAVAILABLE";

// PSS parameters — RFC 8017 §9.1. SHA-256 hash, 32-byte salt (matches
// the hash length, the modern default; pyca's `cryptography` library
// uses the same when you pass `salt_length=32`).
const HASH = "SHA-256";
const SALT_LENGTH = 32;
const MODULUS_LENGTH = 2048;

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
      {
        name: "RSA-PSS",
        modulusLength: MODULUS_LENGTH,
        // F4 / 65537. Standard public exponent; the only one Web Crypto
        // actually accepts in practice. Big-endian byte representation.
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: HASH,
      },
      true,                           // extractable — we want to export the public key
      ["sign", "verify"]
    );
  } catch (e) {
    // Any failure from the engine — surface a sentinel so the caller
    // can render a "your browser doesn't support this" fallback panel.
    const err = new Error(WEB_CRYPTO_UNAVAILABLE);
    err.cause = e;
    throw err;
  }
}

// Idempotent. First call generates and caches the keypair; subsequent
// calls return the same one. Throws WEB_CRYPTO_UNAVAILABLE on engines
// without crypto.subtle. Returns the hex of the SubjectPublicKeyInfo
// (SPKI) export — that's what `openssl rsa -pubout` produces and what
// you'd paste into a TLS cert config.
export async function ensureKeypair() {
  if (!_keypairPromise) {
    _keypairPromise = generate().catch((e) => {
      // Clear cache so a later call can retry (useful in tests).
      _keypairPromise = null;
      throw e;
    });
  }
  const { publicKey } = await _keypairPromise;
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", publicKey));
  return { publicKeyHex: bytesToHex(spki) };
}

// Sign a UTF-8 string. Returns 512-char hex (256-byte signature for a
// 2048-bit key — always equal to modulus length / 8, regardless of
// message length or salt length).
//
// IMPORTANT: RSA-PSS is probabilistic. Same key + same message ⇒
// different signature every call, because the salt is fresh from
// crypto.getRandomValues each time. Verifiers extract the salt from the
// decrypted signature; they never need to be told what it was.
export async function sign(message) {
  await ensureKeypair();
  const { privateKey } = await _keypairPromise;
  const data = new TextEncoder().encode(message);
  const sig = await crypto.subtle.sign(
    { name: "RSA-PSS", saltLength: SALT_LENGTH },
    privateKey,
    data
  );
  return bytesToHex(new Uint8Array(sig));
}

// Verify a UTF-8 message + hex signature. Returns boolean.
// Throws if the hex is malformed — callers should catch and render
// "invalid". On Web Crypto, RSA-PSS verify returns false (not throw)
// for cryptographically-invalid signatures of correct length; only
// malformed *byte* inputs raise.
export async function verify(message, sigHex) {
  await ensureKeypair();
  const { publicKey } = await _keypairPromise;
  const data = new TextEncoder().encode(message);
  const sigBytes = hexToBytes(sigHex);
  return await crypto.subtle.verify(
    { name: "RSA-PSS", saltLength: SALT_LENGTH },
    publicKey,
    sigBytes,
    data
  );
}

// Hex of the SubjectPublicKeyInfo (SPKI) export of the public key.
// For a 2048-bit RSA key this is ~294 bytes (~588 hex chars) — the
// DER-encoded structure that wraps the bare (n, e) tuple with an
// AlgorithmIdentifier header. Same encoding as `openssl rsa -pubout`.
export async function publicKeyHex() {
  const { publicKeyHex: hex } = await ensureKeypair();
  return hex;
}

// Test-only: reset the cached keypair. Not exported for browser use.
export function _resetForTests() {
  _keypairPromise = null;
}
