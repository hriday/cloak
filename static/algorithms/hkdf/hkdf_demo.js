// HKDF demo helpers (RFC 5869).
//
// HKDF = Extract-then-Expand. Extract turns a possibly-non-uniform input
// keying material (IKM) — e.g. a raw X25519 shared secret — into a uniform
// pseudo-random key (PRK). Expand uses that PRK plus a per-purpose `info`
// string to derive any number of independent output keys of any length.
//
// API exposed to the lesson:
//   extract(salt, ikm)            → PRK as hex  (32 bytes for SHA-256)
//   expand(prkHex, info, length)  → OKM as hex  (length bytes)
//   hkdf(ikm, salt, info, length) → OKM as hex  (single-shot, used by tests
//                                                against RFC 5869 vectors)
//   deriveTlsKeys(seed)           → {clientKey, serverKey, clientIv,
//                                    serverIv} — the lesson's interactive
//                                    step. Deterministic from `seed`.
//
// Why a hand-rolled HMAC loop for Expand instead of Web Crypto's HKDF?
// Web Crypto's `{name:"HKDF"}` is Extract+Expand in one shot — it always
// runs the HMAC(salt, ikm) prefix step. So we can't reuse it to do "expand
// only" with a PRK that's already been extracted. HMAC, on the other hand,
// is universally supported. We use it for both extract (one HMAC) and the
// iteration that makes up expand (one HMAC per 32-byte block). For the
// single-shot `hkdf()` we prefer Web Crypto's HKDF when present (matches
// the RFC 5869 test-vector path exactly), falling back to the manual
// extract+expand path otherwise. Both routes agree on the same output.

const SHA256_OUT = 32; // HMAC-SHA256 output, in bytes.

// ---------- hex / bytes helpers --------------------------------------------

function _bytesToHex(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let out = "";
  for (let i = 0; i < arr.length; i++) {
    out += arr[i].toString(16).padStart(2, "0");
  }
  return out;
}

function _hexToBytes(hex) {
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

function _toBytes(input) {
  if (input == null) return new Uint8Array(0);
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (typeof input === "string") return new TextEncoder().encode(input);
  throw new Error("unsupported byte source: " + typeof input);
}

function _concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

// ---------- low-level HMAC primitive ----------------------------------------

function _hasSubtle() {
  return (
    typeof globalThis !== "undefined" &&
    typeof globalThis.crypto !== "undefined" &&
    globalThis.crypto.subtle &&
    typeof globalThis.crypto.subtle.sign === "function"
  );
}

async function _hmacSha256(keyBytes, dataBytes) {
  if (!_hasSubtle()) {
    throw new Error("Web Crypto HMAC unavailable in this environment");
  }
  // HMAC keys can be any byte length; Web Crypto handles the K-prime padding.
  // Zero-length keys are legal here — RFC 5869's Extract uses salt = HashLen
  // zeros when no salt is provided, and HMAC accepts that fine.
  const safeKey = keyBytes.length === 0 ? new Uint8Array(SHA256_OUT) : keyBytes;
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    safeKey,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign({ name: "HMAC" }, cryptoKey, dataBytes);
  return new Uint8Array(sig);
}

// ---------- extract --------------------------------------------------------

// RFC 5869 §2.2:  PRK = HMAC-Hash(salt, IKM)
// If `salt` is missing/empty, the RFC says to use a string of HashLen zeros.
// `salt` and `ikm` may be Uint8Array, ArrayBuffer, or string (UTF-8 encoded).
export async function extract(salt, ikm) {
  const saltBytes = _toBytes(salt);
  const ikmBytes  = _toBytes(ikm);
  const prk = await _hmacSha256(saltBytes, ikmBytes);
  return _bytesToHex(prk);
}

// ---------- expand ---------------------------------------------------------

// RFC 5869 §2.3:
//   N = ceil(L / HashLen)
//   T(0) = empty
//   T(i) = HMAC-Hash(PRK, T(i-1) || info || octet(i))   for i = 1..N
//   OKM  = first L bytes of (T(1) || T(2) || ... || T(N))
//
// PRK must be hex (the lesson always carries PRK around as hex); `info` may
// be a string or bytes; `length` is in bytes and capped at 255*HashLen per
// the RFC (= 8160 bytes for SHA-256).
export async function expand(prkHex, info, length) {
  const L = Number(length);
  if (!Number.isInteger(L) || L < 0) {
    throw new Error("expand: length must be a non-negative integer");
  }
  const maxLen = 255 * SHA256_OUT;
  if (L > maxLen) {
    throw new Error(`expand: length must be ≤ ${maxLen} for SHA-256`);
  }
  if (L === 0) return "";

  const prk = _hexToBytes(prkHex);
  if (prk.length !== SHA256_OUT) {
    throw new Error(
      `expand: PRK must be ${SHA256_OUT} bytes (got ${prk.length})`
    );
  }
  const infoBytes = _toBytes(info);

  const n = Math.ceil(L / SHA256_OUT);
  let t = new Uint8Array(0);          // T(i-1)
  const okm = new Uint8Array(L);
  let written = 0;

  for (let i = 1; i <= n; i++) {
    // HMAC input is T(i-1) || info || single-byte counter i.
    const counter = new Uint8Array([i]);
    const input = _concat(_concat(t, infoBytes), counter);
    t = await _hmacSha256(prk, input);
    const take = Math.min(SHA256_OUT, L - written);
    okm.set(t.subarray(0, take), written);
    written += take;
  }
  return _bytesToHex(okm);
}

// ---------- single-shot HKDF -----------------------------------------------

// Extract-then-Expand in one call. Prefers Web Crypto's HKDF (which does
// exactly this) and falls back to extract() + expand() on environments
// without it. Used by the demo for the RFC 5869 test vectors and for any
// caller that wants the production single-shot KDF.
export async function hkdf(ikm, salt, info, length) {
  const L = Number(length);
  if (!Number.isInteger(L) || L < 0) {
    throw new Error("hkdf: length must be a non-negative integer");
  }
  if (L === 0) return "";

  const ikmBytes  = _toBytes(ikm);
  const saltBytes = _toBytes(salt);
  const infoBytes = _toBytes(info);

  if (_hasSubtle() && typeof crypto.subtle.deriveBits === "function") {
    try {
      const baseKey = await crypto.subtle.importKey(
        "raw",
        ikmBytes,
        "HKDF",
        false,
        ["deriveBits"]
      );
      const bits = await crypto.subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt: saltBytes, info: infoBytes },
        baseKey,
        L * 8
      );
      return _bytesToHex(new Uint8Array(bits));
    } catch {
      // Some platforms support subtle.deriveBits but not the HKDF algorithm
      // (e.g. very old node, locked-down envs). Fall back to manual path.
    }
  }

  const prkHex = await extract(saltBytes, ikmBytes);
  return await expand(prkHex, infoBytes, L);
}

// ---------- interactive step: derive TLS-style keys -------------------------

// The four labels TLS 1.3 uses (in spirit — the real TLS labels include a
// length prefix and version tag, see RFC 8446 §7.1; we keep the labels
// plain so the lesson surfaces the idea, not the wire format).
export const TLS_KEY_LABELS = Object.freeze({
  clientKey: "client write key",
  serverKey: "server write key",
  clientIv:  "client iv",
  serverIv:  "server iv",
});

// Lengths roughly matching AES-128-GCM in TLS 1.3 (16-byte key, 12-byte IV).
export const TLS_KEY_LENGTHS = Object.freeze({
  clientKey: 16,
  serverKey: 16,
  clientIv:  12,
  serverIv:  12,
});

// Derive a deterministic PRK from a seed string so the lesson is repeatable
// across runs. In production, PRK would be the output of HKDF-Extract over
// a real shared secret (e.g. an X25519 output). Here we stand in for that
// step with HMAC(salt="cloak hkdf demo", ikm=seed) — same shape, fixed
// inputs, deterministic.
const DEMO_PRK_SALT = "cloak hkdf demo";

async function _prkFromSeed(seed) {
  return await extract(DEMO_PRK_SALT, seed);
}

// Run the four Expand calls and return the four hex strings + the PRK used.
// `seed` defaults to a fixed string so the page has something to render
// even when the user hasn't typed anything. Pure function modulo the seed:
// same seed → same four outputs, every time.
export async function deriveTlsKeys(seed) {
  const seedString =
    typeof seed === "string" && seed.length > 0
      ? seed
      : "x25519-shared-secret-stand-in";
  const prkHex = await _prkFromSeed(seedString);

  const [clientKey, serverKey, clientIv, serverIv] = await Promise.all([
    expand(prkHex, TLS_KEY_LABELS.clientKey, TLS_KEY_LENGTHS.clientKey),
    expand(prkHex, TLS_KEY_LABELS.serverKey, TLS_KEY_LENGTHS.serverKey),
    expand(prkHex, TLS_KEY_LABELS.clientIv,  TLS_KEY_LENGTHS.clientIv),
    expand(prkHex, TLS_KEY_LABELS.serverIv,  TLS_KEY_LENGTHS.serverIv),
  ]);

  return {
    seed: seedString,
    prkHex,
    clientKey,
    serverKey,
    clientIv,
    serverIv,
  };
}
