import { test } from "node:test";
import assert from "node:assert/strict";
import {
  extract,
  expand,
  hkdf,
  deriveTlsKeys,
  TLS_KEY_LABELS,
  TLS_KEY_LENGTHS,
} from "../hkdf_demo.js";

// ----- helpers --------------------------------------------------------------

function bytesOf(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    out[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return out;
}

function hasSubtle() {
  return typeof crypto !== "undefined" && crypto.subtle != null;
}

// ----- RFC 5869 §A.1 test vector --------------------------------------------
// Basic test case with SHA-256.
//   IKM  = 0x0b * 22
//   salt = 0x000102030405060708090a0b0c (13 bytes)
//   info = 0xf0f1f2f3f4f5f6f7f8f9 (10 bytes)
//   L    = 42
//   PRK  = 077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5
//   OKM  = 3cb25f25faacd57a90434f64d0362f2a
//          2d2d0a90cf1a5a4c5db02d56ecc4c5bf
//          34007208d5b887185865

const A1 = Object.freeze({
  ikmHex:  "0b".repeat(22),
  saltHex: "000102030405060708090a0b0c",
  infoHex: "f0f1f2f3f4f5f6f7f8f9",
  length:  42,
  prkHex:  "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
  okmHex:  "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
});

test("RFC 5869 §A.1 — extract produces the expected PRK", async (t) => {
  if (!hasSubtle()) { t.skip("crypto.subtle not available"); return; }
  const prk = await extract(bytesOf(A1.saltHex), bytesOf(A1.ikmHex));
  assert.equal(prk, A1.prkHex);
});

test("RFC 5869 §A.1 — expand from the PRK produces the expected OKM", async (t) => {
  if (!hasSubtle()) { t.skip("crypto.subtle not available"); return; }
  const okm = await expand(A1.prkHex, bytesOf(A1.infoHex), A1.length);
  assert.equal(okm, A1.okmHex);
});

test("RFC 5869 §A.1 — single-shot hkdf() matches extract + expand", async (t) => {
  if (!hasSubtle()) { t.skip("crypto.subtle not available"); return; }
  const okmOneShot = await hkdf(
    bytesOf(A1.ikmHex),
    bytesOf(A1.saltHex),
    bytesOf(A1.infoHex),
    A1.length
  );
  assert.equal(okmOneShot, A1.okmHex);

  // And it must equal the manual two-step composition.
  const prk = await extract(bytesOf(A1.saltHex), bytesOf(A1.ikmHex));
  const okm = await expand(prk, bytesOf(A1.infoHex), A1.length);
  assert.equal(okmOneShot, okm);
});

// ----- extract --------------------------------------------------------------

test("extract returns 32-byte (64 hex chars) PRK", async (t) => {
  if (!hasSubtle()) { t.skip("crypto.subtle not available"); return; }
  const prk = await extract("salt", "ikm");
  assert.equal(prk.length, 64);
  assert.match(prk, /^[0-9a-f]+$/);
});

test("extract is deterministic for the same (salt, ikm)", async (t) => {
  if (!hasSubtle()) { t.skip("crypto.subtle not available"); return; }
  const a = await extract("salt", "ikm");
  const b = await extract("salt", "ikm");
  assert.equal(a, b);
});

test("extract differs when salt changes", async (t) => {
  if (!hasSubtle()) { t.skip("crypto.subtle not available"); return; }
  const a = await extract("salt-a", "ikm");
  const b = await extract("salt-b", "ikm");
  assert.notEqual(a, b);
});

test("extract differs when ikm changes", async (t) => {
  if (!hasSubtle()) { t.skip("crypto.subtle not available"); return; }
  const a = await extract("salt", "ikm-a");
  const b = await extract("salt", "ikm-b");
  assert.notEqual(a, b);
});

test("extract accepts an empty salt (RFC §2.2 says use HashLen zeros)", async (t) => {
  if (!hasSubtle()) { t.skip("crypto.subtle not available"); return; }
  const prk = await extract("", "ikm");
  assert.equal(prk.length, 64);
});

// ----- expand ---------------------------------------------------------------

test("expand returns exactly `length` bytes (= length*2 hex chars)", async (t) => {
  if (!hasSubtle()) { t.skip("crypto.subtle not available"); return; }
  const okm = await expand(A1.prkHex, "info", 16);
  assert.equal(okm.length, 32);
  assert.match(okm, /^[0-9a-f]+$/);
});

test("expand is deterministic for the same (prk, info, length)", async (t) => {
  if (!hasSubtle()) { t.skip("crypto.subtle not available"); return; }
  const a = await expand(A1.prkHex, "info", 16);
  const b = await expand(A1.prkHex, "info", 16);
  assert.equal(a, b);
});

test("expand with different info strings produces independent outputs", async (t) => {
  if (!hasSubtle()) { t.skip("crypto.subtle not available"); return; }
  const a = await expand(A1.prkHex, "client write key", 16);
  const b = await expand(A1.prkHex, "server write key", 16);
  assert.notEqual(a, b);
  // No prefix relationship: change the info and the entire stream changes.
  assert.notEqual(a.slice(0, 4), b.slice(0, 4));
});

test("expand at exactly HashLen (32) gives one HMAC block worth of bytes", async (t) => {
  if (!hasSubtle()) { t.skip("crypto.subtle not available"); return; }
  const okm = await expand(A1.prkHex, "info", 32);
  assert.equal(okm.length, 64);
});

test("expand across multiple blocks (L > HashLen) is consistent with the RFC vector", async (t) => {
  if (!hasSubtle()) { t.skip("crypto.subtle not available"); return; }
  // 42 bytes > 32 so this exercises N=2 internally. The published OKM is the
  // authoritative answer (already checked above), so the very fact that we
  // pass A.1 means our multi-block iteration is right.
  const okm = await expand(A1.prkHex, bytesOf(A1.infoHex), A1.length);
  assert.equal(okm, A1.okmHex);
});

test("expand rejects non-integer length", async () => {
  await assert.rejects(() => expand(A1.prkHex, "info", 1.5), /integer/);
});

test("expand rejects negative length", async () => {
  await assert.rejects(() => expand(A1.prkHex, "info", -1), /non-negative/);
});

test("expand rejects PRK of wrong size", async (t) => {
  if (!hasSubtle()) { t.skip("crypto.subtle not available"); return; }
  await assert.rejects(() => expand("00".repeat(16), "info", 16), /32 bytes/);
});

test("expand returns empty string for length=0", async (t) => {
  if (!hasSubtle()) { t.skip("crypto.subtle not available"); return; }
  const okm = await expand(A1.prkHex, "info", 0);
  assert.equal(okm, "");
});

test("expand rejects length above 255*HashLen", async () => {
  await assert.rejects(() => expand(A1.prkHex, "info", 255 * 32 + 1), /8160/);
});

// ----- hkdf (single-shot) ---------------------------------------------------

test("hkdf with empty salt and empty info still produces L bytes", async (t) => {
  if (!hasSubtle()) { t.skip("crypto.subtle not available"); return; }
  const okm = await hkdf("ikm", "", "", 16);
  assert.equal(okm.length, 32);
});

test("hkdf with string inputs equals hkdf with the same bytes", async (t) => {
  if (!hasSubtle()) { t.skip("crypto.subtle not available"); return; }
  const a = await hkdf("ikm", "salt", "info", 16);
  const b = await hkdf(
    new TextEncoder().encode("ikm"),
    new TextEncoder().encode("salt"),
    new TextEncoder().encode("info"),
    16
  );
  assert.equal(a, b);
});

// ----- deriveTlsKeys --------------------------------------------------------

test("deriveTlsKeys returns the four hex blobs with correct lengths", async (t) => {
  if (!hasSubtle()) { t.skip("crypto.subtle not available"); return; }
  const r = await deriveTlsKeys("anything");
  assert.equal(r.clientKey.length, TLS_KEY_LENGTHS.clientKey * 2);
  assert.equal(r.serverKey.length, TLS_KEY_LENGTHS.serverKey * 2);
  assert.equal(r.clientIv.length,  TLS_KEY_LENGTHS.clientIv * 2);
  assert.equal(r.serverIv.length,  TLS_KEY_LENGTHS.serverIv * 2);
  // All hex.
  for (const v of [r.clientKey, r.serverKey, r.clientIv, r.serverIv]) {
    assert.match(v, /^[0-9a-f]+$/);
  }
  // PRK is 32 bytes.
  assert.equal(r.prkHex.length, 64);
});

test("deriveTlsKeys: four keys from the same PRK are all distinct", async (t) => {
  if (!hasSubtle()) { t.skip("crypto.subtle not available"); return; }
  const r = await deriveTlsKeys("seed");
  const set = new Set([r.clientKey, r.serverKey, r.clientIv, r.serverIv]);
  assert.equal(set.size, 4, "different info strings must produce different OKMs");
});

test("deriveTlsKeys is deterministic for a given seed", async (t) => {
  if (!hasSubtle()) { t.skip("crypto.subtle not available"); return; }
  const a = await deriveTlsKeys("the-same-seed");
  const b = await deriveTlsKeys("the-same-seed");
  assert.equal(a.prkHex, b.prkHex);
  assert.equal(a.clientKey, b.clientKey);
  assert.equal(a.serverKey, b.serverKey);
  assert.equal(a.clientIv, b.clientIv);
  assert.equal(a.serverIv, b.serverIv);
});

test("deriveTlsKeys differs when seed differs", async (t) => {
  if (!hasSubtle()) { t.skip("crypto.subtle not available"); return; }
  const a = await deriveTlsKeys("seed-a");
  const b = await deriveTlsKeys("seed-b");
  assert.notEqual(a.prkHex, b.prkHex);
  assert.notEqual(a.clientKey, b.clientKey);
});

test("deriveTlsKeys falls back to a default seed when called with empty/missing", async (t) => {
  if (!hasSubtle()) { t.skip("crypto.subtle not available"); return; }
  const a = await deriveTlsKeys();
  const b = await deriveTlsKeys("");
  const c = await deriveTlsKeys(null);
  assert.equal(a.seed.length > 0, true);
  assert.equal(a.clientKey, b.clientKey);
  assert.equal(a.clientKey, c.clientKey);
});

test("TLS_KEY_LABELS exposes the four expected labels", () => {
  assert.equal(TLS_KEY_LABELS.clientKey, "client write key");
  assert.equal(TLS_KEY_LABELS.serverKey, "server write key");
  assert.equal(TLS_KEY_LABELS.clientIv,  "client iv");
  assert.equal(TLS_KEY_LABELS.serverIv,  "server iv");
});
