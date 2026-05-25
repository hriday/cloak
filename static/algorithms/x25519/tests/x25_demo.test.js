import { test } from "node:test";
import assert from "node:assert/strict";
import {
  runExchange,
  RFC7748_FALLBACK,
  WEB_CRYPTO_UNAVAILABLE,
  generateAlice,
  generateBob,
  deriveSharedFromAlice,
  deriveSharedFromBob,
  exportPublic,
  _reset,
} from "../x25_demo.js";

// Probe once at module load — Node 20+ may or may not ship Web Crypto X25519.
// If it does, we get to test the live path. If not, we exercise the fallback.
async function probeX25519() {
  if (typeof crypto === "undefined" || !crypto.subtle) return false;
  try {
    await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
    return true;
  } catch {
    return false;
  }
}

const HAS_X25519 = await probeX25519();

test("runExchange returns the four hex blobs + match flag", async () => {
  _reset();
  const r = await runExchange();
  assert.equal(typeof r.alicePubHex, "string");
  assert.equal(typeof r.bobPubHex, "string");
  assert.equal(typeof r.sharedHexFromAlice, "string");
  assert.equal(typeof r.sharedHexFromBob, "string");
  // Curve25519 public keys + shared secrets are all 32 bytes = 64 hex chars.
  assert.equal(r.alicePubHex.length, 64);
  assert.equal(r.bobPubHex.length, 64);
  assert.equal(r.sharedHexFromAlice.length, 64);
  assert.equal(r.sharedHexFromBob.length, 64);
  assert.match(r.alicePubHex, /^[0-9a-f]+$/);
  assert.equal(r.match, true);
  assert.equal(r.sharedHexFromAlice, r.sharedHexFromBob);
});

test("runExchange — both sides land on identical bytes (the whole pedagogical point)", async () => {
  _reset();
  const r = await runExchange();
  assert.equal(r.sharedHexFromAlice, r.sharedHexFromBob);
  assert.equal(r.match, true);
});

if (HAS_X25519) {
  test("runExchange — live path: Alice ≠ Bob pubkeys (fresh random keys)", async () => {
    _reset();
    const r = await runExchange();
    assert.equal(r.usedFallback, false);
    assert.notEqual(r.alicePubHex, r.bobPubHex);
  });

  test("two consecutive exchanges produce different keypairs", async () => {
    _reset();
    const a = await runExchange();
    _reset();
    const b = await runExchange();
    assert.notEqual(a.alicePubHex, b.alicePubHex);
    assert.notEqual(a.sharedHexFromAlice, b.sharedHexFromAlice);
  });

  test("generateAlice/generateBob + exportPublic + derive symmetry", async () => {
    _reset();
    await generateAlice();
    await generateBob();
    const aPub = await exportPublic("alice");
    const bPub = await exportPublic("bob");
    assert.equal(aPub.length, 64);
    assert.equal(bPub.length, 64);
    assert.notEqual(aPub, bPub);
    const sA = await deriveSharedFromAlice();
    const sB = await deriveSharedFromBob();
    assert.equal(sA, sB);
  });
} else {
  test("runExchange — fallback path returns RFC 7748 §6.1 canonical vectors", async () => {
    _reset();
    const r = await runExchange();
    assert.equal(r.usedFallback, true);
    assert.equal(r.alicePubHex, RFC7748_FALLBACK.alicePubHex);
    assert.equal(r.bobPubHex,   RFC7748_FALLBACK.bobPubHex);
    assert.equal(r.sharedHexFromAlice, RFC7748_FALLBACK.sharedHex);
    assert.equal(r.sharedHexFromBob,   RFC7748_FALLBACK.sharedHex);
    assert.equal(r.match, true);
  });
}

test("WEB_CRYPTO_UNAVAILABLE tag is exported and a string", () => {
  assert.equal(typeof WEB_CRYPTO_UNAVAILABLE, "string");
  assert.ok(WEB_CRYPTO_UNAVAILABLE.length > 0);
});

test("fallback path is taken when crypto.subtle is absent", async () => {
  const originalDescriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  Object.defineProperty(globalThis, "crypto", {
    value: { getRandomValues: () => new Uint8Array(32) }, // no .subtle
    configurable: true,
    writable: true,
  });
  try {
    _reset();
    const r = await runExchange();
    assert.equal(r.usedFallback, true);
    assert.equal(r.sharedHexFromAlice, RFC7748_FALLBACK.sharedHex);
    assert.equal(r.sharedHexFromBob,   RFC7748_FALLBACK.sharedHex);
    assert.equal(r.match, true);
  } finally {
    if (originalDescriptor) {
      Object.defineProperty(globalThis, "crypto", originalDescriptor);
    } else {
      delete globalThis.crypto;
    }
  }
});

test("RFC7748_FALLBACK constant matches the published vectors", () => {
  // RFC 7748 §6.1 — these literals are sanity-checked here so a refactor
  // that accidentally edits them gets caught.
  assert.equal(
    RFC7748_FALLBACK.alicePrivHex,
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
  );
  assert.equal(
    RFC7748_FALLBACK.bobPrivHex,
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
  );
  assert.equal(
    RFC7748_FALLBACK.sharedHex,
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
  );
});
