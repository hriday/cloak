import { test } from "node:test";
import assert from "node:assert/strict";
import * as sim from "../rsapss_simulator.js";

const hasRsaPss = await (async () => {
  if (typeof crypto === "undefined" || !crypto.subtle) return false;
  try {
    await crypto.subtle.generateKey(
      {
        name: "RSA-PSS",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"]
    );
    return true;
  } catch {
    return false;
  }
})();

test("ensureKeypair returns a hex SPKI public key when RSA-PSS is available", async (t) => {
  if (!hasRsaPss) { t.skip("RSA-PSS not supported in this Node runtime"); return; }
  sim._resetForTests();
  const { publicKeyHex } = await sim.ensureKeypair();
  assert.equal(typeof publicKeyHex, "string");
  // SPKI-encoded RSA-2048 public keys are ~294 bytes ⇒ ~588 hex chars.
  // The exact length varies a couple of bytes with how short integers
  // get encoded in DER; we just check it's in the right ballpark and
  // is valid hex.
  assert.ok(publicKeyHex.length >= 500 && publicKeyHex.length <= 700,
    `expected ~588 hex chars, got ${publicKeyHex.length}`);
  assert.match(publicKeyHex, /^[0-9a-f]+$/);
});

test("ensureKeypair is idempotent across calls (cached keypair)", async (t) => {
  if (!hasRsaPss) { t.skip("RSA-PSS not supported in this Node runtime"); return; }
  sim._resetForTests();
  const a = await sim.ensureKeypair();
  const b = await sim.ensureKeypair();
  assert.equal(a.publicKeyHex, b.publicKeyHex);
});

test("sign returns 512-char hex (256-byte signature for 2048-bit modulus)", async (t) => {
  if (!hasRsaPss) { t.skip("RSA-PSS not supported in this Node runtime"); return; }
  sim._resetForTests();
  const sig = await sim.sign("hello");
  assert.equal(typeof sig, "string");
  assert.equal(sig.length, 512);
  assert.match(sig, /^[0-9a-f]+$/);
});

test("sign produces DIFFERENT signatures on repeated calls (probabilistic property)", async (t) => {
  if (!hasRsaPss) { t.skip("RSA-PSS not supported in this Node runtime"); return; }
  sim._resetForTests();
  const a = await sim.sign("hello");
  const b = await sim.sign("hello");
  // Both 512 hex chars but should be cryptographically different
  // because the EMSA-PSS salt is freshly random each call.
  assert.notEqual(a, b);
  // Sanity check: both are still well-formed sigs.
  assert.equal(a.length, 512);
  assert.equal(b.length, 512);
});

test("verify accepts a fresh signature against the same message", async (t) => {
  if (!hasRsaPss) { t.skip("RSA-PSS not supported in this Node runtime"); return; }
  sim._resetForTests();
  const sig = await sim.sign("hello");
  const ok = await sim.verify("hello", sig);
  assert.equal(ok, true);
});

test("verify accepts BOTH of two distinct signatures of the same message (probabilistic)", async (t) => {
  if (!hasRsaPss) { t.skip("RSA-PSS not supported in this Node runtime"); return; }
  sim._resetForTests();
  const sig1 = await sim.sign("hello");
  const sig2 = await sim.sign("hello");
  assert.notEqual(sig1, sig2);
  assert.equal(await sim.verify("hello", sig1), true);
  assert.equal(await sim.verify("hello", sig2), true);
});

test("verify rejects a signature with one flipped hex char (tampered)", async (t) => {
  if (!hasRsaPss) { t.skip("RSA-PSS not supported in this Node runtime"); return; }
  sim._resetForTests();
  const sig = await sim.sign("hello");
  // Flip the first hex char.
  const tampered = (sig[0] === "0" ? "1" : "0") + sig.slice(1);
  const ok = await sim.verify("hello", tampered);
  assert.equal(ok, false);
});

test("verify rejects a signature against a different message", async (t) => {
  if (!hasRsaPss) { t.skip("RSA-PSS not supported in this Node runtime"); return; }
  sim._resetForTests();
  const sig = await sim.sign("hello");
  const ok = await sim.verify("HELLO", sig);
  assert.equal(ok, false);
});

test("verify throws on malformed hex", async (t) => {
  if (!hasRsaPss) { t.skip("RSA-PSS not supported in this Node runtime"); return; }
  sim._resetForTests();
  await assert.rejects(() => sim.verify("hello", "zz" + "00".repeat(255)), /invalid hex/);
});

test("publicKeyHex returns the SPKI hex string (~588 chars)", async (t) => {
  if (!hasRsaPss) { t.skip("RSA-PSS not supported in this Node runtime"); return; }
  sim._resetForTests();
  const hex = await sim.publicKeyHex();
  assert.ok(hex.length >= 500 && hex.length <= 700);
  assert.match(hex, /^[0-9a-f]+$/);
});

test("ensureKeypair throws WEB_CRYPTO_UNAVAILABLE without crypto.subtle", async () => {
  sim._resetForTests();
  const originalDescriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  Object.defineProperty(globalThis, "crypto", {
    value: { getRandomValues: () => new Uint8Array(16) },
    configurable: true,
    writable: true,
  });
  try {
    await assert.rejects(() => sim.ensureKeypair(), (e) => e.message === sim.WEB_CRYPTO_UNAVAILABLE);
  } finally {
    if (originalDescriptor) Object.defineProperty(globalThis, "crypto", originalDescriptor);
    else delete globalThis.crypto;
    sim._resetForTests();
  }
});

test("WEB_CRYPTO_UNAVAILABLE sentinel is exported as a string", () => {
  assert.equal(typeof sim.WEB_CRYPTO_UNAVAILABLE, "string");
  assert.ok(sim.WEB_CRYPTO_UNAVAILABLE.length > 0);
});
