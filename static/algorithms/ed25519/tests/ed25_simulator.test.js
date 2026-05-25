import { test } from "node:test";
import assert from "node:assert/strict";
import * as sim from "../ed25_simulator.js";

const hasEd25519 = await (async () => {
  if (typeof crypto === "undefined" || !crypto.subtle) return false;
  try {
    await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    return true;
  } catch {
    return false;
  }
})();

test("ensureKeypair returns a 64-char hex public key when Ed25519 is available", async (t) => {
  if (!hasEd25519) { t.skip("Ed25519 not supported in this Node runtime"); return; }
  sim._resetForTests();
  const { publicKeyHex } = await sim.ensureKeypair();
  assert.equal(typeof publicKeyHex, "string");
  assert.equal(publicKeyHex.length, 64);                  // 32 bytes
  assert.match(publicKeyHex, /^[0-9a-f]+$/);
});

test("ensureKeypair is idempotent across calls (cached keypair)", async (t) => {
  if (!hasEd25519) { t.skip("Ed25519 not supported in this Node runtime"); return; }
  sim._resetForTests();
  const a = await sim.ensureKeypair();
  const b = await sim.ensureKeypair();
  assert.equal(a.publicKeyHex, b.publicKeyHex);
});

test("sign returns 128-char hex (64-byte signature)", async (t) => {
  if (!hasEd25519) { t.skip("Ed25519 not supported in this Node runtime"); return; }
  sim._resetForTests();
  const sig = await sim.sign("hello");
  assert.equal(typeof sig, "string");
  assert.equal(sig.length, 128);
  assert.match(sig, /^[0-9a-f]+$/);
});

test("verify accepts a fresh signature against the same message", async (t) => {
  if (!hasEd25519) { t.skip("Ed25519 not supported in this Node runtime"); return; }
  sim._resetForTests();
  const sig = await sim.sign("hello");
  const ok = await sim.verify("hello", sig);
  assert.equal(ok, true);
});

test("verify rejects a signature with one flipped hex char (tampered)", async (t) => {
  if (!hasEd25519) { t.skip("Ed25519 not supported in this Node runtime"); return; }
  sim._resetForTests();
  const sig = await sim.sign("hello");
  // Flip the first hex char.
  const tampered = (sig[0] === "0" ? "1" : "0") + sig.slice(1);
  const ok = await sim.verify("hello", tampered);
  assert.equal(ok, false);
});

test("verify rejects a signature against a different message", async (t) => {
  if (!hasEd25519) { t.skip("Ed25519 not supported in this Node runtime"); return; }
  sim._resetForTests();
  const sig = await sim.sign("hello");
  const ok = await sim.verify("HELLO", sig);
  assert.equal(ok, false);
});

test("verify throws on malformed hex", async (t) => {
  if (!hasEd25519) { t.skip("Ed25519 not supported in this Node runtime"); return; }
  sim._resetForTests();
  await assert.rejects(() => sim.verify("hello", "zz" + "00".repeat(63)), /invalid hex/);
});

test("publicKeyHex returns a 64-char hex string", async (t) => {
  if (!hasEd25519) { t.skip("Ed25519 not supported in this Node runtime"); return; }
  sim._resetForTests();
  const hex = await sim.publicKeyHex();
  assert.equal(hex.length, 64);
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
