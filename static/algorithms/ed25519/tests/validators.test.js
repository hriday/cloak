import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";
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

test("ed25519_operation rejects missing op", async () => {
  const r = await v.ed25519_operation({ message: "hi" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /sign|verify/i);
});

test("ed25519_operation rejects empty message", async () => {
  const r = await v.ed25519_operation({ op: "sign", message: "" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /something|empty/i);
});

test("ed25519_operation rejects verify without signature", async () => {
  const r = await v.ed25519_operation({ op: "verify", message: "hi" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /signature/i);
});

test("ed25519_operation rejects verify with too-short signature", async () => {
  const r = await v.ed25519_operation({ op: "verify", message: "hi", signature: "abcd" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /64 bytes|128 hex/i);
});

test("ed25519_operation rejects verify with non-hex signature", async () => {
  const r = await v.ed25519_operation({ op: "verify", message: "hi", signature: "z".repeat(128) }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /64 bytes|128 hex/i);
});

test("ed25519_operation sign happy path writes ed25_last_op + ed25_last_input", async () => {
  const r = await v.ed25519_operation({ op: "sign", message: "hi" }, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.ed25_last_op, "sign");
  assert.equal(r.value.ed25_last_input, "hi");
  // ed25_last_signature may be hex (with crypto.subtle) or null (without)
});

test("ed25519_operation sign produces a 128-hex signature when Ed25519 is available", async (t) => {
  if (!hasEd25519) { t.skip("Ed25519 not supported in this Node runtime"); return; }
  sim._resetForTests();
  const r = await v.ed25519_operation({ op: "sign", message: "hello" }, {});
  assert.equal(r.ok, true);
  assert.equal(typeof r.value.ed25_last_signature, "string");
  assert.equal(r.value.ed25_last_signature.length, 128);
  assert.match(r.value.ed25_last_signature, /^[0-9a-f]+$/);
  assert.equal(r.value.ed25_op_error, null);
});

test("ed25519_operation verify returns true on a valid round-trip", async (t) => {
  if (!hasEd25519) { t.skip("Ed25519 not supported in this Node runtime"); return; }
  sim._resetForTests();
  const signed = await v.ed25519_operation({ op: "sign", message: "hello" }, {});
  const sig = signed.value.ed25_last_signature;
  const verified = await v.ed25519_operation({ op: "verify", message: "hello", signature: sig }, {});
  assert.equal(verified.ok, true);
  assert.equal(verified.value.ed25_verify_result, true);
  assert.equal(verified.value.ed25_last_op, "verify");
});

test("ed25519_operation verify returns false (not an error) for a tampered signature", async (t) => {
  if (!hasEd25519) { t.skip("Ed25519 not supported in this Node runtime"); return; }
  sim._resetForTests();
  const signed = await v.ed25519_operation({ op: "sign", message: "hello" }, {});
  const sig = signed.value.ed25_last_signature;
  const tampered = (sig[0] === "0" ? "1" : "0") + sig.slice(1);
  const verified = await v.ed25519_operation({ op: "verify", message: "hello", signature: tampered }, {});
  assert.equal(verified.ok, true);                   // not an error
  assert.equal(verified.value.ed25_verify_result, false);
});

test("ed25519_operation verify returns false for a wrong message", async (t) => {
  if (!hasEd25519) { t.skip("Ed25519 not supported in this Node runtime"); return; }
  sim._resetForTests();
  const signed = await v.ed25519_operation({ op: "sign", message: "hello" }, {});
  const sig = signed.value.ed25_last_signature;
  const verified = await v.ed25519_operation({ op: "verify", message: "HELLO", signature: sig }, {});
  assert.equal(verified.ok, true);
  assert.equal(verified.value.ed25_verify_result, false);
});

test("ed25519_operation uppercase hex signature is accepted (normalized to lowercase)", async (t) => {
  if (!hasEd25519) { t.skip("Ed25519 not supported in this Node runtime"); return; }
  sim._resetForTests();
  const signed = await v.ed25519_operation({ op: "sign", message: "hello" }, {});
  const sigUpper = signed.value.ed25_last_signature.toUpperCase();
  const verified = await v.ed25519_operation({ op: "verify", message: "hello", signature: sigUpper }, {});
  assert.equal(verified.ok, true);
  assert.equal(verified.value.ed25_verify_result, true);
});

test("ed25519_operation no-crypto fallback returns ok with null signature/result", async () => {
  const originalDescriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  Object.defineProperty(globalThis, "crypto", {
    value: { getRandomValues: () => new Uint8Array(16) }, // no .subtle
    configurable: true,
    writable: true,
  });
  try {
    const r = await v.ed25519_operation({ op: "sign", message: "hi" }, {});
    assert.equal(r.ok, true);
    assert.equal(r.value.ed25_last_op, "sign");
    assert.equal(r.value.ed25_last_input, "hi");
    assert.equal(r.value.ed25_last_signature, null);
    assert.equal(r.value.ed25_verify_result, null);
    assert.equal(r.value.ed25_op_error, null);
  } finally {
    if (originalDescriptor) Object.defineProperty(globalThis, "crypto", originalDescriptor);
    else delete globalThis.crypto;
    sim._resetForTests();
  }
});

test("info always ok", () => {
  assert.deepEqual(v.info("anything", {}), { ok: true, value: {} });
});

test("walkthroughs.ed25519_operation returns 3 non-empty string rungs", () => {
  assert.equal(typeof v.walkthroughs.ed25519_operation, "function");
  const rungs = v.walkthroughs.ed25519_operation({});
  assert.ok(Array.isArray(rungs));
  assert.equal(rungs.length, 3);
  rungs.forEach((r) => {
    assert.equal(typeof r, "string");
    assert.ok(r.length > 0);
  });
});
