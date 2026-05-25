import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";
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

test("rsapss_operation rejects missing op", async () => {
  const r = await v.rsapss_operation({ message: "hi" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /sign|verify/i);
});

test("rsapss_operation rejects empty message", async () => {
  const r = await v.rsapss_operation({ op: "sign", message: "" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /something|empty/i);
});

test("rsapss_operation rejects verify without signature", async () => {
  const r = await v.rsapss_operation({ op: "verify", message: "hi" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /signature/i);
});

test("rsapss_operation rejects verify with too-short signature", async () => {
  const r = await v.rsapss_operation({ op: "verify", message: "hi", signature: "abcd" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /256 bytes|512 hex/i);
});

test("rsapss_operation rejects verify with non-hex signature", async () => {
  const r = await v.rsapss_operation({ op: "verify", message: "hi", signature: "z".repeat(512) }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /256 bytes|512 hex/i);
});

test("rsapss_operation sign happy path writes rsapss_last_op + rsapss_last_input", async () => {
  const r = await v.rsapss_operation({ op: "sign", message: "hi" }, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.rsapss_last_op, "sign");
  assert.equal(r.value.rsapss_last_input, "hi");
  // rsapss_signature may be hex (with crypto.subtle) or null (without)
});

test("rsapss_operation sign produces a 512-hex signature when RSA-PSS is available", async (t) => {
  if (!hasRsaPss) { t.skip("RSA-PSS not supported in this Node runtime"); return; }
  sim._resetForTests();
  const r = await v.rsapss_operation({ op: "sign", message: "hello" }, {});
  assert.equal(r.ok, true);
  assert.equal(typeof r.value.rsapss_signature, "string");
  assert.equal(r.value.rsapss_signature.length, 512);
  assert.match(r.value.rsapss_signature, /^[0-9a-f]+$/);
  assert.equal(r.value.rsapss_op_error, null);
});

test("rsapss_operation: two sign calls with same input produce DIFFERENT signatures (probabilistic)", async (t) => {
  if (!hasRsaPss) { t.skip("RSA-PSS not supported in this Node runtime"); return; }
  sim._resetForTests();
  const r1 = await v.rsapss_operation({ op: "sign", message: "hello" }, {});
  const r2 = await v.rsapss_operation({ op: "sign", message: "hello" }, {});
  assert.equal(r1.ok, true);
  assert.equal(r2.ok, true);
  // The whole point of PSS: fresh salt ⇒ different signature bytes.
  assert.notEqual(r1.value.rsapss_signature, r2.value.rsapss_signature);
});

test("rsapss_operation verify returns true on a valid round-trip", async (t) => {
  if (!hasRsaPss) { t.skip("RSA-PSS not supported in this Node runtime"); return; }
  sim._resetForTests();
  const signed = await v.rsapss_operation({ op: "sign", message: "hello" }, {});
  const sig = signed.value.rsapss_signature;
  const verified = await v.rsapss_operation({ op: "verify", message: "hello", signature: sig }, {});
  assert.equal(verified.ok, true);
  assert.equal(verified.value.rsapss_verify_result, true);
  assert.equal(verified.value.rsapss_last_op, "verify");
});

test("rsapss_operation verify returns true for BOTH distinct sigs of the same message", async (t) => {
  if (!hasRsaPss) { t.skip("RSA-PSS not supported in this Node runtime"); return; }
  sim._resetForTests();
  const s1 = await v.rsapss_operation({ op: "sign", message: "hello" }, {});
  const s2 = await v.rsapss_operation({ op: "sign", message: "hello" }, {});
  assert.notEqual(s1.value.rsapss_signature, s2.value.rsapss_signature);
  const v1 = await v.rsapss_operation({ op: "verify", message: "hello", signature: s1.value.rsapss_signature }, {});
  const v2 = await v.rsapss_operation({ op: "verify", message: "hello", signature: s2.value.rsapss_signature }, {});
  assert.equal(v1.value.rsapss_verify_result, true);
  assert.equal(v2.value.rsapss_verify_result, true);
});

test("rsapss_operation verify returns false (not an error) for a tampered signature", async (t) => {
  if (!hasRsaPss) { t.skip("RSA-PSS not supported in this Node runtime"); return; }
  sim._resetForTests();
  const signed = await v.rsapss_operation({ op: "sign", message: "hello" }, {});
  const sig = signed.value.rsapss_signature;
  const tampered = (sig[0] === "0" ? "1" : "0") + sig.slice(1);
  const verified = await v.rsapss_operation({ op: "verify", message: "hello", signature: tampered }, {});
  assert.equal(verified.ok, true);                   // not an error
  assert.equal(verified.value.rsapss_verify_result, false);
});

test("rsapss_operation verify returns false for a wrong message", async (t) => {
  if (!hasRsaPss) { t.skip("RSA-PSS not supported in this Node runtime"); return; }
  sim._resetForTests();
  const signed = await v.rsapss_operation({ op: "sign", message: "hello" }, {});
  const sig = signed.value.rsapss_signature;
  const verified = await v.rsapss_operation({ op: "verify", message: "HELLO", signature: sig }, {});
  assert.equal(verified.ok, true);
  assert.equal(verified.value.rsapss_verify_result, false);
});

test("rsapss_operation uppercase hex signature is accepted (normalized to lowercase)", async (t) => {
  if (!hasRsaPss) { t.skip("RSA-PSS not supported in this Node runtime"); return; }
  sim._resetForTests();
  const signed = await v.rsapss_operation({ op: "sign", message: "hello" }, {});
  const sigUpper = signed.value.rsapss_signature.toUpperCase();
  const verified = await v.rsapss_operation({ op: "verify", message: "hello", signature: sigUpper }, {});
  assert.equal(verified.ok, true);
  assert.equal(verified.value.rsapss_verify_result, true);
});

test("rsapss_operation no-crypto fallback returns ok with null signature/result", async () => {
  const originalDescriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  Object.defineProperty(globalThis, "crypto", {
    value: { getRandomValues: () => new Uint8Array(16) }, // no .subtle
    configurable: true,
    writable: true,
  });
  try {
    const r = await v.rsapss_operation({ op: "sign", message: "hi" }, {});
    assert.equal(r.ok, true);
    assert.equal(r.value.rsapss_last_op, "sign");
    assert.equal(r.value.rsapss_last_input, "hi");
    assert.equal(r.value.rsapss_signature, null);
    assert.equal(r.value.rsapss_verify_result, null);
    assert.equal(r.value.rsapss_op_error, null);
  } finally {
    if (originalDescriptor) Object.defineProperty(globalThis, "crypto", originalDescriptor);
    else delete globalThis.crypto;
    sim._resetForTests();
  }
});

test("info always ok", () => {
  assert.deepEqual(v.info("anything", {}), { ok: true, value: {} });
});

test("walkthroughs.rsapss_operation returns 3 non-empty string rungs", () => {
  assert.equal(typeof v.walkthroughs.rsapss_operation, "function");
  const rungs = v.walkthroughs.rsapss_operation({});
  assert.ok(Array.isArray(rungs));
  assert.equal(rungs.length, 3);
  rungs.forEach((r) => {
    assert.equal(typeof r, "string");
    assert.ok(r.length > 0);
  });
});
