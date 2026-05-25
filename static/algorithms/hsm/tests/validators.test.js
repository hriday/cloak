import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

test("hsm_operation rejects missing op", async () => {
  const r = await v.hsm_operation({ message: "hi" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /sign|verify/i);
});

test("hsm_operation rejects empty message", async () => {
  const r = await v.hsm_operation({ op: "sign", message: "" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /at least one|empty/i);
});

test("hsm_operation rejects verify without signature", async () => {
  const r = await v.hsm_operation({ op: "verify", message: "hi" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /signature/i);
});

test("hsm_operation sign happy (in node: validates but encryption may be skipped)", async () => {
  const r = await v.hsm_operation({ op: "sign", message: "hi" }, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.hsm_last_op, "sign");
  assert.equal(r.value.hsm_last_input, "hi");
  // hsm_last_output may be a hex sig OR an error message — both are okay
});

test("pick_hsm_message rejects empty", async () => {
  const r = await v.pick_hsm_message("", {});
  assert.equal(r.ok, false);
});

test("info always ok", () => {
  assert.deepEqual(v.info("anything", {}), { ok: true, value: {} });
});

test("walkthroughs has entries for hsm_operation", () => {
  assert.equal(typeof v.walkthroughs.hsm_operation, "function");
  const rungs = v.walkthroughs.hsm_operation({});
  assert.equal(rungs.length, 3);
  rungs.forEach((r) => assert.equal(typeof r, "string"));
});

// ---- pin_translation ----

test("pin_translation accepts string PIN, defaults PAN", async () => {
  const r = await v.pin_translation("1234", {});
  assert.equal(r.ok, true);
  assert.equal(r.value.pin_value, "1234");
  assert.equal(r.value.pin_pan, "4111111111111111");
});

test("pin_translation accepts {pin, pan} object with custom PAN", async () => {
  const r = await v.pin_translation({ pin: "1234", pan: "5500000000000004" }, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.pin_value, "1234");
  assert.equal(r.value.pin_pan, "5500000000000004");
});

test("pin_translation rejects 3-digit PIN", async () => {
  const r = await v.pin_translation("123", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /PIN|digits/i);
});

test("pin_translation rejects 13-digit PIN", async () => {
  const r = await v.pin_translation("1234567890123", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /PIN|digits/i);
});

test("pin_translation rejects non-numeric PIN", async () => {
  const r = await v.pin_translation("12a4", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /PIN|digits/i);
});

test("pin_translation rejects too-short PAN", async () => {
  const r = await v.pin_translation({ pin: "1234", pan: "411111111" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /PAN|digits/i);
});

test("pin_translation happy path produces three distinct hex ciphertexts and verifies", async (t) => {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    t.skip("crypto.subtle not available in this Node version");
    return;
  }
  const r = await v.pin_translation({ pin: "4321", pan: "4111111111111111" }, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.pin_error, null);
  const { pin_terminal_ct, pin_zpk1_ct, pin_zpk2_ct, pin_verify_result, pin_keys } = r.value;
  assert.equal(typeof pin_terminal_ct, "string");
  assert.equal(pin_terminal_ct.length, 32);
  assert.match(pin_terminal_ct, /^[0-9a-f]+$/);
  assert.equal(typeof pin_zpk1_ct, "string");
  assert.equal(pin_zpk1_ct.length, 32);
  assert.equal(typeof pin_zpk2_ct, "string");
  assert.equal(pin_zpk2_ct.length, 32);
  // All three should differ — different keys at each hop.
  assert.notEqual(pin_terminal_ct, pin_zpk1_ct);
  assert.notEqual(pin_zpk1_ct, pin_zpk2_ct);
  assert.notEqual(pin_terminal_ct, pin_zpk2_ct);
  assert.equal(pin_verify_result, true);
  assert.equal(typeof pin_keys, "object");
  assert.equal(Object.keys(pin_keys).length, 3);
  for (const k of ["tpk", "zpk1", "zpk2"]) {
    assert.equal(typeof pin_keys[k], "string");
    assert.equal(pin_keys[k].length, 8);
  }
});

test("pin_translation no-crypto fallback returns ok with null ciphertexts", async () => {
  // globalThis.crypto in modern Node is a getter-only property — redefine it
  // via Object.defineProperty rather than assignment, then restore afterward.
  const originalDescriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  Object.defineProperty(globalThis, "crypto", {
    value: { getRandomValues: () => new Uint8Array(16) }, // no .subtle
    configurable: true,
    writable: true,
  });
  try {
    const r = await v.pin_translation("1234", {});
    assert.equal(r.ok, true);
    assert.equal(r.value.pin_value, "1234");
    assert.equal(r.value.pin_terminal_ct, null);
    assert.equal(r.value.pin_zpk1_ct, null);
    assert.equal(r.value.pin_zpk2_ct, null);
    assert.equal(r.value.pin_verify_result, null);
    assert.equal(r.value.pin_keys, null);
    assert.equal(r.value.pin_error, null);
  } finally {
    if (originalDescriptor) {
      Object.defineProperty(globalThis, "crypto", originalDescriptor);
    } else {
      delete globalThis.crypto;
    }
  }
});

test("walkthroughs.pin_translation returns 3 non-empty string rungs", () => {
  assert.equal(typeof v.walkthroughs.pin_translation, "function");
  const rungs = v.walkthroughs.pin_translation({});
  assert.ok(Array.isArray(rungs));
  assert.equal(rungs.length, 3);
  rungs.forEach((r) => {
    assert.equal(typeof r, "string");
    assert.ok(r.length > 0);
  });
});
