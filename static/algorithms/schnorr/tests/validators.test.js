import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

const hasSubtle = typeof crypto !== "undefined" && !!crypto.subtle;

test("schnorr_operation rejects missing op", async () => {
  const r = await v.schnorr_operation({ message: "hi" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /sign|verify/i);
});

test("schnorr_operation rejects empty message", async () => {
  const r = await v.schnorr_operation({ op: "sign", message: "" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /something|empty/i);
});

test("schnorr_operation rejects verify without signature", async () => {
  const r = await v.schnorr_operation({ op: "verify", message: "hi" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /signature/i);
});

test("schnorr_operation rejects malformed signature", async () => {
  const r = await v.schnorr_operation(
    { op: "verify", message: "hi", signature: "not a pair" },
    {},
  );
  assert.equal(r.ok, false);
  assert.match(r.hint, /R,s|integers/i);
});

test("schnorr_operation sign happy path writes state keys", async (t) => {
  if (!hasSubtle) { t.skip("crypto.subtle not available"); return; }
  const r = await v.schnorr_operation({ op: "sign", message: "hello" }, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.schnorr_last_op, "sign");
  assert.equal(r.value.schnorr_last_input, "hello");
  assert.ok(/^\d+$/.test(r.value.schnorr_last_R));
  assert.ok(/^\d+$/.test(r.value.schnorr_last_s));
  assert.equal(r.value.schnorr_op_error, null);
  // keypair is written so the next call sees the same x, X
  assert.ok(/^\d+$/.test(r.value.schnorr_keypair_x));
  assert.ok(/^\d+$/.test(r.value.schnorr_keypair_X));
});

test("schnorr_operation uses fixed seed for first-use keypair (x=100)", async (t) => {
  if (!hasSubtle) { t.skip("crypto.subtle not available"); return; }
  const r = await v.schnorr_operation({ op: "sign", message: "hello" }, {});
  assert.equal(r.value.schnorr_keypair_x, "100");
});

test("schnorr_operation verify returns valid:true on a fresh round-trip", async (t) => {
  if (!hasSubtle) { t.skip("crypto.subtle not available"); return; }
  const signed = await v.schnorr_operation({ op: "sign", message: "hello" }, {});
  const sigStr = signed.value.schnorr_last_R + "," + signed.value.schnorr_last_s;
  // Reuse the keypair via state — that's what the wizard does between steps.
  const state = {
    schnorr_keypair_x: signed.value.schnorr_keypair_x,
    schnorr_keypair_X: signed.value.schnorr_keypair_X,
  };
  const verified = await v.schnorr_operation(
    { op: "verify", message: "hello", signature: sigStr },
    state,
  );
  assert.equal(verified.ok, true);
  assert.equal(verified.value.schnorr_verify_result, true);
  assert.equal(verified.value.schnorr_eq_lhs, verified.value.schnorr_eq_rhs);
});

test("schnorr_operation verify returns valid:false (not an error) for a tampered s", async (t) => {
  if (!hasSubtle) { t.skip("crypto.subtle not available"); return; }
  const signed = await v.schnorr_operation({ op: "sign", message: "hello" }, {});
  const R = signed.value.schnorr_last_R;
  const sNum = BigInt(signed.value.schnorr_last_s);
  const tampered = R + "," + ((sNum + 1n) % 233n).toString();
  const state = {
    schnorr_keypair_x: signed.value.schnorr_keypair_x,
    schnorr_keypair_X: signed.value.schnorr_keypair_X,
  };
  const verified = await v.schnorr_operation(
    { op: "verify", message: "hello", signature: tampered },
    state,
  );
  assert.equal(verified.ok, true);
  assert.equal(verified.value.schnorr_verify_result, false);
  assert.notEqual(verified.value.schnorr_eq_lhs, verified.value.schnorr_eq_rhs);
});

test("schnorr_operation verify rejects sig on different message", async (t) => {
  if (!hasSubtle) { t.skip("crypto.subtle not available"); return; }
  const signed = await v.schnorr_operation({ op: "sign", message: "hello" }, {});
  const sigStr = signed.value.schnorr_last_R + "," + signed.value.schnorr_last_s;
  const state = {
    schnorr_keypair_x: signed.value.schnorr_keypair_x,
    schnorr_keypair_X: signed.value.schnorr_keypair_X,
  };
  const verified = await v.schnorr_operation(
    { op: "verify", message: "HELLO", signature: sigStr },
    state,
  );
  assert.equal(verified.ok, true);
  assert.equal(verified.value.schnorr_verify_result, false);
});

test("schnorr_operation accepts signature wrapped in braces / whitespace", async (t) => {
  if (!hasSubtle) { t.skip("crypto.subtle not available"); return; }
  const signed = await v.schnorr_operation({ op: "sign", message: "hello" }, {});
  const R = signed.value.schnorr_last_R;
  const s = signed.value.schnorr_last_s;
  const state = {
    schnorr_keypair_x: signed.value.schnorr_keypair_x,
    schnorr_keypair_X: signed.value.schnorr_keypair_X,
  };
  const verified = await v.schnorr_operation(
    { op: "verify", message: "hello", signature: `{ ${R} , ${s} }` },
    state,
  );
  assert.equal(verified.value.schnorr_verify_result, true);
});

test("schnorr_operation no-crypto fallback returns ok with null values", async () => {
  const originalDescriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  Object.defineProperty(globalThis, "crypto", {
    value: { getRandomValues: () => new Uint8Array(16) },
    configurable: true,
    writable: true,
  });
  try {
    const r = await v.schnorr_operation({ op: "sign", message: "hi" }, {});
    assert.equal(r.ok, true);
    assert.equal(r.value.schnorr_last_op, "sign");
    assert.equal(r.value.schnorr_last_input, "hi");
    assert.equal(r.value.schnorr_last_R, null);
    assert.equal(r.value.schnorr_last_s, null);
    assert.equal(r.value.schnorr_verify_result, null);
    assert.equal(r.value.schnorr_op_error, null);
    // keypair still written so the lesson template can render it
    assert.ok(/^\d+$/.test(r.value.schnorr_keypair_x));
    assert.ok(/^\d+$/.test(r.value.schnorr_keypair_X));
  } finally {
    if (originalDescriptor) Object.defineProperty(globalThis, "crypto", originalDescriptor);
    else delete globalThis.crypto;
  }
});

test("info always ok", () => {
  assert.deepEqual(v.info("anything", {}), { ok: true, value: {} });
});

test("walkthroughs.schnorr_operation returns 3 non-empty string rungs", () => {
  assert.equal(typeof v.walkthroughs.schnorr_operation, "function");
  const rungs = v.walkthroughs.schnorr_operation({});
  assert.ok(Array.isArray(rungs));
  assert.equal(rungs.length, 3);
  rungs.forEach((r) => {
    assert.equal(typeof r, "string");
    assert.ok(r.length > 0);
  });
});
