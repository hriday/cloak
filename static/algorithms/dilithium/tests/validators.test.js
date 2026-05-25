import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

// ---- input validation ----------------------------------------------------

test("dilithium_operation rejects missing op", async () => {
  const r = await v.dilithium_operation({ message: "hi" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /sign|verify/i);
});

test("dilithium_operation rejects empty message", async () => {
  const r = await v.dilithium_operation({ op: "sign", message: "" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /message|empty/i);
});

test("dilithium_operation rejects verify without signature", async () => {
  const r = await v.dilithium_operation({ op: "verify", message: "hi" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /signature/i);
});

test("dilithium_operation rejects verify with non-hex signature", async () => {
  const r = await v.dilithium_operation(
    { op: "verify", message: "hi", signature: "z".repeat(80) },
    {}
  );
  assert.equal(r.ok, false);
  assert.match(r.hint, /hex/i);
});

test("dilithium_operation rejects verify with wrong-length signature", async () => {
  const r = await v.dilithium_operation(
    { op: "verify", message: "hi", signature: "abcd" },
    {}
  );
  assert.equal(r.ok, false);
  assert.match(r.hint, /80 hex/i);
});

// ---- sign happy path -----------------------------------------------------

test("dilithium_operation sign returns ok with state keys", async () => {
  const r = await v.dilithium_operation({ op: "sign", message: "hello" }, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.dilithium_last_op, "sign");
  assert.equal(r.value.dilithium_last_input, "hello");
  assert.equal(typeof r.value.dilithium_signature, "string");
  assert.equal(r.value.dilithium_signature.length, 80);
  assert.match(r.value.dilithium_signature, /^[0-9a-f]+$/);
  assert.equal(r.value.dilithium_op_error, null);
  assert.ok(r.value.dilithium_attempts >= 1);
});

test("dilithium_operation sign produces different signatures on repeat (randomized)", async () => {
  const r1 = await v.dilithium_operation({ op: "sign", message: "same" }, {});
  const r2 = await v.dilithium_operation({ op: "sign", message: "same" }, {});
  assert.equal(r1.ok, true);
  assert.equal(r2.ok, true);
  // Dilithium is randomized — same message, different signature.
  // (Note: there's a tiny chance these collide if Math.random returns the
  // same float, but in practice the seed includes Date.now() and Math.random.)
  assert.notEqual(r1.value.dilithium_signature, r2.value.dilithium_signature);
});

// ---- verify round-trip ---------------------------------------------------

test("dilithium_operation verify returns true on a valid round-trip", async () => {
  const signed = await v.dilithium_operation({ op: "sign", message: "hello" }, {});
  const sig = signed.value.dilithium_signature;
  const verified = await v.dilithium_operation(
    { op: "verify", message: "hello", signature: sig },
    {}
  );
  assert.equal(verified.ok, true);
  assert.equal(verified.value.dilithium_verify_result, true);
  assert.equal(verified.value.dilithium_last_op, "verify");
});

test("dilithium_operation verify returns false (not an error) for a tampered signature", async () => {
  const signed = await v.dilithium_operation({ op: "sign", message: "hello" }, {});
  const sig = signed.value.dilithium_signature;
  const tampered = (sig[0] === "0" ? "1" : "0") + sig.slice(1);
  const verified = await v.dilithium_operation(
    { op: "verify", message: "hello", signature: tampered },
    {}
  );
  assert.equal(verified.ok, true);
  assert.equal(verified.value.dilithium_verify_result, false);
});

test("dilithium_operation verify returns false for a wrong message", async () => {
  const signed = await v.dilithium_operation({ op: "sign", message: "hello" }, {});
  const sig = signed.value.dilithium_signature;
  const verified = await v.dilithium_operation(
    { op: "verify", message: "HELLO", signature: sig },
    {}
  );
  assert.equal(verified.ok, true);
  assert.equal(verified.value.dilithium_verify_result, false);
});

test("dilithium_operation accepts uppercase hex (normalized to lowercase)", async () => {
  const signed = await v.dilithium_operation({ op: "sign", message: "hello" }, {});
  const sig = signed.value.dilithium_signature.toUpperCase();
  const verified = await v.dilithium_operation(
    { op: "verify", message: "hello", signature: sig },
    {}
  );
  assert.equal(verified.ok, true);
  assert.equal(verified.value.dilithium_verify_result, true);
});

test("dilithium_operation trims whitespace from message", async () => {
  const signed = await v.dilithium_operation({ op: "sign", message: "  hello  " }, {});
  // The trimmed message should be what gets signed.
  assert.equal(signed.value.dilithium_last_input, "hello");
});

// ---- attempts counter ---------------------------------------------------

test("dilithium_operation sign records the number of rejection-loop attempts", async () => {
  // Average across many calls — should hit attempts > 1 for some messages.
  let sawMultiAttempt = false;
  for (let i = 0; i < 30; i++) {
    const r = await v.dilithium_operation({ op: "sign", message: "attempt-" + i }, {});
    if (r.value.dilithium_attempts >= 2) sawMultiAttempt = true;
  }
  assert.ok(sawMultiAttempt, "expected at least one signature to need ≥ 2 attempts");
});

// ---- info ---------------------------------------------------------------

test("info always ok with empty value", () => {
  assert.deepEqual(v.info("anything", {}), { ok: true, value: {} });
});

// ---- walkthroughs -------------------------------------------------------

test("walkthroughs.dilithium_operation returns 3 non-empty string rungs", () => {
  assert.equal(typeof v.walkthroughs.dilithium_operation, "function");
  const rungs = v.walkthroughs.dilithium_operation({});
  assert.ok(Array.isArray(rungs));
  assert.equal(rungs.length, 3);
  for (const r of rungs) {
    assert.equal(typeof r, "string");
    assert.ok(r.length > 0);
  }
});

test("walkthroughs.dilithium_operation mentions rejection sampling", () => {
  const rungs = v.walkthroughs.dilithium_operation({});
  const all = rungs.join("\n");
  assert.match(all, /reject/i);
});

test("walkthroughs.dilithium_operation mentions A·z − c·t (or the cancellation)", () => {
  const rungs = v.walkthroughs.dilithium_operation({});
  const all = rungs.join("\n");
  // The closing math reference.
  assert.match(all, /A·z|cancel/i);
});
