import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";
import {
  SIG_HEX_LEN,
  serializeSignature,
  deserializeSignature,
  _resetForTests,
} from "../validators.js";
import {
  N_BYTES,
  NUM_CHUNKS,
  NUM_LEAVES,
  TREE_HEIGHT,
  sphincsKeygen,
  sphincsSign,
  lessonSeedBytes,
} from "../sphincs_demo.js";

// ---- signature serialisation ---------------------------------------------

test("SIG_HEX_LEN matches the toy parameters (1 + 8*32 + 3*32 = 353)", () => {
  assert.equal(SIG_HEX_LEN, 1 + NUM_CHUNKS * N_BYTES * 2 + TREE_HEIGHT * N_BYTES * 2);
  assert.equal(SIG_HEX_LEN, 353);
});

test("serialize → deserialize round-trip on a real signature", async () => {
  _resetForTests();
  const seed = await lessonSeedBytes();
  const { sk } = await sphincsKeygen(seed);
  const sig = await sphincsSign(new TextEncoder().encode("hello"), sk);
  const hex = serializeSignature(sig);
  assert.equal(hex.length, SIG_HEX_LEN);
  const recovered = deserializeSignature(hex);
  assert.equal(recovered.leafIndex, sig.leafIndex);
  assert.equal(recovered.wotsSig.length, NUM_CHUNKS);
  assert.equal(recovered.authPath.length, TREE_HEIGHT);
  for (let i = 0; i < NUM_CHUNKS; i++) {
    assert.deepEqual(Array.from(recovered.wotsSig[i]), Array.from(sig.wotsSig[i]));
  }
  for (let i = 0; i < TREE_HEIGHT; i++) {
    assert.deepEqual(Array.from(recovered.authPath[i]), Array.from(sig.authPath[i]));
  }
});

test("deserializeSignature rejects wrong length", () => {
  assert.throws(() => deserializeSignature("abc"), /length/);
});

test("deserializeSignature rejects non-hex characters", () => {
  const bad = "z".repeat(SIG_HEX_LEN);
  assert.throws(() => deserializeSignature(bad), /hex/i);
});

test("deserializeSignature rejects an out-of-range leaf index", () => {
  const tail = "0".repeat(SIG_HEX_LEN - 1);
  assert.throws(() => deserializeSignature("8" + tail), /leafIndex/);
  assert.throws(() => deserializeSignature("f" + tail), /leafIndex/);
});

// ---- sphincs_operation input validation ----------------------------------

test("sphincs_operation rejects missing op", async () => {
  const r = await v.sphincs_operation({ message: "hi" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /sign|verify/i);
});

test("sphincs_operation rejects empty message", async () => {
  const r = await v.sphincs_operation({ op: "sign", message: "" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /something|empty/i);
});

test("sphincs_operation rejects verify without signature", async () => {
  const r = await v.sphincs_operation({ op: "verify", message: "hi" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /signature/i);
});

test("sphincs_operation rejects verify with wrong-length signature", async () => {
  const r = await v.sphincs_operation(
    { op: "verify", message: "hi", signature: "abcd" },
    {}
  );
  assert.equal(r.ok, false);
  assert.match(r.hint, new RegExp(String(SIG_HEX_LEN)));
});

test("sphincs_operation rejects verify with right-length non-hex signature", async () => {
  const r = await v.sphincs_operation(
    { op: "verify", message: "hi", signature: "z".repeat(SIG_HEX_LEN) },
    {}
  );
  assert.equal(r.ok, false);
  assert.match(r.hint, /hex/i);
});

// ---- sphincs_operation happy paths ---------------------------------------

test("sphincs_operation sign happy path writes the lesson state keys", async () => {
  _resetForTests();
  const r = await v.sphincs_operation({ op: "sign", message: "hello" }, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.sphincs_last_op, "sign");
  assert.equal(r.value.sphincs_last_input, "hello");
  assert.equal(typeof r.value.sphincs_signature, "string");
  assert.equal(r.value.sphincs_signature.length, SIG_HEX_LEN);
  assert.match(r.value.sphincs_signature, /^[0-9a-f]+$/);
  assert.equal(typeof r.value.sphincs_leaf_index, "number");
  assert.ok(r.value.sphincs_leaf_index >= 0 && r.value.sphincs_leaf_index < NUM_LEAVES);
  assert.equal(typeof r.value.sphincs_root, "string");
  assert.equal(r.value.sphincs_root.length, N_BYTES * 2);
  assert.equal(r.value.sphincs_verify_result, null);
  assert.equal(r.value.sphincs_op_error, null);
});

test("sphincs_operation verify returns true on a valid round-trip", async () => {
  _resetForTests();
  const signed = await v.sphincs_operation({ op: "sign", message: "hello" }, {});
  const sig = signed.value.sphincs_signature;
  const verified = await v.sphincs_operation(
    { op: "verify", message: "hello", signature: sig },
    {}
  );
  assert.equal(verified.ok, true);
  assert.equal(verified.value.sphincs_verify_result, true);
  assert.equal(verified.value.sphincs_last_op, "verify");
});

test("sphincs_operation verify returns false (not an error) for a tampered signature", async () => {
  _resetForTests();
  const signed = await v.sphincs_operation({ op: "sign", message: "hello" }, {});
  const sig = signed.value.sphincs_signature;
  // Flip the first hex char of the WOTS+ portion (skip the leaf-index nibble).
  const tampered = sig.slice(0, 1) + (sig[1] === "0" ? "1" : "0") + sig.slice(2);
  const verified = await v.sphincs_operation(
    { op: "verify", message: "hello", signature: tampered },
    {}
  );
  assert.equal(verified.ok, true);
  assert.equal(verified.value.sphincs_verify_result, false);
});

test("sphincs_operation verify returns false for a wrong message", async () => {
  _resetForTests();
  const signed = await v.sphincs_operation({ op: "sign", message: "hello" }, {});
  const sig = signed.value.sphincs_signature;
  const verified = await v.sphincs_operation(
    { op: "verify", message: "HELLO", signature: sig },
    {}
  );
  assert.equal(verified.ok, true);
  assert.equal(verified.value.sphincs_verify_result, false);
});

test("sphincs_operation uppercase hex signature is accepted (normalized to lowercase)", async () => {
  _resetForTests();
  const signed = await v.sphincs_operation({ op: "sign", message: "hello" }, {});
  const sigUpper = signed.value.sphincs_signature.toUpperCase();
  const verified = await v.sphincs_operation(
    { op: "verify", message: "hello", signature: sigUpper },
    {}
  );
  assert.equal(verified.ok, true);
  assert.equal(verified.value.sphincs_verify_result, true);
});

test("sphincs_operation surfaces the public-key root identically across sign and verify", async () => {
  _resetForTests();
  const signed = await v.sphincs_operation({ op: "sign", message: "a" }, {});
  const verified = await v.sphincs_operation(
    { op: "verify", message: "a", signature: signed.value.sphincs_signature },
    {}
  );
  assert.equal(signed.value.sphincs_root, verified.value.sphincs_root);
  assert.match(signed.value.sphincs_root, /^[0-9a-f]{32}$/);
});

test("sphincs_operation tolerates leading/trailing whitespace in message and signature", async () => {
  _resetForTests();
  const signed = await v.sphincs_operation({ op: "sign", message: "hello" }, {});
  const sig = signed.value.sphincs_signature;
  const verified = await v.sphincs_operation(
    { op: "verify", message: "  hello  ", signature: "  " + sig + "  " },
    {}
  );
  assert.equal(verified.ok, true);
  assert.equal(verified.value.sphincs_verify_result, true);
});

// ---- info -----------------------------------------------------------------

test("info always ok with empty value", () => {
  assert.deepEqual(v.info("anything", {}), { ok: true, value: {} });
  assert.deepEqual(v.info(null, {}), { ok: true, value: {} });
});

// ---- walkthroughs ---------------------------------------------------------

test("walkthroughs.sphincs_operation returns 3 non-empty string rungs", () => {
  assert.equal(typeof v.walkthroughs.sphincs_operation, "function");
  const rungs = v.walkthroughs.sphincs_operation({});
  assert.equal(rungs.length, 3);
  rungs.forEach((rung) => {
    assert.equal(typeof rung, "string");
    assert.ok(rung.length > 0);
  });
});

test("walkthroughs.sphincs_operation mentions WOTS+ and Merkle", () => {
  const rungs = v.walkthroughs.sphincs_operation({});
  const all = rungs.join("\n");
  assert.match(all, /WOTS\+/);
  assert.match(all, /Merkle/);
});

test("walkthroughs.sphincs_operation mentions SHA-256", () => {
  const rungs = v.walkthroughs.sphincs_operation({});
  const all = rungs.join("\n");
  assert.match(all, /SHA-256/);
});
