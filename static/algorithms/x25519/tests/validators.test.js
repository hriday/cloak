import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

// ---- compute_dh -----------------------------------------------------------

test("compute_dh accepts integer 2", () => {
  const r = v.compute_dh(2, {});
  assert.equal(r.ok, true);
  assert.deepEqual(r.value, { x25_classical_shared: 2 });
});

test("compute_dh accepts string '2'", () => {
  const r = v.compute_dh("2", {});
  assert.equal(r.ok, true);
  assert.equal(r.value.x25_classical_shared, 2);
});

test("compute_dh accepts ' 2 ' with surrounding whitespace", () => {
  const r = v.compute_dh(" 2 ", {});
  assert.equal(r.ok, true);
});

test("compute_dh rejects empty string", () => {
  const r = v.compute_dh("", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /whole number/i);
});

test("compute_dh rejects 'abc'", () => {
  const r = v.compute_dh("abc", {});
  assert.equal(r.ok, false);
});

test("compute_dh rejects wrong value 3 with the 19^6 mod 23 walkthrough", () => {
  const r = v.compute_dh(3, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /19/);
  assert.match(r.hint, /23/);
});

test("compute_dh rejects decimal-looking floats", () => {
  const r = v.compute_dh("2.5", {});
  assert.equal(r.ok, false);
});

// ---- clamp_byte -----------------------------------------------------------

test("clamp_byte accepts 0xA0 (lowercase 0x prefix)", () => {
  const r = v.clamp_byte("0xA0", {});
  assert.equal(r.ok, true);
  assert.deepEqual(r.value, { x25_clamped: "0xA0" });
});

test("clamp_byte accepts 0xa0 (lowercase letters)", () => {
  const r = v.clamp_byte("0xa0", {});
  assert.equal(r.ok, true);
});

test("clamp_byte accepts bare hex 'a0'", () => {
  const r = v.clamp_byte("a0", {});
  assert.equal(r.ok, true);
});

test("clamp_byte accepts decimal 160 (= 0xA0)", () => {
  const r = v.clamp_byte("160", {});
  assert.equal(r.ok, true);
});

test("clamp_byte accepts integer 160", () => {
  const r = v.clamp_byte(160, {});
  assert.equal(r.ok, true);
});

test("clamp_byte rejects out-of-range 256", () => {
  const r = v.clamp_byte("256", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /0–255|0-255/);
});

test("clamp_byte rejects negative -1", () => {
  const r = v.clamp_byte("-1", {});
  assert.equal(r.ok, false);
});

test("clamp_byte rejects unparseable 'zzz'", () => {
  const r = v.clamp_byte("zzz", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /hex|decimal/i);
});

test("clamp_byte rejects empty string", () => {
  const r = v.clamp_byte("", {});
  assert.equal(r.ok, false);
});

test("clamp_byte rejects wrong value 0xA7 (the unclamped input) with bit-walk hint", () => {
  const r = v.clamp_byte("0xA7", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /0xA7|10100111/);
  assert.match(r.hint, /0xF8|11111000/);
});

test("clamp_byte rejects wrong value 0xB0 (the spec's example, not ours)", () => {
  const r = v.clamp_byte("0xB0", {});
  assert.equal(r.ok, false);
});

// ---- exchange_keys --------------------------------------------------------

test("exchange_keys returns ok with the four state keys when crypto.subtle works", async () => {
  const r = await v.exchange_keys(null, {});
  assert.equal(r.ok, true);
  assert.equal(typeof r.value.x25_alice_pub, "string");
  assert.equal(typeof r.value.x25_bob_pub, "string");
  assert.equal(typeof r.value.x25_shared_secret, "string");
  assert.equal(r.value.x25_alice_pub.length, 64);
  assert.equal(r.value.x25_bob_pub.length, 64);
  assert.equal(r.value.x25_shared_secret.length, 64);
  assert.equal(r.value.x25_shared_secret, r.value.x25_shared_from_b);
  assert.equal(r.value.x25_match, true);
  assert.equal(typeof r.value.x25_used_fallback, "boolean");
});

test("exchange_keys writes match=true even on the fallback path", async () => {
  const originalDescriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  Object.defineProperty(globalThis, "crypto", {
    value: { getRandomValues: () => new Uint8Array(32) }, // no .subtle
    configurable: true,
    writable: true,
  });
  try {
    const r = await v.exchange_keys(null, {});
    assert.equal(r.ok, true);
    assert.equal(r.value.x25_used_fallback, true);
    assert.equal(r.value.x25_match, true);
    assert.equal(r.value.x25_shared_secret, r.value.x25_shared_from_b);
    // Should be the RFC 7748 §6.1 shared.
    assert.equal(
      r.value.x25_shared_secret,
      "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    );
  } finally {
    if (originalDescriptor) {
      Object.defineProperty(globalThis, "crypto", originalDescriptor);
    } else {
      delete globalThis.crypto;
    }
  }
});

// ---- info -----------------------------------------------------------------

test("info always ok with empty value", () => {
  assert.deepEqual(v.info("anything", {}), { ok: true, value: {} });
  assert.deepEqual(v.info(null, {}), { ok: true, value: {} });
});

// ---- walkthroughs ---------------------------------------------------------

test("walkthroughs.compute_dh returns 3 non-empty string rungs", () => {
  assert.equal(typeof v.walkthroughs.compute_dh, "function");
  const rungs = v.walkthroughs.compute_dh({});
  assert.equal(rungs.length, 3);
  rungs.forEach((r) => {
    assert.equal(typeof r, "string");
    assert.ok(r.length > 0);
  });
});

test("walkthroughs.clamp_byte returns 3 non-empty string rungs", () => {
  assert.equal(typeof v.walkthroughs.clamp_byte, "function");
  const rungs = v.walkthroughs.clamp_byte({});
  assert.equal(rungs.length, 3);
  rungs.forEach((r) => {
    assert.equal(typeof r, "string");
    assert.ok(r.length > 0);
  });
});
