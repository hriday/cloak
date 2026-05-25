import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";
import { _resetForTests, getPlaintext } from "../po_simulator.js";

test("info always ok", () => {
  assert.deepEqual(v.info("anything", {}), { ok: true, value: {} });
});

test("walkthroughs has entries for recover_byte and recover_block", () => {
  assert.equal(typeof v.walkthroughs.recover_byte, "function");
  assert.equal(typeof v.walkthroughs.recover_block, "function");
  for (const k of ["recover_byte", "recover_block"]) {
    const rungs = v.walkthroughs[k]({});
    assert.ok(Array.isArray(rungs));
    assert.equal(rungs.length, 3);
    rungs.forEach((r) => {
      assert.equal(typeof r, "string");
      assert.ok(r.length > 0);
    });
  }
});

test("recover_byte happy: ok=true, writes recovered byte + queries + target", async () => {
  _resetForTests();
  const expectedPt = await getPlaintext();
  const expectedLast = expectedPt.charCodeAt(15);

  const r = await v.recover_byte(null, {});
  assert.equal(r.ok, true);
  const val = r.value;
  assert.equal(typeof val.po_recovered_byte_hex, "string");
  assert.match(val.po_recovered_byte_hex, /^[0-9a-f]{2}$/);
  assert.equal(parseInt(val.po_recovered_byte_hex, 16), expectedLast);
  assert.equal(typeof val.po_queries_made, "number");
  assert.ok(val.po_queries_made >= 1 && val.po_queries_made <= 257);
  assert.equal(typeof val.po_target_block_hex, "string");
  assert.equal(val.po_target_block_hex.length, 32);
  assert.equal(typeof val.po_target_iv_hex, "string");
  assert.equal(val.po_target_iv_hex.length, 32);
});

test("recover_block happy: ok=true, writes plaintext + total queries + target", async () => {
  _resetForTests();
  const expectedPt = await getPlaintext();

  const r = await v.recover_block(null, {});
  assert.equal(r.ok, true);
  const val = r.value;
  assert.equal(val.po_plaintext, expectedPt);
  assert.equal(typeof val.po_plaintext_hex, "string");
  assert.equal(val.po_plaintext_hex.length, 32);
  assert.equal(typeof val.po_total_queries, "number");
  assert.ok(val.po_total_queries >= 16 && val.po_total_queries <= 4200);
  assert.equal(typeof val.po_target_block_hex, "string");
  assert.equal(val.po_target_block_hex.length, 32);
});

test("recover_byte returns helpful hint when crypto.subtle is missing", async () => {
  const originalDescriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  Object.defineProperty(globalThis, "crypto", {
    value: { getRandomValues: () => new Uint8Array(16) }, // no .subtle
    configurable: true,
    writable: true,
  });
  try {
    const r = await v.recover_byte(null, {});
    assert.equal(r.ok, false);
    assert.match(r.hint, /Web Crypto/);
  } finally {
    if (originalDescriptor) {
      Object.defineProperty(globalThis, "crypto", originalDescriptor);
    } else {
      delete globalThis.crypto;
    }
  }
});

test("recover_block returns helpful hint when crypto.subtle is missing", async () => {
  const originalDescriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  Object.defineProperty(globalThis, "crypto", {
    value: { getRandomValues: () => new Uint8Array(16) },
    configurable: true,
    writable: true,
  });
  try {
    const r = await v.recover_block(null, {});
    assert.equal(r.ok, false);
    assert.match(r.hint, /Web Crypto/);
  } finally {
    if (originalDescriptor) {
      Object.defineProperty(globalThis, "crypto", originalDescriptor);
    } else {
      delete globalThis.crypto;
    }
  }
});
