import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

function hasSubtle() {
  return typeof crypto !== "undefined" && crypto.subtle != null;
}

// ---- derive_keys ----------------------------------------------------------

test("derive_keys returns ok with the six expected state keys on the happy path", async (t) => {
  if (!hasSubtle()) { t.skip("crypto.subtle not available"); return; }
  const r = await v.derive_keys(null, {});
  assert.equal(r.ok, true);
  assert.equal(typeof r.value.hkdf_seed_used, "string");
  assert.equal(typeof r.value.hkdf_prk, "string");
  assert.equal(typeof r.value.hkdf_client_key, "string");
  assert.equal(typeof r.value.hkdf_server_key, "string");
  assert.equal(typeof r.value.hkdf_client_iv, "string");
  assert.equal(typeof r.value.hkdf_server_iv, "string");
});

test("derive_keys writes the right hex lengths (16-byte keys, 12-byte IVs)", async (t) => {
  if (!hasSubtle()) { t.skip("crypto.subtle not available"); return; }
  const r = await v.derive_keys(null, {});
  assert.equal(r.value.hkdf_client_key.length, 32);
  assert.equal(r.value.hkdf_server_key.length, 32);
  assert.equal(r.value.hkdf_client_iv.length, 24);
  assert.equal(r.value.hkdf_server_iv.length, 24);
  // PRK is 32 bytes for SHA-256.
  assert.equal(r.value.hkdf_prk.length, 64);
});

test("derive_keys: the four derived outputs are all distinct", async (t) => {
  if (!hasSubtle()) { t.skip("crypto.subtle not available"); return; }
  const r = await v.derive_keys(null, {});
  const set = new Set([
    r.value.hkdf_client_key,
    r.value.hkdf_server_key,
    r.value.hkdf_client_iv,
    r.value.hkdf_server_iv,
  ]);
  assert.equal(set.size, 4);
});

test("derive_keys is deterministic across calls (fixed seed)", async (t) => {
  if (!hasSubtle()) { t.skip("crypto.subtle not available"); return; }
  const a = await v.derive_keys(null, {});
  const b = await v.derive_keys(null, {});
  assert.equal(a.value.hkdf_prk, b.value.hkdf_prk);
  assert.equal(a.value.hkdf_client_key, b.value.hkdf_client_key);
  assert.equal(a.value.hkdf_server_key, b.value.hkdf_server_key);
  assert.equal(a.value.hkdf_client_iv,  b.value.hkdf_client_iv);
  assert.equal(a.value.hkdf_server_iv,  b.value.hkdf_server_iv);
});

test("derive_keys ignores its input argument (it's button-driven)", async (t) => {
  if (!hasSubtle()) { t.skip("crypto.subtle not available"); return; }
  const a = await v.derive_keys(null, {});
  const b = await v.derive_keys("any string", {});
  const c = await v.derive_keys({ anything: true }, {});
  assert.equal(a.value.hkdf_client_key, b.value.hkdf_client_key);
  assert.equal(a.value.hkdf_client_key, c.value.hkdf_client_key);
});

test("derive_keys output hex chars are valid 0-9a-f", async (t) => {
  if (!hasSubtle()) { t.skip("crypto.subtle not available"); return; }
  const r = await v.derive_keys(null, {});
  for (const v of [
    r.value.hkdf_prk,
    r.value.hkdf_client_key,
    r.value.hkdf_server_key,
    r.value.hkdf_client_iv,
    r.value.hkdf_server_iv,
  ]) {
    assert.match(v, /^[0-9a-f]+$/);
  }
});

test("derive_keys no-crypto fallback returns ok with null OKMs", async () => {
  const originalDescriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  Object.defineProperty(globalThis, "crypto", {
    value: { getRandomValues: () => new Uint8Array(16) }, // no .subtle
    configurable: true,
    writable: true,
  });
  try {
    const r = await v.derive_keys(null, {});
    assert.equal(r.ok, true);
    assert.equal(r.value.hkdf_client_key, null);
    assert.equal(r.value.hkdf_server_key, null);
    assert.equal(r.value.hkdf_client_iv, null);
    assert.equal(r.value.hkdf_server_iv, null);
    assert.equal(r.value.hkdf_prk, null);
    assert.equal(typeof r.value.hkdf_seed_used, "string");
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

test("walkthroughs.derive_keys returns 3 non-empty string rungs", () => {
  assert.equal(typeof v.walkthroughs.derive_keys, "function");
  const rungs = v.walkthroughs.derive_keys({});
  assert.ok(Array.isArray(rungs));
  assert.equal(rungs.length, 3);
  rungs.forEach((r) => {
    assert.equal(typeof r, "string");
    assert.ok(r.length > 0);
  });
});

test("walkthroughs.derive_keys mentions Expand, PRK, and the four labels", () => {
  const joined = v.walkthroughs.derive_keys({}).join(" ");
  assert.match(joined, /Expand/);
  assert.match(joined, /PRK/);
  assert.match(joined, /client write key/);
  assert.match(joined, /server write key/);
});
