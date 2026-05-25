import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

// ---- compute_hmac ----

test("compute_hmac rejects empty key", async () => {
  const r = await v.compute_hmac({ key: "", message: "hi" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /key/i);
});

test("compute_hmac rejects empty message", async () => {
  const r = await v.compute_hmac({ key: "k", message: "" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /message/i);
});

test("compute_hmac rejects oversized input", async () => {
  const big = "x".repeat(501);
  const r = await v.compute_hmac({ key: "k", message: big }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /500/);
});

test("compute_hmac rejects non-ASCII in message", async () => {
  const r = await v.compute_hmac({ key: "k", message: "héllo" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /ASCII/);
});

test("compute_hmac rejects non-ASCII in key", async () => {
  const r = await v.compute_hmac({ key: "kéy", message: "hi" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /ASCII/);
});

test("compute_hmac rejects newlines", async () => {
  const r = await v.compute_hmac({ key: "k", message: "hi\nthere" }, {});
  assert.equal(r.ok, false);
});

test("compute_hmac happy path writes hm_key, hm_message, hm_mac_hex", async (t) => {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    t.skip("crypto.subtle not available");
    return;
  }
  const r = await v.compute_hmac({ key: "secret", message: "hello" }, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.hm_key, "secret");
  assert.equal(r.value.hm_message, "hello");
  assert.equal(typeof r.value.hm_mac_hex, "string");
  assert.equal(r.value.hm_mac_hex.length, 64);
  assert.match(r.value.hm_mac_hex, /^[0-9a-f]+$/);
});

test("compute_hmac no-crypto fallback returns ok with null mac", async () => {
  const originalDescriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  Object.defineProperty(globalThis, "crypto", {
    value: { getRandomValues: () => new Uint8Array(16) }, // no .subtle
    configurable: true,
    writable: true,
  });
  try {
    const r = await v.compute_hmac({ key: "secret", message: "hello" }, {});
    assert.equal(r.ok, true);
    assert.equal(r.value.hm_key, "secret");
    assert.equal(r.value.hm_message, "hello");
    assert.equal(r.value.hm_mac_hex, null);
  } finally {
    if (originalDescriptor) {
      Object.defineProperty(globalThis, "crypto", originalDescriptor);
    } else {
      delete globalThis.crypto;
    }
  }
});

// ---- verify_hmac ----

test("verify_hmac rejects unknown action", async () => {
  const r = await v.verify_hmac({ verifyAction: "wat" }, {
    hm_key: "k", hm_message: "m", hm_mac_hex: "00".repeat(32),
  });
  assert.equal(r.ok, false);
  assert.match(r.hint, /Verify|Tamper/i);
});

test("verify_hmac rejects when state lacks hm_key", async () => {
  const r = await v.verify_hmac({ verifyAction: "verify" }, {
    hm_message: "m", hm_mac_hex: "00".repeat(32),
  });
  assert.equal(r.ok, false);
  assert.match(r.hint, /step 5/i);
});

test("verify_hmac rejects when state lacks hm_mac_hex", async () => {
  const r = await v.verify_hmac({ verifyAction: "verify" }, {
    hm_key: "k", hm_message: "m",
  });
  assert.equal(r.ok, false);
});

test("verify_hmac verify action returns true on unchanged input", async (t) => {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    t.skip("crypto.subtle not available");
    return;
  }
  const c = await v.compute_hmac({ key: "secret", message: "hello" }, {});
  const state = c.value;
  const r = await v.verify_hmac({ verifyAction: "verify" }, state);
  assert.equal(r.ok, true);
  assert.equal(r.value.hm_verify_result, true);
  assert.equal(r.value.hm_tampered, false);
  assert.equal(r.value.hm_tampered_message, null);
});

test("verify_hmac tamper action returns false and surfaces a mutated message", async (t) => {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    t.skip("crypto.subtle not available");
    return;
  }
  const c = await v.compute_hmac({ key: "secret", message: "hello" }, {});
  const state = c.value;
  const r = await v.verify_hmac({ verifyAction: "tamper" }, state);
  assert.equal(r.ok, true);
  assert.equal(r.value.hm_verify_result, false);
  assert.equal(r.value.hm_tampered, true);
  assert.equal(typeof r.value.hm_tampered_message, "string");
  assert.notEqual(r.value.hm_tampered_message, "hello");
  // The mutation should be a single-char diff at the end.
  assert.equal(r.value.hm_tampered_message.slice(0, 4), "hell");
});

test("verify_hmac no-crypto fallback returns ok with null verify_result", async () => {
  const state = {
    hm_key: "k", hm_message: "m", hm_mac_hex: "00".repeat(32),
  };
  const originalDescriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  Object.defineProperty(globalThis, "crypto", {
    value: { getRandomValues: () => new Uint8Array(16) },
    configurable: true,
    writable: true,
  });
  try {
    const r = await v.verify_hmac({ verifyAction: "verify" }, state);
    assert.equal(r.ok, true);
    assert.equal(r.value.hm_verify_result, null);
    assert.equal(r.value.hm_tampered, false);
  } finally {
    if (originalDescriptor) {
      Object.defineProperty(globalThis, "crypto", originalDescriptor);
    } else {
      delete globalThis.crypto;
    }
  }
});

// ---- info & walkthroughs ----

test("info always ok", () => {
  assert.deepEqual(v.info("anything", {}), { ok: true, value: {} });
});

test("walkthroughs.compute_hmac returns 3 non-empty string rungs", () => {
  assert.equal(typeof v.walkthroughs.compute_hmac, "function");
  const rungs = v.walkthroughs.compute_hmac({});
  assert.ok(Array.isArray(rungs));
  assert.equal(rungs.length, 3);
  rungs.forEach((r) => {
    assert.equal(typeof r, "string");
    assert.ok(r.length > 0);
  });
});

test("walkthroughs.compute_hmac mentions ipad and opad", () => {
  const rungs = v.walkthroughs.compute_hmac({});
  const joined = rungs.join(" ");
  assert.match(joined, /ipad/);
  assert.match(joined, /opad/);
});
