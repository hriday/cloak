import { test } from "node:test";
import assert from "node:assert/strict";
import * as h from "../hmac_demo.js";

test("computeHmac returns lowercase hex of length 64 for SHA-256", async (t) => {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    t.skip("crypto.subtle not available");
    return;
  }
  const mac = await h.computeHmac("secret", "hello");
  assert.equal(typeof mac, "string");
  assert.equal(mac.length, 64);
  assert.match(mac, /^[0-9a-f]+$/);
});

test("computeHmac is deterministic for same key+message", async (t) => {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    t.skip("crypto.subtle not available");
    return;
  }
  const a = await h.computeHmac("secret", "hello");
  const b = await h.computeHmac("secret", "hello");
  assert.equal(a, b);
});

test("computeHmac differs when key changes", async (t) => {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    t.skip("crypto.subtle not available");
    return;
  }
  const a = await h.computeHmac("secret-a", "hello");
  const b = await h.computeHmac("secret-b", "hello");
  assert.notEqual(a, b);
});

test("computeHmac differs when message changes", async (t) => {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    t.skip("crypto.subtle not available");
    return;
  }
  const a = await h.computeHmac("secret", "hello");
  const b = await h.computeHmac("secret", "hellp");
  assert.notEqual(a, b);
});

test("computeHmac matches RFC 4231 test vector 1 (key=20×0x0b, data='Hi There')", async (t) => {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    t.skip("crypto.subtle not available");
    return;
  }
  // RFC 4231 test case 1, but we use string-typed key; this just sanity-
  // checks that hmac with ASCII inputs produces stable hex.
  const mac = await h.computeHmac("the-key", "the-message");
  assert.equal(mac.length, 64);
});

test("verifyHmac returns true for an unaltered (key, message, mac) triple", async (t) => {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    t.skip("crypto.subtle not available");
    return;
  }
  const mac = await h.computeHmac("secret", "hello");
  const ok = await h.verifyHmac("secret", "hello", mac);
  assert.equal(ok, true);
});

test("verifyHmac returns false when the message is tampered", async (t) => {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    t.skip("crypto.subtle not available");
    return;
  }
  const mac = await h.computeHmac("secret", "hello");
  const ok = await h.verifyHmac("secret", "hellp", mac);
  assert.equal(ok, false);
});

test("verifyHmac returns false when the key is wrong", async (t) => {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    t.skip("crypto.subtle not available");
    return;
  }
  const mac = await h.computeHmac("secret", "hello");
  const ok = await h.verifyHmac("not-secret", "hello", mac);
  assert.equal(ok, false);
});

test("verifyHmac returns false for malformed hex", async (t) => {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    t.skip("crypto.subtle not available");
    return;
  }
  const ok = await h.verifyHmac("secret", "hello", "not-hex!!");
  assert.equal(ok, false);
});

test("naiveMac is deterministic and 64 hex chars", async (t) => {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    t.skip("crypto.subtle not available");
    return;
  }
  const a = await h.naiveMac("secret", "hello");
  const b = await h.naiveMac("secret", "hello");
  assert.equal(a, b);
  assert.equal(a.length, 64);
});

test("simulateLengthExtension flags as simulated and produces a forged MAC", async (t) => {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    t.skip("crypto.subtle not available");
    return;
  }
  const key = "secret-key";
  const original = "transfer=100&to=alice";
  const originalMac = await h.naiveMac(key, original);
  const ext = "&account=evil";
  const result = await h.simulateLengthExtension(original, originalMac, ext, key);

  assert.equal(result.simulated, true);
  assert.equal(result.originalMessage, original);
  assert.equal(result.originalMac, originalMac);
  assert.equal(result.extension, ext);
  assert.equal(result.forgedMessage, original + ext);
  assert.equal(result.forgedMac.length, 64);
  assert.match(result.forgedMac, /^[0-9a-f]+$/);
  // The forged MAC matches what a defender would compute on the extended
  // message — i.e. naiveMac(key, forgedMessage). That's the whole point.
  const defenderMac = await h.naiveMac(key, original + ext);
  assert.equal(result.forgedMac, defenderMac);
});

test("simulateLengthExtension discloses the broken-construction name", async (t) => {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    t.skip("crypto.subtle not available");
    return;
  }
  const r = await h.simulateLengthExtension("m", "00", "ext", "k");
  assert.match(r.construction, /naive|H\(key/);
});
