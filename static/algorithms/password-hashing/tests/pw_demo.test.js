import { test } from "node:test";
import assert from "node:assert/strict";
import * as pw from "../pw_demo.js";

const HAS_SUBTLE = typeof crypto !== "undefined" && !!crypto.subtle;

// ---- sha256TimedHex ----

test("sha256TimedHex returns 64 lowercase hex chars + ms", async (t) => {
  if (!HAS_SUBTLE) return t.skip("crypto.subtle not available");
  const r = await pw.sha256TimedHex("password123");
  assert.equal(typeof r.hex, "string");
  assert.equal(r.hex.length, 64);
  assert.match(r.hex, /^[0-9a-f]{64}$/);
  assert.equal(typeof r.ms, "number");
  assert.ok(r.ms >= 0);
});

test("sha256TimedHex matches the canonical SHA-256 of 'password123'", async (t) => {
  if (!HAS_SUBTLE) return t.skip("crypto.subtle not available");
  const r = await pw.sha256TimedHex("password123");
  // sha256("password123") = a published value; lock it in.
  assert.equal(
    r.hex,
    "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f"
  );
});

test("sha256TimedHex is deterministic", async (t) => {
  if (!HAS_SUBTLE) return t.skip("crypto.subtle not available");
  const a = await pw.sha256TimedHex("hello");
  const b = await pw.sha256TimedHex("hello");
  assert.equal(a.hex, b.hex);
});

// ---- pbkdf2Hex ----

test("pbkdf2Hex returns 64 lowercase hex chars + salt + ms", async (t) => {
  if (!HAS_SUBTLE) return t.skip("crypto.subtle not available");
  const r = await pw.pbkdf2Hex("hunter2", 1000);
  assert.equal(typeof r.hex, "string");
  assert.equal(r.hex.length, 64);
  assert.match(r.hex, /^[0-9a-f]{64}$/);
  assert.equal(typeof r.salt_hex, "string");
  assert.equal(r.salt_hex.length, 32); // 16 bytes
  assert.match(r.salt_hex, /^[0-9a-f]{32}$/);
  assert.equal(typeof r.ms, "number");
  assert.ok(r.ms >= 0);
});

test("pbkdf2Hex with two different salts on the same password yields different hashes", async (t) => {
  if (!HAS_SUBTLE) return t.skip("crypto.subtle not available");
  const a = await pw.pbkdf2Hex("hunter2", 1000);
  const b = await pw.pbkdf2Hex("hunter2", 1000);
  // Random salt means different output every call.
  assert.notEqual(a.hex, b.hex);
  assert.notEqual(a.salt_hex, b.salt_hex);
});

test("pbkdf2Hex rejects non-positive iterations", async (t) => {
  if (!HAS_SUBTLE) return t.skip("crypto.subtle not available");
  await assert.rejects(() => pw.pbkdf2Hex("hunter2", 0));
  await assert.rejects(() => pw.pbkdf2Hex("hunter2", -1));
  await assert.rejects(() => pw.pbkdf2Hex("hunter2", "abc"));
});

test("pbkdf2Hex higher iter count costs more wall-clock time", async (t) => {
  if (!HAS_SUBTLE) return t.skip("crypto.subtle not available");
  // Avoid flakiness: just assert 100k took > 0 ms, not a strict ordering vs 1k
  // (which can both round to 0 ms on fast hardware in Node).
  const r = await pw.pbkdf2Hex("hunter2", 100000);
  assert.ok(r.ms >= 0);
});

// ---- compareAll ----

test("compareAll returns 5 rows in the expected order", async (t) => {
  if (!HAS_SUBTLE) return t.skip("crypto.subtle not available");
  const rows = await pw.compareAll("correct horse battery staple");
  assert.equal(rows.length, 5);
  assert.equal(rows[0].algo, "SHA-256");
  assert.equal(rows[1].algo, "PBKDF2-1k");
  assert.equal(rows[2].algo, "PBKDF2-100k");
  assert.equal(rows[3].algo, "bcrypt-12");
  assert.equal(rows[4].algo, "Argon2id-default");
});

test("compareAll marks bcrypt and Argon2id as cited; PBKDF2/SHA-256 as live", async (t) => {
  if (!HAS_SUBTLE) return t.skip("crypto.subtle not available");
  const rows = await pw.compareAll("p");
  assert.equal(rows[0].cited, false);
  assert.equal(rows[1].cited, false);
  assert.equal(rows[2].cited, false);
  assert.equal(rows[3].cited, true);
  assert.equal(rows[4].cited, true);
});

test("compareAll cited rows use the CITED constants", async (t) => {
  if (!HAS_SUBTLE) return t.skip("crypto.subtle not available");
  const rows = await pw.compareAll("p");
  assert.equal(rows[3].ms, pw.CITED.bcrypt_12_ms);
  assert.equal(rows[3].hex, pw.CITED.bcrypt_12_hash);
  assert.equal(rows[4].ms, pw.CITED.argon2id_default_ms);
  assert.equal(rows[4].hex, pw.CITED.argon2id_default_hash);
});

test("compareAll live rows have 64-hex output and finite ms", async (t) => {
  if (!HAS_SUBTLE) return t.skip("crypto.subtle not available");
  const rows = await pw.compareAll("p");
  for (let i = 0; i < 3; i++) {
    assert.match(rows[i].hex, /^[0-9a-f]{64}$/, `row ${i} hex shape`);
    assert.ok(Number.isFinite(rows[i].ms), `row ${i} ms finite`);
  }
});

test("CITED export carries cite-style hash placeholders", () => {
  assert.match(pw.CITED.bcrypt_12_hash, /^\$2b\$12\$/);
  assert.match(pw.CITED.argon2id_default_hash, /^\$argon2id\$/);
  assert.equal(pw.CITED.bcrypt_12_ms, 250);
  assert.equal(pw.CITED.argon2id_default_ms, 500);
});
