import { test } from "node:test";
import assert from "node:assert/strict";
import * as coll from "../coll_demo.js";

// ---------- MD5 — canonical test vectors (RFC 1321 §A.5) ----------

test("md5 of empty string", async () => {
  assert.equal(await coll.md5Hash(""), "d41d8cd98f00b204e9800998ecf8427e");
});

test("md5('a')", async () => {
  assert.equal(await coll.md5Hash("a"), "0cc175b9c0f1b6a831c399e269772661");
});

test("md5('abc') — RFC 1321 §A.5", async () => {
  assert.equal(await coll.md5Hash("abc"), "900150983cd24fb0d6963f7d28e17f72");
});

test("md5('message digest')", async () => {
  assert.equal(
    await coll.md5Hash("message digest"),
    "f96b697d7cb7938d525a2f31aaf161d0"
  );
});

test("md5('abcdefghijklmnopqrstuvwxyz')", async () => {
  assert.equal(
    await coll.md5Hash("abcdefghijklmnopqrstuvwxyz"),
    "c3fcd3d76192e4007dfb496cca67e13b"
  );
});

test("md5 of a long alphanumeric string", async () => {
  // From RFC 1321: 62 chars.
  assert.equal(
    await coll.md5Hash("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
    "d174ab98d277d9f5a5611c2c9f419d9f"
  );
});

test("md5 of 80-byte input — exercises multi-block compression", async () => {
  // > 64 bytes forces a second compression call. RFC 1321 §A.5:
  assert.equal(
    await coll.md5Hash("12345678901234567890123456789012345678901234567890123456789012345678901234567890"),
    "57edf4a22be3c955ac49da2e2107b67a"
  );
});

test("md5 output is always 32 lowercase hex characters", async () => {
  const h = await coll.md5Hash("anything");
  assert.equal(h.length, 32);
  assert.match(h, /^[0-9a-f]{32}$/);
});

// ---------- MD5 colliding blobs (Wang/Stevens) ----------

test("getMd5CollidingBlobs returns two 128-byte blobs + expected hash", () => {
  const { blob1, blob2, expectedHash } = coll.getMd5CollidingBlobs();
  assert.equal(blob1.length, 128);
  assert.equal(blob2.length, 128);
  assert.equal(expectedHash, "79054025255fb1a26e4bc422aef54eb4");
});

test("the two MD5 colliding blobs are NOT byte-identical", () => {
  const { blob1, blob2 } = coll.getMd5CollidingBlobs();
  let equal = true;
  for (let i = 0; i < blob1.length; i++) {
    if (blob1[i] !== blob2[i]) { equal = false; break; }
  }
  assert.equal(equal, false, "the two collision blobs should differ");
});

test("the two MD5 colliding blobs differ in exactly 6 bytes (Wang/Stevens canonical pair)", () => {
  const { blob1, blob2 } = coll.getMd5CollidingBlobs();
  assert.equal(coll.byteDiffCount(blob1, blob2), 6);
});

test("BOTH MD5 colliding blobs hash to 79054025255fb1a26e4bc422aef54eb4 — the load-bearing pedagogical assertion", async () => {
  const { blob1, blob2, expectedHash } = coll.getMd5CollidingBlobs();
  const h1 = await coll.md5Hash(blob1);
  const h2 = await coll.md5Hash(blob2);
  assert.equal(h1, expectedHash, "blob1 should hash to the published Wang/Stevens value");
  assert.equal(h2, expectedHash, "blob2 should hash to the published Wang/Stevens value");
  assert.equal(h1, h2, "the two blobs MUST collide under MD5 — that's the whole point of the lesson");
});

// ---------- SHA-1 (Web Crypto) ----------

test("sha1('') matches the canonical empty-string SHA-1", async () => {
  assert.equal(await coll.sha1Hash(""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
});

test("sha1('abc') matches FIPS 180-4 / RFC 3174 vector", async () => {
  assert.equal(await coll.sha1Hash("abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
});

test("sha1 output is always 40 lowercase hex characters", async () => {
  const h = await coll.sha1Hash("anything");
  assert.equal(h.length, 40);
  assert.match(h, /^[0-9a-f]{40}$/);
});

// ---------- SHAttered SHA-1 collision (fact sheet, not in-page blobs) ----------
//
// We don't bake the 422 KB colliding PDFs inline — too large, too brittle.
// The lesson shows the published hash as a fact and points users to
// shattered.io for the actual files.

test("SHATTERED_PUBLISHED_HASH is the famous SHA-1 collision digest", () => {
  assert.equal(coll.SHATTERED_PUBLISHED_HASH, "38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
});

test("SHATTERED_PDF_BYTES matches the published PDF size", () => {
  assert.equal(coll.SHATTERED_PDF_BYTES, 422435);
});

test("getSha1CollidingFactSheet returns the headline data", () => {
  const f = coll.getSha1CollidingFactSheet();
  assert.equal(f.publishedHash, "38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
  assert.equal(f.pdfBytes, 422435);
  assert.match(f.downloadUrl, /shattered\.io/);
  assert.match(f.verifyCommand, /shasum/);
});

// ---------- byteDiffCount ----------

test("byteDiffCount on identical arrays = 0", () => {
  const a = new Uint8Array([1, 2, 3, 4]);
  const b = new Uint8Array([1, 2, 3, 4]);
  assert.equal(coll.byteDiffCount(a, b), 0);
});

test("byteDiffCount counts each differing byte", () => {
  const a = new Uint8Array([1, 2, 3, 4]);
  const b = new Uint8Array([1, 9, 3, 9]);
  assert.equal(coll.byteDiffCount(a, b), 2);
});

test("byteDiffCount throws on length mismatch", () => {
  const a = new Uint8Array([1]);
  const b = new Uint8Array([1, 2]);
  assert.throws(() => coll.byteDiffCount(a, b), /same length/);
});

// ---------- Determinism / round-trips ----------

test("md5Hash is deterministic", async () => {
  const a = await coll.md5Hash("hello world");
  const b = await coll.md5Hash("hello world");
  assert.equal(a, b);
});

test("md5Hash accepts both strings and Uint8Arrays", async () => {
  const fromStr = await coll.md5Hash("hello");
  const fromBytes = await coll.md5Hash(new TextEncoder().encode("hello"));
  assert.equal(fromStr, fromBytes);
  assert.equal(fromStr, "5d41402abc4b2a76b9719d911017c592");
});

test("MD5_COLLISION_HASH export matches the canonical Wang/Stevens value", () => {
  assert.equal(coll.MD5_COLLISION_HASH, "79054025255fb1a26e4bc422aef54eb4");
});
