import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

// ---------- compute_md5_collision ----------

test("compute_md5_collision succeeds and writes the canonical hash", async () => {
  const r = await v.compute_md5_collision(null, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.coll_md5_hash, "79054025255fb1a26e4bc422aef54eb4");
  assert.equal(r.value.coll_md5_match, true);
});

test("compute_md5_collision exposes the blobs' first 16 bytes (preview for UI)", async () => {
  const r = await v.compute_md5_collision(null, {});
  // Both blobs start with the same 16 bytes (they only differ at positions
  // 19, 45, 59, 83, 109, 123 — all beyond byte 16).
  assert.equal(r.value.coll_md5_blob1_first16, r.value.coll_md5_blob2_first16);
  // Specifically: d131dd02c5e6eec4693d9a0698aff95c
  assert.equal(r.value.coll_md5_blob1_first16, "d131dd02c5e6eec4693d9a0698aff95c");
});

test("compute_md5_collision records 128-byte blob length", async () => {
  const r = await v.compute_md5_collision(null, {});
  assert.equal(r.value.coll_md5_blob_bytes, 128);
});

test("compute_md5_collision records the 6-byte diff count", async () => {
  const r = await v.compute_md5_collision(null, {});
  assert.equal(r.value.coll_md5_byte_diff_count, 6);
});

test("compute_md5_collision ignores its input argument (it's a button press)", async () => {
  const r1 = await v.compute_md5_collision(null, {});
  const r2 = await v.compute_md5_collision("anything", {});
  const r3 = await v.compute_md5_collision({ junk: true }, {});
  assert.equal(r1.value.coll_md5_hash, r2.value.coll_md5_hash);
  assert.equal(r1.value.coll_md5_hash, r3.value.coll_md5_hash);
});

// ---------- compute_sha1_collision ----------

test("compute_sha1_collision records the published SHAttered hash", () => {
  const r = v.compute_sha1_collision(null, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.coll_sha1_hash, "38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
});

test("compute_sha1_collision records the PDF byte size", () => {
  const r = v.compute_sha1_collision(null, {});
  assert.equal(r.value.coll_sha1_pdf_bytes, 422435);
});

test("compute_sha1_collision exposes the shattered.io download URL", () => {
  const r = v.compute_sha1_collision(null, {});
  assert.match(r.value.coll_sha1_download, /shattered\.io/);
});

test("compute_sha1_collision exposes a verifiable shasum command", () => {
  const r = v.compute_sha1_collision(null, {});
  assert.match(r.value.coll_sha1_verify_cmd, /shasum/);
  assert.match(r.value.coll_sha1_verify_cmd, /shattered-1\.pdf/);
  assert.match(r.value.coll_sha1_verify_cmd, /shattered-2\.pdf/);
});

// ---------- info ----------

test("info always ok", () => {
  assert.deepEqual(v.info("anything", {}), { ok: true, value: {} });
  assert.deepEqual(v.info(null, {}), { ok: true, value: {} });
});

// ---------- walkthroughs ----------

test("walkthroughs has compute_md5_collision with 3 rungs", () => {
  assert.equal(typeof v.walkthroughs.compute_md5_collision, "function");
  const rungs = v.walkthroughs.compute_md5_collision({});
  assert.equal(rungs.length, 3);
  rungs.forEach((r) => assert.equal(typeof r, "string"));
});

test("compute_md5_collision walkthrough final rung reveals the canonical hash", () => {
  const rungs = v.walkthroughs.compute_md5_collision({});
  assert.match(rungs[2], /79054025255fb1a26e4bc422aef54eb4/);
});

test("walkthroughs has compute_sha1_collision with 3 rungs", () => {
  const rungs = v.walkthroughs.compute_sha1_collision({});
  assert.equal(rungs.length, 3);
  rungs.forEach((r) => assert.equal(typeof r, "string"));
});

test("compute_sha1_collision walkthrough mentions the SHAttered hash and the cost", () => {
  const rungs = v.walkthroughs.compute_sha1_collision({});
  assert.match(rungs[1], /38762cf7f55934b34d179ae6a4c80cadccbb7f0a/);
  // Cost / compute mentioned somewhere (2^63 SHA-1 computations, written
  // with Unicode superscripts in the prose).
  const joined = rungs.join(" ");
  assert.match(joined, /2⁶³/);
});
