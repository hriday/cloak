import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

const MD5_HASH = "79054025255fb1a26e4bc422aef54eb4";
const SHA1_HASH = "38762cf7f55934b34d179ae6a4c80cadccbb7f0a";

const MD5_BLOB_1_PREFIX = "d131dd02c5e6eec4693d9a0698aff95c";
const MD5_BLOB_2_PREFIX = "d131dd02c5e6eec4693d9a0698aff95c";

test("full_script imports hashlib (stdlib — no install needed)", () => {
  const out = c.full_script({});
  assert.match(out, /^import hashlib$/m);
});

test("full_script embeds the two MD5 colliding blobs as bytes.fromhex literals", () => {
  const out = c.full_script({});
  assert.match(out, /BLOB_1 = bytes\.fromhex\(/);
  assert.match(out, /BLOB_2 = bytes\.fromhex\(/);
  // First 32 hex of each blob (shared prefix).
  assert.match(out, new RegExp(MD5_BLOB_1_PREFIX));
  assert.match(out, new RegExp(MD5_BLOB_2_PREFIX));
});

test("full_script hashes both MD5 blobs and asserts equality", () => {
  const out = c.full_script({});
  assert.match(out, /hashlib\.md5\(BLOB_1\)/);
  assert.match(out, /hashlib\.md5\(BLOB_2\)/);
  assert.match(out, /assert h1 == h2 ==/);
});

test("full_script asserts the canonical Wang/Stevens MD5 collision hash", () => {
  const out = c.full_script({});
  assert.match(out, new RegExp(MD5_HASH));
});

test("full_script includes the SHAttered published SHA-1 hash", () => {
  const out = c.full_script({});
  assert.match(out, new RegExp(SHA1_HASH));
});

test("full_script shows a shasum command to verify the SHAttered PDFs", () => {
  const out = c.full_script({});
  assert.match(out, /shasum -a 1 shattered-1\.pdf shattered-2\.pdf/);
});

test("full_script points to shattered.io for the colliding files", () => {
  const out = c.full_script({});
  assert.match(out, /shattered\.io/);
});

test("full_script computes the byte-diff count between the two MD5 blobs", () => {
  const out = c.full_script({});
  assert.match(out, /sum\(1 for a, b in zip\(BLOB_1, BLOB_2\)/);
});

test("full_script smoke-tests hashlib.sha1 against the FIPS test vector", () => {
  const out = c.full_script({});
  assert.match(out, /hashlib\.sha1\(b"abc"\)/);
  assert.match(out, /a9993e364706816aba3e25717850c26c9cd0d89d/);
});

test("full_script warns NOT to use MD5 or SHA-1 for crypto", () => {
  const out = c.full_script({});
  assert.match(out, /Do not use MD5/i);
  assert.match(out, /Do not use SHA-1/i);
});

test("full_script names the published collision references", () => {
  const out = c.full_script({});
  assert.match(out, /Wang/);          // Wang & Yu / Wang/Stevens
  assert.match(out, /SHAttered/i);
  assert.match(out, /Stevens/);
});

test("full_script recommends modern hash functions", () => {
  const out = c.full_script({});
  // Should point to safe replacements somewhere.
  assert.match(out, /SHA-?256/i);
  assert.match(out, /BLAKE2|BLAKE3|SHA-?3/);
});

test("per-step stubs return empty strings", () => {
  for (const key of [
    "intro",
    "md5_collisions",
    "verify_md5_collision",
    "sha1_collisions",
    "verify_sha1_collision",
    "defenses_and_state",
    "done",
    "info",
  ]) {
    assert.equal(typeof c[key], "function", `${key} should be exported`);
    assert.equal(c[key]({}), "", `${key} should return ""`);
  }
});

test("full_script is valid Python syntax-shaped output (no unclosed strings)", () => {
  const out = c.full_script({});
  // Each line either is balanced or is inside a docstring. Quick sanity
  // check: triple-quoted docstring opens and closes exactly twice each.
  const tripleDoubles = (out.match(/"""/g) || []).length;
  assert.equal(tripleDoubles, 2, "expected exactly two triple-quote markers (open + close)");
});
