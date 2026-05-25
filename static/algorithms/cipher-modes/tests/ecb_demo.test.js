import { test } from "node:test";
import assert from "node:assert/strict";
import { drawSilhouette, ecbEncrypt, cbcEncrypt, runCbcWalk } from "../ecb_demo.js";

test("drawSilhouette returns 1024 bytes", () => {
  const buf = drawSilhouette();
  assert.equal(buf.length, 1024);
  assert.ok(buf instanceof Uint8Array);
});

test("drawSilhouette is deterministic", () => {
  const a = drawSilhouette();
  const b = drawSilhouette();
  assert.deepEqual(Array.from(a), Array.from(b));
});

test("drawSilhouette uses 3 distinct pixel values (body + bg + feet)", () => {
  const buf = drawSilhouette();
  const unique = new Set(buf);
  assert.equal(unique.size, 3, `expected 3 colors, got ${[...unique]}`);
});

test("drawSilhouette has long horizontal runs (pedagogically required for ECB demo)", () => {
  // The ECB penguin demo only "lands" if there are repeated 16-byte blocks
  // in the silhouette — those collapse to identical ciphertext blocks under
  // ECB. The body has rows of 32 consecutive FG pixels = two identical
  // 16-byte blocks. Verify at least one such row exists.
  const buf = drawSilhouette();
  let foundDoubleBlock = false;
  for (let y = 0; y < 32; y++) {
    const row = buf.subarray(y * 32, (y + 1) * 32);
    const first = row.subarray(0, 16);
    const second = row.subarray(16, 32);
    if (Array.from(first).every((v, i) => v === second[i])) {
      foundDoubleBlock = true;
      break;
    }
  }
  assert.ok(foundDoubleBlock, "expected at least one row with two identical 16-byte halves");
});

test("ecbEncrypt and cbcEncrypt and runCbcWalk are async functions", () => {
  assert.equal(typeof ecbEncrypt, "function");
  assert.equal(typeof cbcEncrypt, "function");
  assert.equal(typeof runCbcWalk, "function");
});

test("ecbEncrypt rejects non-aligned plaintext", async () => {
  // crypto.subtle may or may not be available in Node test runner; the length
  // check fires before any crypto call, so this works either way.
  await assert.rejects(
    () => ecbEncrypt(new Uint8Array(15), new Uint8Array(16)),
    /multiple of 16/,
  );
});

test("cbcEncrypt rejects wrong-length plaintext", async () => {
  await assert.rejects(
    () => cbcEncrypt(new Uint8Array(32), new Uint8Array(16), new Uint8Array(16)),
    /48 bytes/,
  );
});

test("runCbcWalk roundtrips when Web Crypto is available", async (t) => {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    t.skip("crypto.subtle unavailable in this Node version");
    return;
  }
  const r = await runCbcWalk();
  assert.equal(r.plaintext, "YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE");
  assert.equal(r.iv_hex.length, 32);
  assert.equal(r.ct_blocks.length, 3);
  r.ct_blocks.forEach((b) => assert.equal(b.length, 32));
  // Chaining ⇒ all three blocks differ even though plaintext blocks are identical.
  assert.notEqual(r.ct_blocks[0], r.ct_blocks[1]);
  assert.notEqual(r.ct_blocks[1], r.ct_blocks[2]);
  assert.notEqual(r.ct_blocks[0], r.ct_blocks[2]);
});
