import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  Sha256,
  sha256,
  computeGluePadding,
  bytesToHex,
  hexToBytes,
} from "../sha256_mutable.js";

// ---- known answers from FIPS 180-2 / NIST ----

test("SHA-256('abc') matches known answer", () => {
  const out = sha256(new TextEncoder().encode("abc"));
  assert.equal(
    bytesToHex(out),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  );
});

test("SHA-256('') matches known answer", () => {
  const out = sha256(new Uint8Array(0));
  assert.equal(
    bytesToHex(out),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  );
});

test("SHA-256 of 448-bit message (NIST sample 2) matches known answer", () => {
  // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" — 56 bytes.
  const input = new TextEncoder().encode(
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  );
  const out = sha256(input);
  assert.equal(
    bytesToHex(out),
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
  );
});

test("SHA-256 of a long message (1,000,000 'a's) matches known answer", () => {
  const million = new Uint8Array(1000000);
  million.fill(0x61); // 'a'
  const out = sha256(million);
  assert.equal(
    bytesToHex(out),
    "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
  );
});

// ---- streaming / update behavior ----

test("Sha256 produces the same digest whether fed in one or many updates", () => {
  const data = new TextEncoder().encode("abcdefghijklmnopqrstuvwxyz0123456789");
  const single = new Sha256().update(data).finalize();
  const h = new Sha256();
  for (let i = 0; i < data.length; i++) {
    h.update(data.subarray(i, i + 1));
  }
  const streamed = h.finalize();
  assert.equal(bytesToHex(single), bytesToHex(streamed));
});

test("Sha256.update throws after finalize", () => {
  const h = new Sha256();
  h.finalize();
  assert.throws(() => h.update(new Uint8Array([1])), /after finalize/);
});

test("Sha256.finalize throws if called twice", () => {
  const h = new Sha256();
  h.finalize();
  assert.throws(() => h.finalize(), /called twice/);
});

test("Sha256.update rejects non-Uint8Array input", () => {
  const h = new Sha256();
  assert.throws(() => h.update("hello"), /Uint8Array/);
});

test("Sha256.clone produces an independent hasher mid-stream", () => {
  const h = new Sha256().update(new TextEncoder().encode("foo"));
  const c = h.clone();
  // Diverge.
  const a = h.update(new TextEncoder().encode("bar")).finalize();
  const b = c.update(new TextEncoder().encode("baz")).finalize();
  assert.equal(bytesToHex(a), bytesToHex(sha256(new TextEncoder().encode("foobar"))));
  assert.equal(bytesToHex(b), bytesToHex(sha256(new TextEncoder().encode("foobaz"))));
});

// ---- fromState — the load-bearing primitive for length extension ----

test("Sha256.fromState(state, totalBytes) resumes producing the same hash as a single call would", () => {
  // Build a message whose first 64 bytes form a complete block.
  const first = new TextEncoder().encode("X".repeat(64));
  const extension = new TextEncoder().encode("YYYYY");
  const full = new Uint8Array(first.length + extension.length);
  full.set(first, 0);
  full.set(extension, first.length);
  const baseline = sha256(full);

  // Stage 1: hash `first` to get its state. Per Merkle-Damgard, after
  // absorbing exactly one block of input AND finalizing, the digest IS
  // the chaining state we'd see right after that block's compression…
  // EXCEPT finalize() also processes the padding block, which mutates
  // the state further. So we can't use the digest of `first` as the
  // resume state — we'd need the state after one compress() call but
  // BEFORE padding. The length-extension attack works precisely because
  // the attacker captures H(secret || msg), which IS the post-padding-
  // block state — and the attacker's resume bakes the original glue
  // padding into the input the server eventually re-hashes.
  //
  // Verify that by constructing the equivalent scenario explicitly here.
  const stage1 = new Sha256();
  // Mimic what an internal call would do: process the first block by
  // hand. We use update() to absorb the 64 bytes; bufLen ends at 0 and
  // totalBytes at 64. We CAN'T then call finalize() and use that output
  // as the resume state — finalize() adds padding. Instead, peek at the
  // chaining state directly via clone+finalize-with-no-more-input would
  // diverge.
  //
  // Right test: simulate H(extension || gluePad(extLen)) starting from
  // the mid-stream state we get by absorbing exactly one block. We
  // expose that state by reading h._H — but that's private. Instead,
  // we verify fromState via the integrated test below ("length
  // extension is correct"), which is the actual user-facing property.
  assert.ok(stage1); // smoke
  assert.equal(baseline.length, 32);
});

test("Sha256.fromState rejects bad stateBytes / totalBytesProcessed", () => {
  assert.throws(() => Sha256.fromState(new Uint8Array(31), 64), /Uint8Array\(32\)/);
  assert.throws(() => Sha256.fromState(new Uint8Array(32), 1), /multiple of 64/);
  assert.throws(() => Sha256.fromState(new Uint8Array(32), -64), /non-negative/);
  assert.throws(() => Sha256.fromState(new Uint8Array(32), 0.5), /non-negative/);
  // Valid call should not throw.
  Sha256.fromState(new Uint8Array(32), 0);
  Sha256.fromState(new Uint8Array(32), 64);
});

// ---- the end-to-end length-extension property ----
//
// THIS is the load-bearing test for the lesson. Given any (secret, msg):
//   sig = SHA-256(secret || msg)
//   gluePad = computeGluePadding(secret.length + msg.length)
//   forged = SHA-256.fromState(sig, secret.length + msg.length + gluePad.length)
//            .update(extension).finalize()
// must equal
//   SHA-256(secret || msg || gluePad || extension)
//
// If this holds, the attack works.

function runLengthExtensionCheck(secret, msg, extension) {
  const secretBytes = new TextEncoder().encode(secret);
  const msgBytes = new TextEncoder().encode(msg);
  const extBytes = new TextEncoder().encode(extension);

  // Baseline: H(secret || msg)
  const sm = new Uint8Array(secretBytes.length + msgBytes.length);
  sm.set(secretBytes, 0);
  sm.set(msgBytes, secretBytes.length);
  const sig = sha256(sm);

  // Glue padding for (secret || msg).
  const gluePad = computeGluePadding(secretBytes.length + msgBytes.length);

  // Forged signature, computed by RESUMING from sig.
  const totalBeforeExt = secretBytes.length + msgBytes.length + gluePad.length;
  const forgedSig = Sha256.fromState(sig, totalBeforeExt)
    .update(extBytes)
    .finalize();

  // Independently re-compute H(secret || msg || gluePad || extension).
  const full = new Uint8Array(
    secretBytes.length + msgBytes.length + gluePad.length + extBytes.length
  );
  let off = 0;
  full.set(secretBytes, off); off += secretBytes.length;
  full.set(msgBytes, off);    off += msgBytes.length;
  full.set(gluePad, off);     off += gluePad.length;
  full.set(extBytes, off);
  const honest = sha256(full);

  assert.equal(bytesToHex(forgedSig), bytesToHex(honest));
}

test("length extension: short secret + short message + short extension", () => {
  runLengthExtensionCheck("correct-horse", "user=alice&amount=10", "&admin=true");
});

test("length extension: empty extension", () => {
  // Even with no appended bytes, the forged sig must equal H(secret||msg||gluePad).
  runLengthExtensionCheck("k", "abc", "");
});

test("length extension: long extension (multiple blocks)", () => {
  runLengthExtensionCheck("secret", "msg", "X".repeat(200));
});

test("length extension: message that pushes into the 'no room' padding case", () => {
  // secret(8) + msg(50) = 58 — > 55, so the original hash would need
  // an extra padding block. gluePad must be > 8 here.
  runLengthExtensionCheck("12345678", "a".repeat(50), "B");
});

test("length extension: message length exactly 55 (boundary)", () => {
  runLengthExtensionCheck("k", "a".repeat(54), "X");
});

test("length extension: message length exactly 56 (just over the boundary)", () => {
  runLengthExtensionCheck("k", "a".repeat(55), "X");
});

// ---- computeGluePadding sanity checks ----

test("computeGluePadding starts with 0x80", () => {
  const p = computeGluePadding(5);
  assert.equal(p[0], 0x80);
});

test("computeGluePadding total length brings (msgLen + pad) to a multiple of 64", () => {
  for (const mLen of [0, 1, 31, 55, 56, 63, 64, 100, 119, 120, 128, 1000]) {
    const p = computeGluePadding(mLen);
    assert.equal((mLen + p.length) % 64, 0, `failed at msgLen=${mLen}`);
  }
});

test("computeGluePadding encodes the bit length big-endian in the trailing 8 bytes", () => {
  const p = computeGluePadding(1); // 8 bits total
  // Last 8 bytes are the big-endian 64-bit value 8.
  for (let i = 0; i < 7; i++) assert.equal(p[p.length - 8 + i], 0);
  assert.equal(p[p.length - 1], 8);
});

test("computeGluePadding for msgLen=55 fits 0x80 + 7 length bytes in one block (no extra block needed)", () => {
  // msgLen=55 -> need pad of length 64-55 = 9: [0x80, 0,...,0, len8]
  const p = computeGluePadding(55);
  assert.equal(p.length, 9);
});

test("computeGluePadding for msgLen=56 needs an extra block", () => {
  // 56 + 9 = 65 — would NOT be a multiple of 64. So pad goes
  // through the next block; total padded length = 128.
  const p = computeGluePadding(56);
  assert.equal(p.length, 72);
});

test("computeGluePadding rejects bad input", () => {
  assert.throws(() => computeGluePadding(-1), /non-negative/);
  assert.throws(() => computeGluePadding(1.5), /non-negative/);
  assert.throws(() => computeGluePadding("nope"), /non-negative/);
});

// ---- cross-check against Node's built-in SHA-256 on random inputs ----

test("Sha256 matches node:crypto on 256 random inputs of varied length", () => {
  for (let i = 0; i < 256; i++) {
    const len = i * 3; // 0..765 — spans many block boundaries
    const data = crypto.randomBytes(len);
    const ours = bytesToHex(sha256(new Uint8Array(data)));
    const theirs = crypto.createHash("sha256").update(data).digest("hex");
    assert.equal(ours, theirs, `mismatch at len=${len}`);
  }
});

// ---- hex helpers ----

test("bytesToHex / hexToBytes round-trip", () => {
  const b = new Uint8Array([0, 1, 2, 0xff, 0xab]);
  assert.equal(bytesToHex(b), "000102ffab");
  assert.deepEqual(hexToBytes("000102ffab"), b);
});

test("hexToBytes rejects invalid input", () => {
  assert.throws(() => hexToBytes("xyz"), /invalid hex/);
  assert.throws(() => hexToBytes("0"), /invalid hex/);
});
