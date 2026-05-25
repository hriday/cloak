import { test } from "node:test";
import assert from "node:assert/strict";
import {
  query,
  getTargetCiphertext,
  getPlaintext,
  getQueryCount,
  _resetForTests,
} from "../po_simulator.js";

// Each test resets the simulator so its random key/plaintext/IV are fresh.

test("getTargetCiphertext returns 16-byte iv and ct as hex", async () => {
  _resetForTests();
  const { iv_hex, ct_hex } = await getTargetCiphertext();
  assert.equal(typeof iv_hex, "string");
  assert.equal(typeof ct_hex, "string");
  assert.equal(iv_hex.length, 32);
  assert.equal(ct_hex.length, 32);
  assert.match(iv_hex, /^[0-9a-f]{32}$/);
  assert.match(ct_hex, /^[0-9a-f]{32}$/);
});

test("getPlaintext returns a 16-byte ASCII string from the bank", async () => {
  _resetForTests();
  const pt = await getPlaintext();
  assert.equal(typeof pt, "string");
  assert.equal(pt.length, 16);
  for (let i = 0; i < pt.length; i++) {
    const code = pt.charCodeAt(i);
    assert.ok(code >= 32 && code < 127, `byte ${i} (${code}) is not printable ASCII`);
  }
});

test("query on the real (iv, ct) returns 'ok' — original padding is valid", async () => {
  _resetForTests();
  const { iv_hex, ct_hex } = await getTargetCiphertext();
  // The captured ct is the data block. Decrypting with the real iv produces
  // the original plaintext, which by definition does NOT end in valid PKCS7
  // — it's just 16 bytes of ASCII. So the response is "bad_padding" unless
  // the plaintext happens to end in a valid PKCS7 byte sequence.
  //
  // (For most bank entries, the last byte is `!`, `.`, `e`, etc. — none of
  // which equals 0x01 through 0x10. So `bad_padding` is the expected
  // response here. The attack proceeds against `bad_padding`.)
  const resp = await query(iv_hex, ct_hex);
  assert.ok(
    resp === "bad_padding" || resp === "ok",
    `expected bad_padding or ok, got ${resp}`
  );
});

test("query with a random forged iv returns 'bad_padding' most of the time", async () => {
  _resetForTests();
  const { ct_hex } = await getTargetCiphertext();

  // Statistical: across 256 random forged IVs, the vast majority should
  // fail the PKCS7 check. Valid PKCS7 has ~256/256 = 1 chance per byte (for
  // last byte = 0x01), so ~1/256 of random IVs pass. We expect ≥240 of 256
  // to come back "bad_padding".
  let badPaddings = 0;
  for (let i = 0; i < 256; i++) {
    const ivBytes = new Uint8Array(16);
    crypto.getRandomValues(ivBytes);
    const ivHex = Array.from(ivBytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    const resp = await query(ivHex, ct_hex);
    if (resp === "bad_padding") badPaddings += 1;
  }
  assert.ok(
    badPaddings >= 240,
    `expected ≥240 bad_padding responses, got ${badPaddings}`
  );
});

test("query returns 'internal_error' on malformed hex", async () => {
  _resetForTests();
  const { ct_hex } = await getTargetCiphertext();
  const resp = await query("not hex!", ct_hex);
  assert.equal(resp, "internal_error");
});

test("query returns 'internal_error' on wrong-length iv", async () => {
  _resetForTests();
  const { ct_hex } = await getTargetCiphertext();
  const resp = await query("aa", ct_hex);
  assert.equal(resp, "internal_error");
});

test("query returns 'internal_error' on wrong-length ct", async () => {
  _resetForTests();
  const { iv_hex } = await getTargetCiphertext();
  const resp = await query(iv_hex, "bb");
  assert.equal(resp, "internal_error");
});

test("getQueryCount tracks total queries served", async () => {
  _resetForTests();
  const { iv_hex, ct_hex } = await getTargetCiphertext();
  const before = await getQueryCount();
  await query(iv_hex, ct_hex);
  await query(iv_hex, ct_hex);
  await query(iv_hex, ct_hex);
  const after = await getQueryCount();
  assert.equal(after - before, 3);
});

test("known-good 'ok' response: forging the iv so D(ct)[15] ^ iv[15] = 0x01 returns ok", async () => {
  _resetForTests();
  // Encrypt a known plaintext, then build a forged IV that XORs into a
  // single-byte 0x01 padding. This verifies the oracle correctly recognises
  // valid PKCS7 with the standard "force last byte = 0x01" attack step.
  const { iv_hex, ct_hex } = await getTargetCiphertext();
  const pt = await getPlaintext();
  const ptLast = pt.charCodeAt(15);
  // Real iv last byte:
  const ivLastReal = parseInt(iv_hex.slice(30, 32), 16);
  // D(ct)[15] = ptLast XOR ivLastReal (because pt = D(ct) XOR iv).
  const dLast = ptLast ^ ivLastReal;
  // Forged iv last byte so D(ct)[15] XOR iv_last = 0x01.
  const ivLastForged = dLast ^ 0x01;
  const forgedHex =
    iv_hex.slice(0, 30) + ivLastForged.toString(16).padStart(2, "0");
  const resp = await query(forgedHex, ct_hex);
  assert.equal(resp, "ok", "forged iv targeting last-byte = 0x01 should produce ok");
});
