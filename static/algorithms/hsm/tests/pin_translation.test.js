import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildPinBlock,
  ensureZoneKeys,
  terminalEncrypt,
  translate,
  issuerVerify,
  keyFingerprints,
} from "../pin_translation.js";

test("buildPinBlock: 1234 / 4111111111111111 → known ISO 9564 Format 0 bytes", () => {
  // PIN field:  04 12 34 FF FF FF FF FF
  // PAN field:  00 00 11 11 11 11 11 11  (PAN minus check digit, rightmost 12)
  // XOR:        04 12 25 EE EE EE EE EE
  const out = buildPinBlock("1234", "4111111111111111");
  assert.ok(out instanceof Uint8Array, "returns Uint8Array");
  assert.equal(out.length, 8, "PIN block is exactly 8 bytes (ISO 9564 Format 0)");
  assert.deepEqual(
    Array.from(out),
    [0x04, 0x12, 0x25, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE],
  );
});

test("buildPinBlock: 6-digit PIN works", () => {
  // PIN field:  06 12 34 56 FF FF FF FF
  // PAN no-check: 555500000000444 → rightmost 12 = 500000000444
  // PAN field:  00 00 50 00 00 00 04 44
  // XOR:        06 12 64 56 FF FF FB BB
  const out = buildPinBlock("123456", "5555000000004444");
  assert.equal(out.length, 8);
  assert.deepEqual(
    Array.from(out),
    [0x06, 0x12, 0x64, 0x56, 0xFF, 0xFF, 0xFB, 0xBB],
  );
});

test("buildPinBlock rejects 2-digit PIN", () => {
  assert.throws(() => buildPinBlock("12", "4111111111111111"), /pin must be 4-12/);
});

test("buildPinBlock rejects PAN shorter than 13 digits", () => {
  assert.throws(() => buildPinBlock("1234", "12"), /pan must be at least 13/);
});

test("buildPinBlock rejects non-digit PIN", () => {
  assert.throws(() => buildPinBlock("12ab", "4111111111111111"), /pin must be/);
});

test("buildPinBlock rejects non-digit PAN", () => {
  assert.throws(() => buildPinBlock("1234", "4111-1111-1111-1111"), /pan must be/);
});

test("ensureZoneKeys is idempotent — same fingerprints across calls", async () => {
  const k1 = await ensureZoneKeys();
  const f1 = await keyFingerprints();
  const k2 = await ensureZoneKeys();
  const f2 = await keyFingerprints();
  assert.equal(k1, k2, "same object reference");
  assert.deepEqual(f1, f2, "same fingerprints");
});

test("keyFingerprints: 3 unique 8-char hex strings", async () => {
  const f = await keyFingerprints();
  for (const name of ["tpk", "zpk1", "zpk2"]) {
    assert.equal(typeof f[name], "string", `${name} is string`);
    assert.equal(f[name].length, 8, `${name} is 8 chars`);
    assert.match(f[name], /^[0-9a-f]{8}$/, `${name} is hex`);
  }
  assert.notEqual(f.tpk, f.zpk1);
  assert.notEqual(f.tpk, f.zpk2);
  assert.notEqual(f.zpk1, f.zpk2);
});

test("terminalEncrypt: 8-byte PIN block → 32 hex chars (16-byte CBC+PKCS7 ciphertext)", async () => {
  const pb = buildPinBlock("1234", "4111111111111111");
  const ct = await terminalEncrypt(pb);
  assert.equal(typeof ct, "string");
  assert.equal(ct.length, 32, "AES-CBC + PKCS7 on 8 bytes → 16-byte ciphertext → 32 hex");
  assert.match(ct, /^[0-9a-f]{32}$/);
});

test("terminalEncrypt rejects wrong-length input", async () => {
  await assert.rejects(() => terminalEncrypt(new Uint8Array(7)), /length 8/);
  await assert.rejects(() => terminalEncrypt(new Uint8Array(16)), /length 8/);
  await assert.rejects(() => terminalEncrypt("not bytes"), /Uint8Array/);
});

test("full zone-translation roundtrip: tpk → zpk1 → zpk2, issuer verifies", async () => {
  const pin = "1234";
  const pan = "4111111111111111";
  const pb = buildPinBlock(pin, pan);

  const ct_tpk = await terminalEncrypt(pb);
  const ct_zpk1 = await translate(ct_tpk, "tpk", "zpk1");
  const ct_zpk2 = await translate(ct_zpk1, "zpk1", "zpk2");

  // All three ciphertexts differ — the whole point of zone translation.
  assert.notEqual(ct_tpk, ct_zpk1);
  assert.notEqual(ct_zpk1, ct_zpk2);
  assert.notEqual(ct_tpk, ct_zpk2);

  const ok = await issuerVerify(ct_zpk2, pin, pan);
  assert.equal(ok, true, "issuer recovers the correct PIN");
});

test("issuerVerify returns false on wrong expected PIN", async () => {
  const pan = "4111111111111111";
  const pb = buildPinBlock("1234", pan);
  const ct_tpk = await terminalEncrypt(pb);
  const ct_zpk1 = await translate(ct_tpk, "tpk", "zpk1");
  const ct_zpk2 = await translate(ct_zpk1, "zpk1", "zpk2");

  const ok = await issuerVerify(ct_zpk2, "9999", pan);
  assert.equal(ok, false);
});

test("issuerVerify returns false when ciphertext is tampered", async () => {
  const pin = "1234";
  const pan = "4111111111111111";
  const pb = buildPinBlock(pin, pan);
  const ct_tpk = await terminalEncrypt(pb);
  const ct_zpk1 = await translate(ct_tpk, "tpk", "zpk1");
  const ct_zpk2 = await translate(ct_zpk1, "zpk1", "zpk2");

  // Flip one hex character.
  const flipped = (ct_zpk2[0] === "a" ? "b" : "a") + ct_zpk2.slice(1);
  assert.notEqual(flipped, ct_zpk2);

  const ok = await issuerVerify(flipped, pin, pan);
  assert.equal(ok, false, "tampered ciphertext must not verify");
});

test("translate rejects unknown key names", async () => {
  const pb = buildPinBlock("1234", "4111111111111111");
  const ct = await terminalEncrypt(pb);
  await assert.rejects(() => translate(ct, "bogus", "zpk1"), /unknown fromKeyName/);
  await assert.rejects(() => translate(ct, "tpk", "bogus"), /unknown toKeyName/);
});

test("6-digit PIN survives full roundtrip", async () => {
  const pin = "987654";
  const pan = "5555000000004444";
  const pb = buildPinBlock(pin, pan);
  const ct = await translate(
    await translate(await terminalEncrypt(pb), "tpk", "zpk1"),
    "zpk1",
    "zpk2",
  );
  assert.equal(await issuerVerify(ct, pin, pan), true);
  assert.equal(await issuerVerify(ct, "987653", pan), false);
});
