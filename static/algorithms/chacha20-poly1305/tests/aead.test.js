import { test } from "node:test";
import assert from "node:assert/strict";
import { aeadEncrypt, aeadDecrypt, InvalidTag } from "../aead.js";

function hexToBytes(hex) {
  const clean = hex.replace(/[^0-9a-fA-F]/g, "");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return out;
}
function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// RFC 8439 §2.8.2 — the full AEAD test vector.
test("aeadEncrypt matches RFC 8439 §2.8.2 vector", () => {
  const plaintext = new TextEncoder().encode(
    "Ladies and Gentlemen of the class of '99: If I could offer you " +
    "only one tip for the future, sunscreen would be it."
  );
  const aad = hexToBytes("50515253c0c1c2c3c4c5c6c7");
  const key = hexToBytes(
    "808182838485868788898a8b8c8d8e8f" +
    "909192939495969798999a9b9c9d9e9f"
  );
  // RFC 8439 §2.8.2 uses a constant prefix of 7 zero bytes followed by
  // the IV "40 41 42 43 44 45 46 47" — total 12 bytes for the nonce.
  const nonce = hexToBytes("070000004041424344454647");

  const { ciphertext, tag } = aeadEncrypt(key, nonce, plaintext, aad);

  const expectedCt =
    "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6" +
    "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" +
    "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" +
    "3ff4def08e4b7a9de576d26586cec64b6116";
  const expectedTag = "1ae10b594f09e26a7e902ecbd0600691";

  assert.equal(bytesToHex(ciphertext), expectedCt);
  assert.equal(bytesToHex(tag), expectedTag);
});

test("aeadDecrypt round-trips RFC 8439 §2.8.2 vector", () => {
  const plaintext = new TextEncoder().encode(
    "Ladies and Gentlemen of the class of '99: If I could offer you " +
    "only one tip for the future, sunscreen would be it."
  );
  const aad = hexToBytes("50515253c0c1c2c3c4c5c6c7");
  const key = hexToBytes(
    "808182838485868788898a8b8c8d8e8f" +
    "909192939495969798999a9b9c9d9e9f"
  );
  const nonce = hexToBytes("070000004041424344454647");

  const { ciphertext, tag } = aeadEncrypt(key, nonce, plaintext, aad);
  const back = aeadDecrypt(key, nonce, ciphertext, tag, aad);
  assert.equal(new TextDecoder().decode(back), new TextDecoder().decode(plaintext));
});

test("aeadDecrypt rejects tampered ciphertext", () => {
  const key = new Uint8Array(32).fill(0x01);
  const nonce = new Uint8Array(12).fill(0x02);
  const aad = new TextEncoder().encode("v1");
  const pt = new TextEncoder().encode("attack at dawn");

  const { ciphertext, tag } = aeadEncrypt(key, nonce, pt, aad);
  const tampered = new Uint8Array(ciphertext);
  tampered[0] ^= 0x01;
  assert.throws(() => aeadDecrypt(key, nonce, tampered, tag, aad), InvalidTag);
});

test("aeadDecrypt rejects tampered tag", () => {
  const key = new Uint8Array(32).fill(0x01);
  const nonce = new Uint8Array(12).fill(0x02);
  const pt = new TextEncoder().encode("attack at dawn");
  const { ciphertext, tag } = aeadEncrypt(key, nonce, pt, new Uint8Array(0));
  const tampered = new Uint8Array(tag);
  tampered[0] ^= 0x01;
  assert.throws(() => aeadDecrypt(key, nonce, ciphertext, tampered, new Uint8Array(0)), InvalidTag);
});

test("aeadDecrypt rejects tampered AAD", () => {
  const key = new Uint8Array(32).fill(0x01);
  const nonce = new Uint8Array(12).fill(0x02);
  const aad = new TextEncoder().encode("v1");
  const pt = new TextEncoder().encode("attack at dawn");
  const { ciphertext, tag } = aeadEncrypt(key, nonce, pt, aad);
  const tamperedAad = new TextEncoder().encode("v2");
  assert.throws(() => aeadDecrypt(key, nonce, ciphertext, tag, tamperedAad), InvalidTag);
});

test("aeadEncrypt handles empty plaintext", () => {
  const key = new Uint8Array(32);
  const nonce = new Uint8Array(12);
  const { ciphertext, tag } = aeadEncrypt(key, nonce, new Uint8Array(0), new Uint8Array(0));
  assert.equal(ciphertext.length, 0);
  assert.equal(tag.length, 16);
  // Decrypt yields empty plaintext.
  const back = aeadDecrypt(key, nonce, ciphertext, tag, new Uint8Array(0));
  assert.equal(back.length, 0);
});

test("aeadEncrypt handles empty AAD by defaulting it", () => {
  const key = new Uint8Array(32).fill(0x42);
  const nonce = new Uint8Array(12).fill(0x07);
  const pt = new TextEncoder().encode("hello");
  // Pass undefined AAD — internally defaults to empty.
  const { ciphertext, tag } = aeadEncrypt(key, nonce, pt);
  const back = aeadDecrypt(key, nonce, ciphertext, tag);
  assert.equal(new TextDecoder().decode(back), "hello");
});
