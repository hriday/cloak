import { test } from "node:test";
import assert from "node:assert/strict";
import { quarterRound, chachaBlock, chacha20Encrypt } from "../chacha20.js";

// Helpers — these only show up in tests, kept local.
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

// RFC 8439 §2.1.1 — single quarter-round test vector.
test("quarterRound matches RFC 8439 §2.1.1 vector", () => {
  // The RFC presents the vector with a, b, c, d as standalone words; we
  // borrow 4 cells of a 16-word state to drive quarterRound() directly.
  const state = new Uint32Array(16);
  state[0] = 0x11111111;
  state[1] = 0x01020304;
  state[2] = 0x9b8d6f43;
  state[3] = 0x01234567;
  quarterRound(state, 0, 1, 2, 3);
  assert.equal(state[0] >>> 0, 0xea2a92f4);
  assert.equal(state[1] >>> 0, 0xcb1cf8ce);
  assert.equal(state[2] >>> 0, 0x4581472e);
  assert.equal(state[3] >>> 0, 0x5881c4bb);
});

// RFC 8439 §2.3.2 — single ChaCha20 block test vector.
test("chachaBlock matches RFC 8439 §2.3.2 vector", () => {
  const key = hexToBytes(
    "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:" +
    "10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f"
  );
  const nonce = hexToBytes("00:00:00:09:00:00:00:4a:00:00:00:00");
  const counter = 1;
  const block = chachaBlock(key, counter, nonce);
  // Expected serialized keystream from RFC 8439 §2.3.2.
  const expected =
    "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e" +
    "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e";
  assert.equal(bytesToHex(block), expected);
});

// RFC 8439 §2.4.2 — ChaCha20 encryption end-to-end ("Ladies and Gentlemen…").
test("chacha20Encrypt matches RFC 8439 §2.4.2 vector", () => {
  const key = hexToBytes(
    "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:" +
    "10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f"
  );
  const nonce = hexToBytes("00:00:00:00:00:00:00:4a:00:00:00:00");
  const plaintext = new TextEncoder().encode(
    "Ladies and Gentlemen of the class of '99: If I could offer you " +
    "only one tip for the future, sunscreen would be it."
  );
  const ct = chacha20Encrypt(key, nonce, plaintext, 1);
  const expected =
    "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b" +
    "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8" +
    "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736" +
    "5af90bbf74a35be6b40b8eedf2785e42874d";
  assert.equal(bytesToHex(ct), expected);
});

test("chacha20Encrypt round-trips (XOR is involutive)", () => {
  const key = new Uint8Array(32).fill(0x42);
  const nonce = new Uint8Array(12).fill(0x07);
  const pt = new TextEncoder().encode("the quick brown fox jumps over the lazy dog");
  const ct = chacha20Encrypt(key, nonce, pt);
  const back = chacha20Encrypt(key, nonce, ct);
  assert.equal(new TextDecoder().decode(back), "the quick brown fox jumps over the lazy dog");
});

test("chacha20Encrypt handles empty input", () => {
  const key = new Uint8Array(32);
  const nonce = new Uint8Array(12);
  assert.equal(chacha20Encrypt(key, nonce, new Uint8Array(0)).length, 0);
});

test("chacha20Encrypt handles partial-block input (<64 bytes)", () => {
  const key = new Uint8Array(32);
  const nonce = new Uint8Array(12);
  const pt = new Uint8Array(7).fill(0xAA);
  const ct = chacha20Encrypt(key, nonce, pt);
  assert.equal(ct.length, 7);
  // XOR back
  const back = chacha20Encrypt(key, nonce, ct);
  assert.deepEqual(Array.from(back), Array.from(pt));
});
