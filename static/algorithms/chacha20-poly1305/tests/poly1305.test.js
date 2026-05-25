import { test } from "node:test";
import assert from "node:assert/strict";
import { poly1305Mac } from "../poly1305.js";

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

// RFC 8439 §2.5.2 — the canonical Poly1305 test vector.
test("poly1305Mac matches RFC 8439 §2.5.2 vector", () => {
  const otk = hexToBytes(
    "85d6be7857556d337f4452fe42d506a8" +
    "0103808afb0db2fd4abff6af4149f51b"
  );
  const message = new TextEncoder().encode("Cryptographic Forum Research Group");
  const tag = poly1305Mac(otk, message);
  assert.equal(bytesToHex(tag), "a8061dc1305136c6c22b8baf0c0127a9");
});

test("poly1305Mac returns 16 bytes for empty message", () => {
  const otk = new Uint8Array(32);
  const tag = poly1305Mac(otk, new Uint8Array(0));
  assert.equal(tag.length, 16);
  // With all-zero key, all-zero message → tag = 0.
  assert.equal(bytesToHex(tag), "00000000000000000000000000000000");
});

test("poly1305Mac handles non-aligned (1, 15, 17) message lengths", () => {
  const otk = new Uint8Array(32).fill(0x42);
  for (const len of [1, 15, 16, 17, 31, 32, 33]) {
    const msg = new Uint8Array(len).fill(0xAA);
    const tag = poly1305Mac(otk, msg);
    assert.equal(tag.length, 16, `length ${len} should produce 16-byte tag`);
  }
});

test("poly1305Mac is deterministic for fixed key + message", () => {
  const otk = hexToBytes("85d6be7857556d337f4452fe42d506a8" + "0103808afb0db2fd4abff6af4149f51b");
  const msg = new TextEncoder().encode("hello");
  const t1 = poly1305Mac(otk, msg);
  const t2 = poly1305Mac(otk, msg);
  assert.deepEqual(Array.from(t1), Array.from(t2));
});
