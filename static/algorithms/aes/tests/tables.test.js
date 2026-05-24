import { test } from "node:test";
import assert from "node:assert/strict";
import { SBOX, SHIFT_OFFSETS, mixColumn } from "../tables.js";

test("SBOX is 256 bytes long", () => {
  assert.equal(SBOX.length, 256);
});

test("SBOX known entries match standard AES table", () => {
  assert.equal(SBOX[0x00], 0x63);  // first byte
  assert.equal(SBOX[0xFF], 0x16);  // last byte
  assert.equal(SBOX[0x53], 0xED);  // canonical lesson example (row 5, col 3)
});

test("SHIFT_OFFSETS is [0, 1, 2, 3]", () => {
  assert.deepEqual(SHIFT_OFFSETS, [0, 1, 2, 3]);
});

test("mixColumn on Wikipedia canonical test vector", () => {
  // [0xDB, 0x13, 0x53, 0x45] → [0x8E, 0x4D, 0xA1, 0xBC]
  assert.deepEqual(mixColumn([0xDB, 0x13, 0x53, 0x45]), [0x8E, 0x4D, 0xA1, 0xBC]);
});

test("mixColumn on zero column returns zero column", () => {
  assert.deepEqual(mixColumn([0, 0, 0, 0]), [0, 0, 0, 0]);
});
