import { test } from "node:test";
import assert from "node:assert/strict";
import { toyEncrypt, mitmFind } from "../mitm.js";

test("toyEncrypt is 2-round XOR", () => {
  // 0x42 XOR 0x10 = 0x52; 0x52 XOR 0x20 = 0x72
  assert.equal(toyEncrypt(0x42, 0x10, 0x20), 0x72);
});

test("toyEncrypt result is in [0, 255]", () => {
  assert.equal(toyEncrypt(0xFF, 0xFF, 0xFF), 0xFF);
  assert.equal(toyEncrypt(0, 0, 0), 0);
});

test("mitmFind returns the canonical (K1, K2) among the matches", () => {
  const pt = 0x42;
  const ct = toyEncrypt(pt, 0x10, 0x20);  // 0x72
  const matches = mitmFind(pt, ct);
  // Every match should round-trip
  for (const [k1, k2] of matches) {
    assert.equal(toyEncrypt(pt, k1, k2), ct, `(${k1}, ${k2}) should encrypt ${pt} to ${ct}`);
  }
  // The original (0x10, 0x20) must be in the list
  const found = matches.some(([k1, k2]) => k1 === 0x10 && k2 === 0x20);
  assert.equal(found, true);
});

test("mitmFind finds 256 matches for a 2-round XOR (one per K1)", () => {
  const matches = mitmFind(0x42, toyEncrypt(0x42, 0x10, 0x20));
  assert.equal(matches.length, 256);
});
