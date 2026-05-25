import { test } from "node:test";
import assert from "node:assert/strict";
import * as cc from "../cc_demo.js";

// ---- Caesar --------------------------------------------------------------

test("caesarEncrypt: HELLO with k=3 → KHOOR", () => {
  assert.equal(cc.caesarEncrypt("HELLO", 3), "KHOOR");
});

test("caesarEncrypt: preserves case", () => {
  assert.equal(cc.caesarEncrypt("Hello", 3), "Khoor");
});

test("caesarEncrypt: leaves spaces and punctuation alone", () => {
  assert.equal(cc.caesarEncrypt("HI, BOB!", 1), "IJ, CPC!");
});

test("caesarEncrypt: wraps around z → a", () => {
  assert.equal(cc.caesarEncrypt("xyz", 3), "abc");
});

test("caesarEncrypt: k=0 is identity", () => {
  assert.equal(cc.caesarEncrypt("anything", 0), "anything");
});

test("caesarEncrypt: handles negative shifts and shifts >= 26", () => {
  assert.equal(cc.caesarEncrypt("abc", -1), cc.caesarEncrypt("abc", 25));
  assert.equal(cc.caesarEncrypt("abc", 29), cc.caesarEncrypt("abc", 3));
});

test("caesar roundtrip: encrypt then decrypt yields plaintext", () => {
  const pt = "The quick brown fox jumps over the lazy dog.";
  assert.equal(cc.caesarDecrypt(cc.caesarEncrypt(pt, 7), 7), pt);
});

// ---- Vigenère ------------------------------------------------------------

test("vigenereEncrypt: ATTACKATDAWN + LEMON = LXFOPVEFRNHR (RFC vector)", () => {
  assert.equal(cc.vigenereEncrypt("ATTACKATDAWN", "LEMON"), "LXFOPVEFRNHR");
});

test("vigenereEncrypt: key advances only on letters, not on spaces", () => {
  // 'AT TACK' with key LEMON: A→L, T→X, space stays, T→F, A→O, C→P, K→V → LX TFOPV
  assert.equal(cc.vigenereEncrypt("AT TACK", "LEMON"), "LX FOPV");
});

test("vigenere roundtrip on longer text", () => {
  const pt = "Now is the time for all good people to come to the aid of their country.";
  const ct = cc.vigenereEncrypt(pt, "lemon");
  assert.equal(cc.vigenereDecrypt(ct, "lemon"), pt);
});

test("vigenereEncrypt rejects all-non-letter keys", () => {
  assert.throws(() => cc.vigenereEncrypt("abc", "!!!"));
});

// ---- Frequency analysis --------------------------------------------------

test("frequencyDist of empty string is all zeros and sums to 0", () => {
  const d = cc.frequencyDist("");
  let sum = 0;
  for (const k of Object.keys(d)) sum += d[k];
  assert.equal(sum, 0);
});

test("frequencyDist sums to ~1 for non-empty input", () => {
  const d = cc.frequencyDist("the quick brown fox");
  let sum = 0;
  for (const k of Object.keys(d)) sum += d[k];
  assert.ok(Math.abs(sum - 1) < 1e-9, `sum should be 1, got ${sum}`);
});

test("frequencyDist ignores non-letters and is case-insensitive", () => {
  const d1 = cc.frequencyDist("AaBb!! ");
  // 2 a's, 2 b's, 4 total → 0.5 each
  assert.ok(Math.abs(d1.a - 0.5) < 1e-9);
  assert.ok(Math.abs(d1.b - 0.5) < 1e-9);
  assert.equal(d1.c, 0);
});

test("breakCaesarByFrequency recovers k=3 on an English plaintext", () => {
  const pt = "It is a truth universally acknowledged that a single man in possession of a good fortune must be in want of a wife. However little known the feelings or views of such a man may be on his first entering a neighborhood this truth is so well fixed in the minds of the surrounding families.";
  const ct = cc.caesarEncrypt(pt, 3);
  const { shift, plaintext } = cc.breakCaesarByFrequency(ct);
  assert.equal(shift, 3);
  assert.equal(plaintext, pt);
});

test("breakCaesarByFrequency recovers a variety of shifts", () => {
  const pt = "The quick brown fox jumps over the lazy dog and then runs back home.";
  for (const k of [1, 5, 7, 13, 19, 25]) {
    const { shift } = cc.breakCaesarByFrequency(cc.caesarEncrypt(pt, k));
    assert.equal(shift, k, `expected to recover shift=${k}, got ${shift}`);
  }
});

// THE LOAD-BEARING TEST: frequency analysis must recover the Vigenère key.
test("breakVigenereByFrequency recovers LEMON on the Lincoln excerpt", () => {
  const pt =
    "Four score and seven years ago our fathers brought forth on this " +
    "continent a new nation conceived in liberty and dedicated to the " +
    "proposition that all men are created equal. Now we are engaged in " +
    "a great civil war testing whether that nation or any nation so " +
    "conceived and so dedicated can long endure.";
  const ct = cc.vigenereEncrypt(pt, "LEMON");
  const { key, plaintext } = cc.breakVigenereByFrequency(ct, 5);
  assert.equal(key.toLowerCase(), "lemon", `expected key 'lemon', got '${key}'`);
  assert.equal(plaintext, pt);
});

test("breakVigenereByFrequency rejects non-positive keyLen", () => {
  assert.throws(() => cc.breakVigenereByFrequency("xxxx", 0));
  assert.throws(() => cc.breakVigenereByFrequency("xxxx", -1));
});

// ---- OTP -----------------------------------------------------------------

test("otpEncrypt: XOR of message with key", () => {
  const m = new Uint8Array([0x00, 0xff, 0xaa]);
  const k = new Uint8Array([0x55, 0x55, 0x55]);
  const c = cc.otpEncrypt(m, k);
  assert.deepEqual(Array.from(c), [0x55, 0xaa, 0xff]);
});

test("otp roundtrip", () => {
  const m = new TextEncoder().encode("meet at dawn");
  const k = new Uint8Array(m.length);
  for (let i = 0; i < k.length; i++) k[i] = (i * 7 + 13) & 0xff;
  const c = cc.otpEncrypt(m, k);
  const back = cc.otpDecrypt(c, k);
  assert.deepEqual(Array.from(back), Array.from(m));
  assert.equal(new TextDecoder().decode(back), "meet at dawn");
});

test("otpEncrypt rejects mismatched key length", () => {
  assert.throws(() => cc.otpEncrypt(new Uint8Array(5), new Uint8Array(4)));
});

test("otpEncrypt accepts string + array forms", () => {
  const c = cc.otpEncrypt("AB", [0x01, 0x02]);
  // 'A'=0x41 ^ 0x01 = 0x40, 'B'=0x42 ^ 0x02 = 0x40
  assert.deepEqual(Array.from(c), [0x40, 0x40]);
});
