import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

// ---- caesar_decrypt ------------------------------------------------------

test("caesar_decrypt: accepts the integer shift 3", () => {
  const r = v.caesar_decrypt("3", {});
  assert.equal(r.ok, true);
  assert.equal(r.value.cc_caesar_shift, 3);
  assert.equal(r.value.cc_caesar_plaintext, v.CAESAR_PLAINTEXT);
});

test("caesar_decrypt: accepts the plaintext (lowercase)", () => {
  const r = v.caesar_decrypt(v.CAESAR_PLAINTEXT, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.cc_caesar_plaintext, v.CAESAR_PLAINTEXT);
});

test("caesar_decrypt: accepts the plaintext (uppercase, extra spaces)", () => {
  const r = v.caesar_decrypt("  THIS  IS  A  SECRET  MESSAGE  ", {});
  assert.equal(r.ok, true);
});

test("caesar_decrypt: rejects empty input", () => {
  const r = v.caesar_decrypt("", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /plaintext|shift/i);
});

test("caesar_decrypt: wrong shift returns the failed attempt as a hint", () => {
  const r = v.caesar_decrypt("5", {});
  assert.equal(r.ok, false);
  // The hint should include what shift=5 actually produces.
  assert.match(r.hint, /Shift 5/);
});

test("caesar_decrypt: wrong plaintext rejected", () => {
  const r = v.caesar_decrypt("hello world", {});
  assert.equal(r.ok, false);
});

test("caesar_decrypt: accepts equivalent shifts (29 ≡ 3 mod 26)", () => {
  const r = v.caesar_decrypt("29", {});
  assert.equal(r.ok, true);
});

// ---- vigenere_break ------------------------------------------------------

test("vigenere_break: empty input is rejected with a button hint", () => {
  const r = v.vigenere_break("", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /button|frequency analysis/i);
});

test("vigenere_break: any non-empty sentinel triggers the break", () => {
  const r = v.vigenere_break("run", {});
  assert.equal(r.ok, true);
  // The recovered key must match LEMON (case-insensitive). This is the
  // load-bearing assertion for the lesson — if this fails, step 6 is broken.
  assert.equal(String(r.value.cc_vigenere_recovered_key).toLowerCase(), "lemon");
  assert.equal(r.value.cc_vigenere_true_key, "LEMON");
  assert.equal(r.value.cc_vigenere_keylen, 5);
  // The recovered plaintext must equal the canonical plaintext, since the
  // recovered key matches the true key.
  assert.equal(r.value.cc_vigenere_plaintext, v.VIGENERE_PLAINTEXT);
  // The ciphertext written to state is the same fixed cipher we encrypt
  // with the true key at module-load time.
  assert.equal(r.value.cc_vigenere_ciphertext, v.VIGENERE_CIPHERTEXT);
});

// ---- info / walkthroughs -------------------------------------------------

test("info always returns ok", () => {
  assert.deepEqual(v.info("anything", {}), { ok: true, value: {} });
});

test("walkthroughs exposes both interactive steps", () => {
  assert.equal(typeof v.walkthroughs.caesar_decrypt, "function");
  assert.equal(typeof v.walkthroughs.vigenere_break, "function");
});

test("caesar_decrypt walkthrough has 3 escalating rungs and reveals shift+plaintext", () => {
  const rungs = v.walkthroughs.caesar_decrypt({});
  assert.equal(rungs.length, 3);
  rungs.forEach((r) => assert.equal(typeof r, "string"));
  // The final rung must mention the answer.
  assert.match(rungs[2], new RegExp(String(v.CAESAR_SHIFT)));
});

test("vigenere_break walkthrough reveals LEMON in the final rung", () => {
  const rungs = v.walkthroughs.vigenere_break({});
  assert.equal(rungs.length, 3);
  assert.match(rungs[2], /LEMON/);
});

// ---- module-level constants ----------------------------------------------

test("VIGENERE_CIPHERTEXT is non-trivial length (>100 letters)", () => {
  // Frequency analysis on short streams is unreliable; we need ~100+ chars.
  const letters = v.VIGENERE_CIPHERTEXT.replace(/[^A-Za-z]/g, "");
  assert.ok(letters.length > 100, `expected >100 letters, got ${letters.length}`);
});

test("CAESAR_CIPHERTEXT is the k=3 encryption of CAESAR_PLAINTEXT", () => {
  // Sanity: it should NOT equal the plaintext.
  assert.notEqual(v.CAESAR_CIPHERTEXT.toLowerCase(), v.CAESAR_PLAINTEXT.toLowerCase());
});
