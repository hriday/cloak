import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

// ---- quarter_round_line ----

test("quarter_round_line accepts the canonical hex answer", () => {
  const r = v.quarter_round_line("0x12131415", {});
  assert.equal(r.ok, true);
  assert.equal(r.value.chap_qr_input, 0x11111111);
  assert.equal(r.value.chap_qr_output, 0x12131415);
});

test("quarter_round_line accepts decimal equivalent", () => {
  // 0x12131415 = 303240213
  const r = v.quarter_round_line(String(0x12131415), {});
  assert.equal(r.ok, true);
  assert.equal(r.value.chap_qr_output, 0x12131415);
});

test("quarter_round_line accepts bare hex with a letter", () => {
  // 0x12131415 has no a-f digits — use a wrong-but-letter value to
  // exercise the bare-hex parsing branch.
  const r = v.quarter_round_line("abcd1234", {});
  assert.equal(r.ok, false);
  // It parsed (didn't say "Enter a 32-bit value"), it's just wrong.
  assert.match(r.hint, /Compute|wrap/);
});

test("quarter_round_line accepts 0X uppercase prefix", () => {
  const r = v.quarter_round_line("0X12131415", {});
  assert.equal(r.ok, true);
});

test("quarter_round_line rejects garbage", () => {
  const r = v.quarter_round_line("hello", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /hex|decimal/);
});

test("quarter_round_line rejects empty", () => {
  const r = v.quarter_round_line("", {});
  assert.equal(r.ok, false);
});

test("quarter_round_line rejects wrong value with helpful hint", () => {
  const r = v.quarter_round_line("0x00000000", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /0x12131415/);
});

// ---- encrypt_aead ----

test("encrypt_aead happy path runs full encrypt + tamper", async () => {
  const r = await v.encrypt_aead({ message: "hello", aad: "v1" }, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.chap_message, "hello");
  assert.equal(r.value.chap_aad, "v1");
  // In Node ≥19 crypto.getRandomValues exists, so we should see hex.
  if (r.value.chap_key_hex) {
    assert.equal(r.value.chap_key_hex.length, 64);   // 32 bytes
    assert.equal(r.value.chap_nonce_hex.length, 24); // 12 bytes
    assert.equal(r.value.chap_tag_hex.length, 32);   // 16 bytes
    assert.equal(r.value.chap_decrypted, "hello");
    assert.equal(r.value.chap_tamper_failed, true);
  }
});

test("encrypt_aead happy path without aad", async () => {
  const r = await v.encrypt_aead({ message: "hi" }, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.chap_message, "hi");
  assert.equal(r.value.chap_aad, "");
});

test("encrypt_aead rejects empty message", async () => {
  const r = await v.encrypt_aead({ message: "" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /at least one/);
});

test("encrypt_aead rejects >500 char message", async () => {
  const r = await v.encrypt_aead({ message: "a".repeat(501) }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /500/);
});

test("encrypt_aead rejects non-ASCII message", async () => {
  const r = await v.encrypt_aead({ message: "hi 🦊" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /ASCII/);
});

test("encrypt_aead rejects >200 char aad", async () => {
  const r = await v.encrypt_aead({ message: "ok", aad: "a".repeat(201) }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /200/);
});

test("encrypt_aead rejects non-ASCII aad", async () => {
  const r = await v.encrypt_aead({ message: "ok", aad: "v1 🦊" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /printable ASCII/);
});

test("encrypt_aead round-trip: decrypted matches input", async () => {
  const r = await v.encrypt_aead({ message: "attack at dawn", aad: "header-v1" }, {});
  assert.equal(r.ok, true);
  if (r.value.chap_decrypted) {
    assert.equal(r.value.chap_decrypted, "attack at dawn");
  }
});

// ---- info / walkthroughs ----

test("info always ok", () => {
  assert.deepEqual(v.info("anything", {}), { ok: true, value: {} });
});

test("walkthroughs has quarter_round_line", () => {
  assert.equal(typeof v.walkthroughs.quarter_round_line, "function");
});

test("walkthroughs.quarter_round_line has 3 rungs and reveals 0x12131415", () => {
  const rungs = v.walkthroughs.quarter_round_line({});
  assert.equal(rungs.length, 3);
  rungs.forEach((r) => assert.equal(typeof r, "string"));
  assert.match(rungs[2], /0x12131415/);
});
