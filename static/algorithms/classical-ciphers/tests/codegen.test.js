import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

test("info inline snippet is empty", () => {
  assert.equal(c.info({}), "");
});

test("caesar inline snippet shows HELLO → KHOOR", () => {
  const out = c.caesar({});
  assert.match(out, /HELLO/);
  assert.match(out, /KHOOR/);
});

test("vigenere inline snippet shows ATTACKATDAWN + LEMON → LXFOPVEFRNHR", () => {
  const out = c.vigenere({});
  assert.match(out, /ATTACKATDAWN/);
  assert.match(out, /LEMON/);
  assert.match(out, /LXFOPVEFRNHR/);
});

test("one_time_pad inline snippet uses os.urandom and matches key length", () => {
  const out = c.one_time_pad({});
  assert.match(out, /os\.urandom/);
  assert.match(out, /len\(message\)/);
});

test("caesar_decrypt_step shows the recovered shift when state has it", () => {
  const out = c.caesar_decrypt_step({
    cc_caesar_shift: 3,
    cc_caesar_ciphertext: "WKLV LV D VHFUHW PHVVDJH",
    cc_caesar_plaintext: "this is a secret message",
  });
  assert.match(out, /shift|Shift/i);
  assert.match(out, /3/);
  assert.match(out, /this is a secret message/);
});

test("vigenere_break_step shows the recovered key when state has it", () => {
  const out = c.vigenere_break_step({
    cc_vigenere_recovered_key: "lemon",
    cc_vigenere_true_key: "LEMON",
    cc_vigenere_keylen: 5,
  });
  assert.match(out, /lemon/);
  assert.match(out, /LEMON/);
  assert.match(out, /5/);
});

test("full_script header warns it's educational only", () => {
  const out = c.full_script({});
  assert.match(out, /EDUCATIONAL ONLY/);
});

test("full_script defines all three cipher families", () => {
  const out = c.full_script({});
  assert.match(out, /def caesar_encrypt/);
  assert.match(out, /def vigenere_encrypt/);
  assert.match(out, /def otp_encrypt/);
});

test("full_script includes break_vigenere", () => {
  const out = c.full_script({});
  assert.match(out, /def break_vigenere/);
});

test("full_script with cc_vigenere state shows the recovered key in a comment", () => {
  const out = c.full_script({
    cc_vigenere_ciphertext: "LXFOPVEFRNHR",
    cc_vigenere_recovered_key: "lemon",
    cc_vigenere_keylen: 5,
  });
  assert.match(out, /lemon/);
  assert.match(out, /break_vigenere/);
});

test("full_script with caesar state asserts the decryption matches", () => {
  const out = c.full_script({
    cc_caesar_ciphertext: "WKLV LV D VHFUHW PHVVDJH",
    cc_caesar_plaintext: "this is a secret message",
  });
  assert.match(out, /this is a secret message/);
  assert.match(out, /assert/);
});

test("full_script always has an OTP demo block at the end", () => {
  const out = c.full_script({});
  assert.match(out, /otp_encrypt\(message, key\)/);
  assert.match(out, /assert otp_decrypt\(ct, key\) == message/);
});
