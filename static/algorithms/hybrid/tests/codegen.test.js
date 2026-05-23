import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

const FULL_STATE = {
  h_sym_key: 42,
  h_wrapped_key: 81,
  h_message: "hi",
  h_ciphertext: [66, 67],
  h_recovered_key: 42,
  h_recovered_message: "hi",
};

test("full_script includes canonical RSA keys", () => {
  const out = c.full_script(FULL_STATE);
  assert.match(out, /p, q = 11, 13/);
  assert.match(out, /e = 7/);
});

test("full_script includes the sym key value and the wrap call", () => {
  const out = c.full_script(FULL_STATE);
  assert.match(out, /sym_key = 42/);
  assert.match(out, /wrapped_key = pow\(sym_key, e, n\)/);
});

test("full_script includes the message and the XOR list comprehension", () => {
  const out = c.full_script(FULL_STATE);
  assert.match(out, /message = "hi"/);
  assert.match(out, /ord\(ch\) \^ sym_key for ch in message/);
});

test("full_script includes the assert that closes the roundtrip", () => {
  const out = c.full_script(FULL_STATE);
  assert.match(out, /assert recovered == message/);
});

test("info and other per-step codegen functions return empty string", () => {
  assert.equal(c.info({}), "");
});
