import { test } from "node:test";
import assert from "node:assert/strict";
import * as m from "../math.js";

test("xorBytes encrypts a string with a key", () => {
  // "hi" with key 42: 'h'=104 XOR 42 = 66; 'i'=105 XOR 42 = 67
  assert.deepEqual(m.xorBytes("hi", 42), [66, 67]);
});

test("xorBytes is self-inverse — applying twice returns original codes", () => {
  const original = "hello";
  const encryptedBytes = m.xorBytes(original, 42);
  // Reassemble bytes into a string, then xor again with same key
  const encStr = encryptedBytes.map((c) => String.fromCharCode(c)).join("");
  const decBytes = m.xorBytes(encStr, 42);
  const recovered = decBytes.map((c) => String.fromCharCode(c)).join("");
  assert.equal(recovered, original);
});

test("xorBytes handles key=0 as identity", () => {
  assert.deepEqual(m.xorBytes("Hi", 0), [72, 105]);
});

test("modPow is re-exported from rsa/math.js", () => {
  // Sanity: re-export works and produces the same value as a direct rsa import
  assert.equal(m.modPow(42n, 7n, 143n), 81n);
});
