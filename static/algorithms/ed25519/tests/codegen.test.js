import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

test("full_script imports Ed25519PrivateKey from cryptography.hazmat", () => {
  const out = c.full_script({});
  assert.match(out, /from cryptography\.hazmat\.primitives\.asymmetric\.ed25519 import Ed25519PrivateKey/);
});

test("full_script imports serialization (for raw-bytes public key export)", () => {
  const out = c.full_script({});
  assert.match(out, /from cryptography\.hazmat\.primitives import serialization/);
});

test("full_script imports InvalidSignature for the tampered-verify branch", () => {
  const out = c.full_script({});
  assert.match(out, /from cryptography\.exceptions import InvalidSignature/);
});

test("full_script generates a fresh keypair", () => {
  const out = c.full_script({});
  assert.match(out, /Ed25519PrivateKey\.generate\(\)/);
  assert.match(out, /private_key\.public_key\(\)/);
});

test("full_script signs the message", () => {
  const out = c.full_script({});
  assert.match(out, /private_key\.sign\(/);
});

test("full_script verifies the fresh signature", () => {
  const out = c.full_script({});
  assert.match(out, /public_key\.verify\(signature, message\)/);
});

test("full_script demonstrates tampered verify with an InvalidSignature catch", () => {
  const out = c.full_script({});
  assert.match(out, /tampered/);
  assert.match(out, /except InvalidSignature/);
});

test("full_script prints the public key as hex", () => {
  const out = c.full_script({});
  assert.match(out, /public_bytes\.hex\(\)/);
});

test("full_script uses state.ed25_message when provided", () => {
  const out = c.full_script({ ed25_message: "my custom payload" });
  assert.match(out, /"my custom payload"/);
});

test("full_script falls back to a default message when state is empty", () => {
  const out = c.full_script({});
  assert.match(out, /"sign me"/);
});

test("full_script tolerates a missing/undefined state object", () => {
  const out = c.full_script();
  assert.match(out, /Ed25519PrivateKey/);
  assert.match(out, /"sign me"/);
});

test("intro returns empty string", () => {
  assert.equal(c.intro({}), "");
});

test("key_derivation returns empty string", () => {
  assert.equal(c.key_derivation({}), "");
});

test("sign_mechanics returns empty string", () => {
  assert.equal(c.sign_mechanics({}), "");
});

test("verify_mechanics returns empty string", () => {
  assert.equal(c.verify_mechanics({}), "");
});

test("sign_and_verify returns empty string", () => {
  assert.equal(c.sign_and_verify({}), "");
});

test("vs_rsa_comparison returns empty string", () => {
  assert.equal(c.vs_rsa_comparison({}), "");
});

test("done returns empty string", () => {
  assert.equal(c.done({}), "");
});
