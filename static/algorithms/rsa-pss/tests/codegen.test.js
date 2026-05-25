import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

test("full_script imports rsa + padding from cryptography.hazmat", () => {
  const out = c.full_script({});
  assert.match(out, /from cryptography\.hazmat\.primitives\.asymmetric import rsa, padding/);
});

test("full_script imports hashes + serialization", () => {
  const out = c.full_script({});
  assert.match(out, /from cryptography\.hazmat\.primitives import hashes, serialization/);
});

test("full_script imports InvalidSignature for the tampered-verify branch", () => {
  const out = c.full_script({});
  assert.match(out, /from cryptography\.exceptions import InvalidSignature/);
});

test("full_script generates a 2048-bit keypair with e=65537", () => {
  const out = c.full_script({});
  assert.match(out, /rsa\.generate_private_key\(public_exponent=65537, key_size=2048\)/);
  assert.match(out, /private_key\.public_key\(\)/);
});

test("full_script exports the public key as SPKI DER hex", () => {
  const out = c.full_script({});
  assert.match(out, /SubjectPublicKeyInfo/);
  assert.match(out, /public_bytes\.hex\(\)/);
});

test("full_script signs with PSS padding + MGF1 + SHA-256 + salt_length=32", () => {
  const out = c.full_script({});
  assert.match(out, /padding\.PSS\(/);
  assert.match(out, /padding\.MGF1\(hashes\.SHA256\(\)\)/);
  assert.match(out, /salt_length=32/);
  assert.match(out, /private_key\.sign\(message, pss_padding, hashes\.SHA256\(\)\)/);
});

test("full_script verifies the fresh signature with the same padding", () => {
  const out = c.full_script({});
  assert.match(out, /public_key\.verify\(signature, message, pss_padding, hashes\.SHA256\(\)\)/);
});

test("full_script signs the SAME message twice and asserts the signatures differ (probabilistic)", () => {
  const out = c.full_script({});
  // Both signing lines present
  assert.match(out, /signature = private_key\.sign\(message, pss_padding, hashes\.SHA256\(\)\)/);
  assert.match(out, /signature2 = private_key\.sign\(message, pss_padding, hashes\.SHA256\(\)\)/);
  // Inequality assertion proving the probabilistic property
  assert.match(out, /assert signature != signature2/);
});

test("full_script verifies BOTH signatures (proves both are individually valid)", () => {
  const out = c.full_script({});
  assert.match(out, /public_key\.verify\(signature, message, pss_padding/);
  assert.match(out, /public_key\.verify\(signature2, message, pss_padding/);
});

test("full_script demonstrates tampered verify with an InvalidSignature catch", () => {
  const out = c.full_script({});
  assert.match(out, /tampered/);
  assert.match(out, /except InvalidSignature/);
});

test("full_script uses state.rsapss_message when provided", () => {
  const out = c.full_script({ rsapss_message: "my custom payload" });
  assert.match(out, /"my custom payload"/);
});

test("full_script falls back to a default message when state is empty", () => {
  const out = c.full_script({});
  assert.match(out, /"sign me"/);
});

test("full_script tolerates a missing/undefined state object", () => {
  const out = c.full_script();
  assert.match(out, /rsa\.generate_private_key/);
  assert.match(out, /"sign me"/);
});

test("intro returns empty string", () => {
  assert.equal(c.intro({}), "");
});

test("textbook_rsa_sign_recap returns empty string", () => {
  assert.equal(c.textbook_rsa_sign_recap({}), "");
});

test("pss_construction returns empty string", () => {
  assert.equal(c.pss_construction({}), "");
});

test("verify_mechanics returns empty string", () => {
  assert.equal(c.verify_mechanics({}), "");
});

test("sign_and_verify returns empty string", () => {
  assert.equal(c.sign_and_verify({}), "");
});

test("vs_ed25519_and_deployment returns empty string", () => {
  assert.equal(c.vs_ed25519_and_deployment({}), "");
});

test("done returns empty string", () => {
  assert.equal(c.done({}), "");
});
