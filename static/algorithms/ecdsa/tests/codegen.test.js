import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

test("full_script imports ec from cryptography.hazmat.primitives.asymmetric", () => {
  const out = c.full_script({});
  assert.match(out, /from cryptography\.hazmat\.primitives\.asymmetric import ec/);
});

test("full_script imports hashes and serialization", () => {
  const out = c.full_script({});
  assert.match(out, /from cryptography\.hazmat\.primitives import hashes, serialization/);
});

test("full_script imports InvalidSignature for the tampered-verify branch", () => {
  const out = c.full_script({});
  assert.match(out, /from cryptography\.exceptions import InvalidSignature/);
});

test("full_script generates a P-256 (SECP256R1) keypair", () => {
  const out = c.full_script({});
  assert.match(out, /ec\.generate_private_key\(ec\.SECP256R1\(\)\)/);
  assert.match(out, /private_key\.public_key\(\)/);
});

test("full_script signs the message with ECDSA(SHA-256)", () => {
  const out = c.full_script({});
  assert.match(out, /private_key\.sign\(message,\s*ec\.ECDSA\(hashes\.SHA256\(\)\)\)/);
});

test("full_script verifies the fresh signature", () => {
  const out = c.full_script({});
  assert.match(
    out,
    /public_key\.verify\(signature,\s*message,\s*ec\.ECDSA\(hashes\.SHA256\(\)\)\)/,
  );
});

test("full_script demonstrates tampered verify with an InvalidSignature catch", () => {
  const out = c.full_script({});
  assert.match(out, /tampered/);
  assert.match(out, /except InvalidSignature/);
});

test("full_script prints the public key as hex (compressed SEC1)", () => {
  const out = c.full_script({});
  assert.match(out, /public_bytes\.hex\(\)/);
  assert.match(out, /CompressedPoint|X962/);
});

test("full_script mentions RFC 6979 deterministic-k as the structural defense", () => {
  const out = c.full_script({});
  assert.match(out, /RFC 6979/);
  assert.match(out, /deterministic/i);
});

test("full_script uses state.ecdsa_message when provided", () => {
  const out = c.full_script({ ecdsa_message: "my custom payload" });
  assert.match(out, /"my custom payload"/);
});

test("full_script falls back to a default message when state is empty", () => {
  const out = c.full_script({});
  assert.match(out, /"ship it"/);
});

test("full_script tolerates a missing/undefined state object", () => {
  const out = c.full_script();
  assert.match(out, /ec\.SECP256R1/);
  assert.match(out, /"ship it"/);
});

test("info returns empty string", () => {
  assert.equal(c.info({}), "");
});

test("recover_k returns empty string", () => {
  assert.equal(c.recover_k({}), "");
});
