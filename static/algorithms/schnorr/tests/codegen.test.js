import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

test("full_script declares the toy group constants p=467, g=4, q=233", () => {
  const out = c.full_script({});
  assert.match(out, /P\s*=\s*467/);
  assert.match(out, /G\s*=\s*4/);
  assert.match(out, /Q\s*=\s*233/);
});

test("full_script imports hashlib and secrets (no third-party deps)", () => {
  const out = c.full_script({});
  assert.match(out, /import hashlib/);
  assert.match(out, /import secrets/);
});

test("full_script defines keygen, sign, verify, hash_challenge", () => {
  const out = c.full_script({});
  assert.match(out, /def keygen\(\)/);
  assert.match(out, /def sign\(/);
  assert.match(out, /def verify\(/);
  assert.match(out, /def hash_challenge\(/);
});

test("full_script sign uses the response equation s = (k + e*x) % Q", () => {
  const out = c.full_script({});
  assert.match(out, /s\s*=\s*\(k\s*\+\s*e\s*\*\s*x\)\s*%\s*Q/);
});

test("full_script verify checks g^s == R · X^e (mod p)", () => {
  const out = c.full_script({});
  assert.match(out, /pow\(G,\s*s,\s*P\)/);
  assert.match(out, /\(R\s*\*\s*pow\(X,\s*e,\s*P\)\)\s*%\s*P/);
});

test("full_script demonstrates a fresh sign + verify round-trip", () => {
  const out = c.full_script({});
  assert.match(out, /verify\(X, message, \(R, s\)\)/);
});

test("full_script demonstrates a tampered signature failing verify", () => {
  const out = c.full_script({});
  assert.match(out, /tampered/i);
});

test("full_script includes the MuSig / linearity demo (the load-bearing pedagogy)", () => {
  const out = c.full_script({});
  assert.match(out, /multi-sig|MuSig|linear/i);
  // Joint key as a product of individual public keys.
  assert.match(out, /X_A\s*\*\s*X_B/);
  // Joint response as a sum of individual responses.
  assert.match(out, /s_A\s*\+\s*s_B/);
});

test("full_script forward-links to BIP-340 / coincurve for production", () => {
  const out = c.full_script({});
  assert.match(out, /BIP-340|coincurve|secp256k1/i);
});

test("full_script uses state.schnorr_message when provided", () => {
  const out = c.full_script({ schnorr_message: "co-sign me" });
  assert.match(out, /"co-sign me"/);
});

test("full_script falls back to default message when state is empty", () => {
  const out = c.full_script({});
  assert.match(out, /"ship it"/);
});

test("full_script tolerates missing state", () => {
  const out = c.full_script();
  assert.match(out, /"ship it"/);
});

test("intro / non-actionable steps return empty string", () => {
  assert.equal(c.intro({}), "");
  assert.equal(c.the_group({}), "");
  assert.equal(c.sign_mechanics({}), "");
  assert.equal(c.verify_mechanics({}), "");
  assert.equal(c.sign_and_verify({}), "");
  assert.equal(c.linearity_and_musig({}), "");
  assert.equal(c.done({}), "");
  assert.equal(c.info({}), "");
});
