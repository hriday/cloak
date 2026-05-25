import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

test("full_script imports ML_DSA_65 from dilithium_py", () => {
  const out = c.full_script({});
  assert.match(out, /from dilithium_py\.ml_dsa import ML_DSA_65/);
});

test("full_script mentions pip install dilithium-py in the header", () => {
  const out = c.full_script({});
  assert.match(out, /pip install dilithium-py/);
});

test("full_script mentions pqcrypto as the alternative", () => {
  const out = c.full_script({});
  assert.match(out, /pqcrypto/i);
});

test("full_script calls keygen, sign, verify", () => {
  const out = c.full_script({});
  assert.match(out, /ML_DSA_65\.keygen\(\)/);
  assert.match(out, /ML_DSA_65\.sign\(/);
  assert.match(out, /ML_DSA_65\.verify\(/);
});

test("full_script demonstrates tampered verify failing", () => {
  const out = c.full_script({});
  assert.match(out, /tampered/i);
  assert.match(out, /assert not ok/);
});

test("full_script demonstrates wrong-message verify failing", () => {
  const out = c.full_script({});
  assert.match(out, /wrong-message|different message/i);
});

test("full_script asserts fresh signature verifies", () => {
  const out = c.full_script({});
  assert.match(out, /assert ok/);
});

test("full_script shows that signing twice produces different bytes", () => {
  const out = c.full_script({});
  assert.match(out, /signing twice|sig2|different bytes/);
});

test("full_script uses state.dilithium_last_input when provided", () => {
  const out = c.full_script({ dilithium_last_input: "my payload" });
  assert.match(out, /"my payload"/);
});

test("full_script falls back to a default message when state is empty", () => {
  const out = c.full_script({});
  assert.match(out, /"hello world"/);
});

test("full_script tolerates a missing/undefined state object", () => {
  const out = c.full_script();
  assert.match(out, /ML_DSA_65/);
});

test("full_script embeds the captured signature hex as a comment when available", () => {
  const out = c.full_script({ dilithium_signature: "abcd".repeat(20) });
  assert.match(out, /# toy signature from the browser/);
});

test("full_script omits the signature comment when state is empty", () => {
  const out = c.full_script({});
  assert.doesNotMatch(out, /# toy signature from the browser/);
});

test("full_script mentions ML-DSA-65 parameters bridging the toy", () => {
  const out = c.full_script({});
  // The lesson's pedagogical point: same shape, much bigger numbers.
  assert.match(out, /q=8380417|q = 8380417/);
  assert.match(out, /n=256|n = 256/);
});

test("full_script mentions hybrid deployment vs Ed25519 size tax", () => {
  const out = c.full_script({});
  assert.match(out, /Ed25519/);
  assert.match(out, /hybrid/i);
});

test("per-step stubs all return empty string", () => {
  for (const slug of [
    "intro",
    "the_problem",
    "keygen",
    "sign_mechanics",
    "verify_mechanics",
    "sign_and_verify",
    "real_dilithium_and_deployment",
    "done",
  ]) {
    assert.equal(typeof c[slug], "function", `${slug} should be exported`);
    assert.equal(c[slug]({}), "", `${slug} should return ""`);
  }
});
