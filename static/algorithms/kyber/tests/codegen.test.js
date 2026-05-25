import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

test("full_script imports ML_KEM_768 from kyber_py", () => {
  const out = c.full_script({});
  assert.match(out, /from kyber_py\.ml_kem import ML_KEM_768/);
});

test("full_script mentions pip install kyber-py in the header comments", () => {
  const out = c.full_script({});
  assert.match(out, /pip install kyber-py/);
});

test("full_script mentions pqcrypto as the alternative", () => {
  const out = c.full_script({});
  assert.match(out, /pqcrypto/i);
});

test("full_script calls keygen, encaps, decaps", () => {
  const out = c.full_script({});
  assert.match(out, /ML_KEM_768\.keygen\(\)/);
  assert.match(out, /ML_KEM_768\.encaps\(ek\)/);
  assert.match(out, /ML_KEM_768\.decaps\(dk, ct\)/);
});

test("full_script asserts K_sender == K_recipient", () => {
  const out = c.full_script({});
  assert.match(out, /assert K_sender == K_recipient/);
});

test("full_script prints the public key length, ciphertext length, shared key", () => {
  const out = c.full_script({});
  assert.match(out, /print\(f"public key:/);
  assert.match(out, /print\(f"ciphertext:/);
  assert.match(out, /print\(f"shared key:/);
});

test("full_script tolerates a missing state object", () => {
  const out = c.full_script();
  assert.match(out, /ML_KEM_768/);
  assert.match(out, /assert K_sender == K_recipient/);
});

test("full_script embeds the captured v[0] as a comment when state has it", () => {
  const out = c.full_script({ kyber_v_coeff: 180 });
  assert.match(out, /# page captured v\[0\]: 180/);
});

test("full_script omits the captured-v0 comment when state is empty", () => {
  const out = c.full_script({});
  assert.doesNotMatch(out, /# page captured v\[0\]/);
});

test("full_script mentions ML-KEM-768 parameters as a bridge from the toy", () => {
  const out = c.full_script({});
  // The lesson's pedagogical point: same shape, bigger numbers.
  assert.match(out, /q=3329|q = 3329/);
  assert.match(out, /n=256|n = 256/);
  assert.match(out, /k=3|k = 3/);
});

test("full_script mentions the Fujisaki-Okamoto transform", () => {
  const out = c.full_script({});
  assert.match(out, /Fujisaki[\s-]?Okamoto/);
});

test("full_script mentions the TLS 1.3 X25519MLKEM768 hybrid", () => {
  const out = c.full_script({});
  assert.match(out, /X25519MLKEM768/);
});

test("per-step stubs all return empty string", () => {
  for (const slug of [
    "intro",
    "lwe_warmup",
    "polynomial_rings",
    "keygen",
    "encapsulation",
    "decapsulation",
    "real_kyber_and_hybrid",
    "done",
  ]) {
    assert.equal(typeof c[slug], "function", `${slug} should be exported`);
    assert.equal(c[slug]({}), "", `${slug} should return ""`);
  }
});
