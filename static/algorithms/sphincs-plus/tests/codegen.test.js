import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

test("full_script imports SPHINCS+ from pqcrypto", () => {
  const out = c.full_script({});
  assert.match(out, /from pqcrypto\.sign\.sphincs_sha2_128f_simple import/);
});

test("full_script mentions pip install pqcrypto", () => {
  const out = c.full_script({});
  assert.match(out, /pip install pqcrypto/);
});

test("full_script calls generate_keypair, sign, verify", () => {
  const out = c.full_script({});
  assert.match(out, /generate_keypair\(\)/);
  assert.match(out, /sign\(secret_key, message\)/);
  assert.match(out, /verify\(public_key, message, signature\)/);
});

test("full_script demonstrates tampered signature rejection", () => {
  const out = c.full_script({});
  assert.match(out, /tampered/);
  assert.match(out, /\^= 0x01/);
});

test("full_script lists the alternate parameter sets", () => {
  const out = c.full_script({});
  // 128s, 192f, 256f all mentioned as swap-in options.
  assert.match(out, /128s_simple/);
  assert.match(out, /192f_simple/);
  assert.match(out, /256f_simple/);
});

test("full_script mentions the FIPS 205 / SLH-DSA name", () => {
  const out = c.full_script({});
  assert.match(out, /FIPS 205|SLH-DSA/);
});

test("full_script mentions WOTS+ and Merkle (the toy → real bridge)", () => {
  const out = c.full_script({});
  assert.match(out, /WOTS\+/);
  assert.match(out, /Merkle/);
});

test("full_script tolerates a missing state object", () => {
  const out = c.full_script();
  assert.match(out, /sphincs_sha2_128f_simple/);
  assert.match(out, /generate_keypair/);
});

test("full_script tolerates an empty state object", () => {
  const out = c.full_script({});
  assert.match(out, /sphincs_sha2_128f_simple/);
});

test("full_script embeds the captured root as a comment when present", () => {
  const out = c.full_script({ sphincs_root: "deadbeefcafebabe1234567890abcdef" });
  assert.match(out, /# page captured root: deadbeefcafebabe1234567890abcdef/);
});

test("full_script embeds the captured leaf index as a comment when present", () => {
  const out = c.full_script({ sphincs_leaf_index: 5 });
  assert.match(out, /# page captured leaf index: 5/);
});

test("full_script omits captured-state comments when state is empty", () => {
  const out = c.full_script({});
  assert.doesNotMatch(out, /# page captured root/);
  assert.doesNotMatch(out, /# page captured leaf index/);
  assert.doesNotMatch(out, /page captured sig preview/);
});

test("full_script uses the page's captured message when present", () => {
  const out = c.full_script({ sphincs_last_input: "the brown fox" });
  assert.match(out, /"the brown fox"/);
});

test("full_script falls back to a default message when state has none", () => {
  const out = c.full_script({});
  assert.match(out, /"hello SPHINCS\+"/);
});

test("full_script renders a sig preview when state has a captured signature", () => {
  const longSig = "a".repeat(353);
  const out = c.full_script({ sphincs_signature: longSig });
  assert.match(out, /# page captured sig preview:/);
});

test("full_script mentions the hash-only security argument", () => {
  const out = c.full_script({});
  assert.match(out, /SHA-256|hash/i);
});

test("full_script mentions the signature size (~17 KB)", () => {
  const out = c.full_script({});
  // We don't pin the exact wording — just that 17088 bytes appears.
  assert.match(out, /17088/);
});

test("per-step stubs all return empty string", () => {
  for (const slug of [
    "intro",
    "lamport_otp",
    "wots_improvement",
    "merkle_trees",
    "hypertree_construction",
    "sign_and_verify",
    "real_sphincs_and_tradeoffs",
    "done",
  ]) {
    assert.equal(typeof c[slug], "function", `${slug} should be exported`);
    assert.equal(c[slug]({}), "", `${slug} should return ""`);
  }
});
