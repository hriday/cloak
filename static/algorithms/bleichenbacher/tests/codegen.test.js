import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

test("full_script begins with a 'for learning only' warning", () => {
  const out = c.full_script({});
  assert.match(out, /FOR LEARNING ONLY/i);
});

test("full_script defines the vulnerable decrypt_pkcs1v15 oracle", () => {
  const out = c.full_script({});
  assert.match(out, /def decrypt_pkcs1v15\(c: int\) -> str:/);
  assert.match(out, /"conforming"/);
  assert.match(out, /"bad"/);
});

test("full_script defines the bleichenbacher function (the attack)", () => {
  const out = c.full_script({});
  assert.match(out, /def bleichenbacher\(c: int\) -> int:/);
});

test("full_script implements all four steps of the algorithm", () => {
  const out = c.full_script({});
  assert.match(out, /Step 1:.*blinding/i);
  assert.match(out, /Step 2/);
  assert.match(out, /Step 2\.a/);
  assert.match(out, /Step 2\.b/);
  assert.match(out, /Step 2\.c/);
  assert.match(out, /Step 3/);
  assert.match(out, /Step 4/);
});

test("full_script defines mod_inv and uses pow(..., D, N) for decryption", () => {
  const out = c.full_script({});
  assert.match(out, /def mod_inv\(/);
  assert.match(out, /pow\(c, D, N\)/);
});

test("full_script implements PKCS#1 v1.5 strip routine", () => {
  const out = c.full_script({});
  assert.match(out, /def _strip_pkcs1v15\(/);
  assert.match(out, /not PKCS#1 v1\.5/);
});

test("full_script inlines bleich_n from state", () => {
  const nStr = "9876543210123456789";
  const out = c.full_script({ bleich_n: nStr });
  assert.ok(out.includes(nStr), "n value should appear in script");
  assert.match(out, /N = /);
});

test("full_script inlines bleich_target_ct from state", () => {
  const ct = "1234567890";
  const out = c.full_script({ bleich_target_ct: ct });
  assert.ok(out.includes(ct), "target ct should appear in script");
  assert.match(out, /TARGET_CT = /);
});

test("full_script includes provenance comment when bleich_recovered_plaintext is in state", () => {
  const out = c.full_script({ bleich_recovered_plaintext: "hi!!" });
  assert.match(out, /Page recovered/);
  assert.match(out, /hi!!/);
});

test("full_script includes total queries when bleich_total_queries is in state", () => {
  const out = c.full_script({ bleich_total_queries: 9999 });
  assert.match(out, /9999/);
  assert.match(out, /oracle queries/);
});

test("full_script includes modulus bits annotation", () => {
  const out = c.full_script({ bleich_modulus_bits: 60 });
  assert.match(out, /~60 bits/);
});

test("full_script falls back to defaults when state is empty", () => {
  const out = c.full_script({});
  // The default n value should appear.
  assert.match(out, /N = 1152921512714829637/);
});

test("full_script tolerates undefined state", () => {
  const out = c.full_script();
  assert.match(out, /def bleichenbacher\(/);
});

test("full_script does not call out to external libs (pure stdlib)", () => {
  const out = c.full_script({});
  // Should not import cryptography or any third-party libs.
  assert.doesNotMatch(out, /import cryptography/);
  assert.doesNotMatch(out, /from Crypto/);
});

test("full_script uses E = 17 (matches simulator)", () => {
  const out = c.full_script({});
  assert.match(out, /E = 17/);
});

test("full_script uses K = 8 (matches simulator)", () => {
  const out = c.full_script({});
  assert.match(out, /K = 8/);
});

test("intro returns empty string", () => {
  assert.equal(c.intro({}), "");
});
test("pkcs1_v1_5_padding returns empty string", () => {
  assert.equal(c.pkcs1_v1_5_padding({}), "");
});
test("the_oracle returns empty string", () => {
  assert.equal(c.the_oracle({}), "");
});
test("the_search returns empty string", () => {
  assert.equal(c.the_search({}), "");
});
test("run_the_attack returns empty string", () => {
  assert.equal(c.run_the_attack({}), "");
});
test("defenses returns empty string", () => {
  assert.equal(c.defenses({}), "");
});
test("done returns empty string", () => {
  assert.equal(c.done({}), "");
});
