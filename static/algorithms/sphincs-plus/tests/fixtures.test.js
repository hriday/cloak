// Structural sanity over the JSON fixture so missing-step / wrong-pk /
// mismatched-lesson / dropped-slug / intro-template-bloat breakage is
// caught at JS-test time before Django ever sees the file.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

const FIXTURE_PATH = join(
  __dirname, "..", "..", "..", "..", "algorithms", "sphincs-plus", "fixtures.json"
);
const data = JSON.parse(readFileSync(FIXTURE_PATH, "utf8"));

const algorithms = data.filter((r) => r.model === "core.algorithm");
const lessons    = data.filter((r) => r.model === "core.lesson");
const steps      = data.filter((r) => r.model === "core.step");

test("fixture contains exactly 1 algorithm, 1 lesson, 8 steps", () => {
  assert.equal(algorithms.length, 1);
  assert.equal(lessons.length, 1);
  assert.equal(steps.length, 8);
});

test("algorithm has pk 26, slug sphincs-plus, family pq", () => {
  const a = algorithms[0];
  assert.equal(a.pk, 26);
  assert.equal(a.fields.slug, "sphincs-plus");
  assert.equal(a.fields.family, "pq");
  assert.equal(a.fields.name, "SPHINCS+ (SLH-DSA)");
  assert.equal(a.fields.status, "live");
  assert.equal(a.fields.order, 26);
});

test("algorithm intro_template is ≤ 200 chars", () => {
  const intro = algorithms[0].fields.intro_template;
  assert.ok(
    intro.length <= 200,
    "intro_template is " + intro.length + " chars (cap 200): " + JSON.stringify(intro)
  );
});

test("lesson has pk 26, slug hash-based-signatures, points at algorithm 26", () => {
  const l = lessons[0];
  assert.equal(l.pk, 26);
  assert.equal(l.fields.slug, "hash-based-signatures");
  assert.equal(l.fields.algorithm, 26);
  assert.equal(l.fields.title, "SPHINCS+: signatures from only a hash");
  assert.equal(l.fields.order, 1);
});

test("step pks are 261 through 268 in order", () => {
  const pks = steps.map((s) => s.pk);
  assert.deepEqual(pks, [261, 262, 263, 264, 265, 266, 267, 268]);
});

test("step slugs match the spec exactly, in spec order", () => {
  const slugs = steps.map((s) => s.fields.slug);
  assert.deepEqual(slugs, [
    "intro",
    "lamport-otp",
    "wots-improvement",
    "merkle-trees",
    "hypertree-construction",
    "sign-and-verify",
    "real-sphincs-and-tradeoffs",
    "done",
  ]);
});

test("step orders are 1..8 in fixture order", () => {
  const orders = steps.map((s) => s.fields.order);
  assert.deepEqual(orders, [1, 2, 3, 4, 5, 6, 7, 8]);
});

test("every step points at lesson 26", () => {
  for (const s of steps) {
    assert.equal(s.fields.lesson, 26);
  }
});

test("step 6 (sign-and-verify) is input-text with validator sphincs_operation", () => {
  const s = steps.find((x) => x.fields.slug === "sign-and-verify");
  assert.equal(s.fields.kind, "input-text");
  assert.equal(s.fields.validator_key, "sphincs_operation");
});

test("all other steps are info kind", () => {
  const others = steps.filter((s) => s.fields.slug !== "sign-and-verify");
  for (const s of others) {
    assert.equal(s.fields.kind, "info", "step " + s.fields.slug + " should be info");
  }
});

test("step 8 (done) carries codegen_key full_script", () => {
  const s = steps.find((x) => x.fields.slug === "done");
  assert.equal(s.fields.codegen_key, "full_script");
});

test("every step has a non-empty prompt_template and help_template (except done)", () => {
  for (const s of steps) {
    assert.equal(typeof s.fields.prompt_template, "string");
    assert.ok(s.fields.prompt_template.length > 0, "prompt empty: " + s.fields.slug);
    assert.equal(typeof s.fields.help_template, "string");
    if (s.fields.slug !== "done") {
      assert.ok(s.fields.help_template.length > 0, "help empty: " + s.fields.slug);
    }
  }
});

test("intro mentions FIPS 205, SLH-DSA, August 2024", () => {
  const s = steps.find((x) => x.fields.slug === "intro");
  assert.match(s.fields.prompt_template, /FIPS 205/);
  assert.match(s.fields.prompt_template, /SLH-DSA/);
  assert.match(s.fields.prompt_template, /August 2024|Aug 2024/);
});

test("intro mentions the only-hash security argument", () => {
  const s = steps.find((x) => x.fields.slug === "intro");
  // Look for any of the hash-based key phrases.
  assert.match(s.fields.prompt_template, /collision-resistant|hash function/i);
});

test("lamport-otp prompt walks the 2n secrets / one-time-only limitation", () => {
  const s = steps.find((x) => x.fields.slug === "lamport-otp");
  assert.match(s.fields.prompt_template, /Lamport/);
  assert.match(s.fields.prompt_template, /one-time/i);
  // The pre-image / hash duality.
  assert.match(s.fields.prompt_template, /pre-image|preimage/i);
});

test("wots-improvement prompt mentions the Winternitz chain and w=16", () => {
  const s = steps.find((x) => x.fields.slug === "wots-improvement");
  assert.match(s.fields.prompt_template, /Winternitz/);
  assert.match(s.fields.prompt_template, /chain/i);
  assert.match(s.fields.prompt_template, /w = 16|w=16/);
});

test("merkle-trees prompt mentions log N proof size and the root commitment", () => {
  const s = steps.find((x) => x.fields.slug === "merkle-trees");
  assert.match(s.fields.prompt_template, /Merkle/);
  assert.match(s.fields.prompt_template, /root/i);
  assert.match(s.fields.prompt_template, /log/i);
});

test("hypertree-construction prompt mentions the FORS bottom layer and the d layers", () => {
  const s = steps.find((x) => x.fields.slug === "hypertree-construction");
  assert.match(s.fields.prompt_template, /hypertree/i);
  assert.match(s.fields.prompt_template, /FORS/);
});

test("sign-and-verify prompt mentions 8 WOTS+ keys and the height-3 Merkle tree", () => {
  const s = steps.find((x) => x.fields.slug === "sign-and-verify");
  assert.match(s.fields.prompt_template, /8 WOTS\+/);
  assert.match(s.fields.prompt_template, /Merkle/);
  // The signature size constant from the toy.
  assert.match(s.fields.prompt_template, /353/);
});

test("real-sphincs-and-tradeoffs prompt lists the canonical signature sizes", () => {
  const s = steps.find((x) => x.fields.slug === "real-sphincs-and-tradeoffs");
  // From FIPS 205 — these numbers should appear verbatim somewhere.
  assert.match(s.fields.prompt_template, /7856/);
  assert.match(s.fields.prompt_template, /17088/);
});

test("done step mentions the next-related PQ algorithms", () => {
  const s = steps.find((x) => x.fields.slug === "done");
  assert.match(s.fields.prompt_template, /Dilithium|ML-DSA/);
  assert.match(s.fields.prompt_template, /Falcon|FN-DSA/);
});
