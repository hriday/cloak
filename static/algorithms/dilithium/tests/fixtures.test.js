// Sanity tests over the JSON fixture so structural breakage (missing step,
// wrong pk, mismatched lesson key, dropped slug, intro_template bloat) is
// caught at JS-test time before Django ever sees the file.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

const FIXTURE_PATH = join(__dirname, "..", "..", "..", "..", "algorithms", "dilithium", "fixtures.json");
const data = JSON.parse(readFileSync(FIXTURE_PATH, "utf8"));

const algorithms = data.filter((r) => r.model === "core.algorithm");
const lessons    = data.filter((r) => r.model === "core.lesson");
const steps      = data.filter((r) => r.model === "core.step");

test("fixture contains exactly 1 algorithm, 1 lesson, 8 steps", () => {
  assert.equal(algorithms.length, 1);
  assert.equal(lessons.length, 1);
  assert.equal(steps.length, 8);
});

test("algorithm has pk 25, slug dilithium, family pq", () => {
  const a = algorithms[0];
  assert.equal(a.pk, 25);
  assert.equal(a.fields.slug, "dilithium");
  assert.equal(a.fields.family, "pq");
  assert.equal(a.fields.name, "Dilithium (ML-DSA)");
  assert.equal(a.fields.status, "live");
  assert.equal(a.fields.order, 25);
});

test("algorithm intro_template is ≤ 200 chars", () => {
  const intro = algorithms[0].fields.intro_template;
  assert.ok(
    intro.length <= 200,
    "intro_template is " + intro.length + " chars (cap 200): " + JSON.stringify(intro)
  );
});

test("lesson has pk 25, slug lattice-signatures, points at algorithm 25", () => {
  const l = lessons[0];
  assert.equal(l.pk, 25);
  assert.equal(l.fields.slug, "lattice-signatures");
  assert.equal(l.fields.algorithm, 25);
  assert.equal(l.fields.title, "Dilithium: post-quantum signatures");
  assert.equal(l.fields.order, 1);
});

test("step pks are 251 through 258 in order", () => {
  const pks = steps.map((s) => s.pk);
  assert.deepEqual(pks, [251, 252, 253, 254, 255, 256, 257, 258]);
});

test("step slugs match the spec exactly, in spec order", () => {
  const slugs = steps.map((s) => s.fields.slug);
  assert.deepEqual(slugs, [
    "intro",
    "the-problem",
    "keygen",
    "sign-mechanics",
    "verify-mechanics",
    "sign-and-verify",
    "real-dilithium-and-deployment",
    "done",
  ]);
});

test("step orders are 1..8 in fixture order", () => {
  const orders = steps.map((s) => s.fields.order);
  assert.deepEqual(orders, [1, 2, 3, 4, 5, 6, 7, 8]);
});

test("every step points at lesson 25", () => {
  for (const s of steps) {
    assert.equal(s.fields.lesson, 25);
  }
});

test("step 6 (sign-and-verify) is input-text with validator dilithium_operation", () => {
  const s = steps.find((x) => x.fields.slug === "sign-and-verify");
  assert.equal(s.fields.kind, "input-text");
  assert.equal(s.fields.validator_key, "dilithium_operation");
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

test("every step has a non-empty prompt_template and help_template", () => {
  for (const s of steps) {
    assert.equal(typeof s.fields.prompt_template, "string");
    assert.ok(s.fields.prompt_template.length > 0, "prompt empty: " + s.fields.slug);
    assert.equal(typeof s.fields.help_template, "string");
    // help can legitimately be empty on the Done step (matches Kyber/Ed25519 convention).
    if (s.fields.slug !== "done") {
      assert.ok(s.fields.help_template.length > 0, "help empty: " + s.fields.slug);
    }
  }
});

test("keygen prompt shows the frozen t polynomial coefficients", () => {
  const s = steps.find((x) => x.fields.slug === "keygen");
  const prompt = s.fields.prompt_template;
  // From frozen vectors: t[0] = [76, 94, 253, 19]
  assert.match(prompt, /76/);
  assert.match(prompt, /253/);
});

test("keygen prompt shows the frozen A matrix", () => {
  const s = steps.find((x) => x.fields.slug === "keygen");
  const prompt = s.fields.prompt_template;
  // From frozen vectors: A[0][0] = [206, 231, 91, 176]
  assert.match(prompt, /206/);
  assert.match(prompt, /231/);
});

test("sign-mechanics prompt mentions the rejection sampling loop", () => {
  const s = steps.find((x) => x.fields.slug === "sign-mechanics");
  const prompt = s.fields.prompt_template;
  assert.match(prompt, /reject/i);
  assert.match(prompt, /GAMMA1|gamma1/);
  assert.match(prompt, /BETA|beta/);
});

test("verify-mechanics prompt walks the cancellation algebra", () => {
  const s = steps.find((x) => x.fields.slug === "verify-mechanics");
  const prompt = s.fields.prompt_template;
  // The load-bearing equation.
  assert.match(prompt, /A·z|A\*z/);
  assert.match(prompt, /c·t|c\*t/);
  assert.match(prompt, /cancel/i);
  // Noise budget
  assert.match(prompt, /BETA|beta/);
});

test("real-dilithium-and-deployment prompt mentions all three NIST parameter sets", () => {
  const s = steps.find((x) => x.fields.slug === "real-dilithium-and-deployment");
  const prompt = s.fields.prompt_template;
  assert.match(prompt, /ML-DSA-44/);
  assert.match(prompt, /ML-DSA-65/);
  assert.match(prompt, /ML-DSA-87/);
  // Compare-to-Ed25519 table
  assert.match(prompt, /Ed25519/);
  // Hybrid pattern
  assert.match(prompt, /hybrid/i);
});

test("intro prompt forward-links to Kyber (pair)", () => {
  const s = steps.find((x) => x.fields.slug === "intro");
  const prompt = s.fields.prompt_template;
  assert.match(prompt, /Kyber/);
  assert.match(prompt, /FIPS 204/);
});

test("the-problem prompt mentions Module-SIS and Shor", () => {
  const s = steps.find((x) => x.fields.slug === "the-problem");
  const prompt = s.fields.prompt_template;
  assert.match(prompt, /Module-SIS/);
  assert.match(prompt, /Shor/);
  // Forward-link to SPHINCS+
  assert.match(prompt, /SPHINCS\+/);
});

test("done prompt mentions hybrid deployment and forward-links to SPHINCS+", () => {
  const s = steps.find((x) => x.fields.slug === "done");
  const prompt = s.fields.prompt_template;
  assert.match(prompt, /SPHINCS\+/);
  assert.match(prompt, /dilithium-py/);
});
