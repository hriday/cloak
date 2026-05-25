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

const FIXTURE_PATH = join(__dirname, "..", "..", "..", "..", "algorithms", "kyber", "fixtures.json");
const data = JSON.parse(readFileSync(FIXTURE_PATH, "utf8"));

const algorithms = data.filter((r) => r.model === "core.algorithm");
const lessons    = data.filter((r) => r.model === "core.lesson");
const steps      = data.filter((r) => r.model === "core.step");

test("fixture contains exactly 1 algorithm, 1 lesson, 8 steps", () => {
  assert.equal(algorithms.length, 1);
  assert.equal(lessons.length, 1);
  assert.equal(steps.length, 8);
});

test("algorithm has pk 18, slug kyber, family pq", () => {
  const a = algorithms[0];
  assert.equal(a.pk, 18);
  assert.equal(a.fields.slug, "kyber");
  assert.equal(a.fields.family, "pq");
  assert.equal(a.fields.name, "Kyber (ML-KEM)");
  assert.equal(a.fields.status, "live");
});

test("algorithm intro_template is ≤ 200 chars", () => {
  const intro = algorithms[0].fields.intro_template;
  assert.ok(
    intro.length <= 200,
    "intro_template is " + intro.length + " chars (cap 200): " + JSON.stringify(intro)
  );
});

test("lesson has pk 18, slug lattice-kem, points at algorithm 18", () => {
  const l = lessons[0];
  assert.equal(l.pk, 18);
  assert.equal(l.fields.slug, "lattice-kem");
  assert.equal(l.fields.algorithm, 18);
  assert.equal(l.fields.title, "Kyber: post-quantum key encapsulation");
  assert.equal(l.fields.order, 1);
});

test("step pks are 181 through 188 in order", () => {
  const pks = steps.map((s) => s.pk);
  assert.deepEqual(pks, [181, 182, 183, 184, 185, 186, 187, 188]);
});

test("step slugs match the spec exactly, in spec order", () => {
  const slugs = steps.map((s) => s.fields.slug);
  assert.deepEqual(slugs, [
    "intro",
    "lwe-warmup",
    "polynomial-rings",
    "keygen",
    "encapsulation",
    "decapsulation",
    "real-kyber-and-hybrid",
    "done",
  ]);
});

test("step orders are 1..8 in fixture order", () => {
  const orders = steps.map((s) => s.fields.order);
  assert.deepEqual(orders, [1, 2, 3, 4, 5, 6, 7, 8]);
});

test("every step points at lesson 18", () => {
  for (const s of steps) {
    assert.equal(s.fields.lesson, 18);
  }
});

test("step 5 (encapsulation) is input-numeric with validator encap_coefficient", () => {
  const s = steps.find((x) => x.fields.slug === "encapsulation");
  assert.equal(s.fields.kind, "input-numeric");
  assert.equal(s.fields.validator_key, "encap_coefficient");
});

test("all other steps are info kind", () => {
  const others = steps.filter((s) => s.fields.slug !== "encapsulation");
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
    // help can legitimately be empty on the Done step (matches x25519 convention).
    if (s.fields.slug !== "done") {
      assert.ok(s.fields.help_template.length > 0, "help empty: " + s.fields.slug);
    }
  }
});

test("frozen v[0] = 180 appears in the encapsulation prompt's hidden answer (via tests, not user-visible)", () => {
  // The fixture should NOT spoil the answer. Make sure 180 doesn't appear
  // in the prompt copy as a standalone numeric clue.
  const s = steps.find((x) => x.fields.slug === "encapsulation");
  // It's fine if "180" appears as part of a larger description, but make
  // sure the prompt doesn't say "the answer is 180" or similar.
  const prompt = s.fields.prompt_template;
  assert.doesNotMatch(prompt, /answer is 180/i);
  assert.doesNotMatch(prompt, /v\[0\] = 180/);
  assert.doesNotMatch(prompt, /v\[0\] is 180/);
});

test("encapsulation prompt mentions the frozen randomness", () => {
  const s = steps.find((x) => x.fields.slug === "encapsulation");
  const prompt = s.fields.prompt_template;
  // Frozen r[0] = [0, -1, 1, 1] should be visible to the learner.
  assert.match(prompt, /r\[0\]/);
  assert.match(prompt, /e2/);
  assert.match(prompt, /128/);
});

test("keygen prompt shows the frozen t polynomial", () => {
  const s = steps.find((x) => x.fields.slug === "keygen");
  const prompt = s.fields.prompt_template;
  // From frozen vectors: t[0] = [72, 30, 20, 218]
  assert.match(prompt, /72/);
  assert.match(prompt, /218/);
});

test("decapsulation prompt walks the v - sᵀ·u computation and lands on bit 1", () => {
  const s = steps.find((x) => x.fields.slug === "decapsulation");
  const prompt = s.fields.prompt_template;
  // 131 is the canonical m'[0] for the frozen vectors with bit=1.
  assert.match(prompt, /131/);
  assert.match(prompt, /bit 1|m = 1/);
  // Noise budget
  assert.match(prompt, /17/);
  assert.match(prompt, /64/);
});
