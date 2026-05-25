// Smoke test: the fixtures JSON parses and has the expected shape per spec.
//
// This complements the Django fixture-load test; we don't load it into the
// DB here, just validate JSON well-formedness and the spec's locked
// allocations (algorithm pk 13, lesson pk 13, step pks 131-138).

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesPath = join(__dirname, "..", "..", "..", "..", "algorithms", "cipher-modes", "fixtures.json");

const fixtures = JSON.parse(readFileSync(fixturesPath, "utf8"));

test("fixtures has 10 records: 1 algorithm + 1 lesson + 8 steps", () => {
  assert.equal(fixtures.length, 10);
});

test("algorithm pk 13, slug cipher-modes, family symmetric", () => {
  const alg = fixtures.find((r) => r.model === "core.algorithm");
  assert.ok(alg);
  assert.equal(alg.pk, 13);
  assert.equal(alg.fields.slug, "cipher-modes");
  assert.equal(alg.fields.family, "symmetric");
  assert.equal(alg.fields.status, "live");
});

test("Algorithm.intro_template under 200 chars", () => {
  const alg = fixtures.find((r) => r.model === "core.algorithm");
  assert.ok(alg.fields.intro_template.length <= 200, `got ${alg.fields.intro_template.length}`);
});

test("lesson pk 13, slug modes-around-aes", () => {
  const lesson = fixtures.find((r) => r.model === "core.lesson");
  assert.ok(lesson);
  assert.equal(lesson.pk, 13);
  assert.equal(lesson.fields.slug, "modes-around-aes");
  assert.equal(lesson.fields.algorithm, 13);
  assert.equal(lesson.fields.title, "Block cipher modes (around AES)");
});

test("8 steps with pks 131-138 in order", () => {
  const steps = fixtures.filter((r) => r.model === "core.step");
  assert.equal(steps.length, 8);
  const expectedSlugs = [
    "intro", "ecb-penguin", "cbc-construction", "cbc-walk",
    "ctr-construction", "gcm-construction", "pick-a-mode", "done",
  ];
  steps.forEach((step, i) => {
    assert.equal(step.pk, 131 + i, `step ${i} pk`);
    assert.equal(step.fields.lesson, 13);
    assert.equal(step.fields.order, i + 1);
    assert.equal(step.fields.slug, expectedSlugs[i]);
  });
});

test("step 4 (cbc-walk) is input-text with cbc_walk validator", () => {
  const step = fixtures.find((r) => r.model === "core.step" && r.pk === 134);
  assert.equal(step.fields.kind, "input-text");
  assert.equal(step.fields.validator_key, "cbc_walk");
});

test("step 7 (pick-a-mode) is choose-from-list with pick_a_mode validator", () => {
  const step = fixtures.find((r) => r.model === "core.step" && r.pk === 137);
  assert.equal(step.fields.kind, "choose-from-list");
  assert.equal(step.fields.validator_key, "pick_a_mode");
});

test("all other steps are kind=info with validator_key=info", () => {
  const steps = fixtures.filter(
    (r) => r.model === "core.step" && r.pk !== 134 && r.pk !== 137,
  );
  assert.equal(steps.length, 6);
  steps.forEach((step) => {
    assert.equal(step.fields.kind, "info", `step ${step.pk} kind`);
    assert.equal(step.fields.validator_key, "info", `step ${step.pk} validator_key`);
  });
});
