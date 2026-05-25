// Sanity-check the fixtures JSON shape. Catches PK / slug /
// intro_template-length regressions cheaply, mirroring the HMAC pattern.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const fixturePath = resolve(here, "../../../../algorithms/hkdf/fixtures.json");
const data = JSON.parse(readFileSync(fixturePath, "utf8"));

test("fixtures: one algorithm at pk=20, family=hash, slug=hkdf", () => {
  const algos = data.filter((r) => r.model === "core.algorithm");
  assert.equal(algos.length, 1);
  const algo = algos[0];
  assert.equal(algo.pk, 20);
  assert.equal(algo.fields.slug, "hkdf");
  assert.equal(algo.fields.name, "HKDF");
  assert.equal(algo.fields.family, "hash");
  assert.equal(algo.fields.status, "live");
  assert.equal(algo.fields.order, 20);
});

test("fixtures: intro_template fits the 200-char model limit", () => {
  const algo = data.find((r) => r.model === "core.algorithm");
  assert.ok(
    algo.fields.intro_template.length <= 200,
    `intro_template is ${algo.fields.intro_template.length} chars (limit 200)`
  );
});

test("fixtures: one lesson at pk=20, slug=extract-then-expand", () => {
  const lessons = data.filter((r) => r.model === "core.lesson");
  assert.equal(lessons.length, 1);
  const lesson = lessons[0];
  assert.equal(lesson.pk, 20);
  assert.equal(lesson.fields.algorithm, 20);
  assert.equal(lesson.fields.slug, "extract-then-expand");
  assert.equal(lesson.fields.title, "HKDF: extract then expand");
});

test("fixtures: six steps with pks 201-206 and the expected slug sequence", () => {
  const steps = data.filter((r) => r.model === "core.step");
  assert.equal(steps.length, 6);
  assert.deepEqual(
    steps.map((r) => r.pk).sort((a, b) => a - b),
    [201, 202, 203, 204, 205, 206]
  );
  assert.deepEqual(
    steps.map((r) => r.fields.slug),
    [
      "intro",
      "extract-step",
      "expand-step",
      "derive-keys",
      "vs-pbkdf2",
      "done",
    ]
  );
});

test("fixtures: derive-keys step is input-text with validator_key=derive_keys", () => {
  const steps = data.filter((r) => r.model === "core.step");
  const dk = steps.find((r) => r.fields.slug === "derive-keys");
  assert.equal(dk.fields.kind, "input-text");
  assert.equal(dk.fields.validator_key, "derive_keys");
  assert.equal(dk.fields.codegen_key, "derive_keys");
});

test("fixtures: done step is info with codegen_key=full_script", () => {
  const steps = data.filter((r) => r.model === "core.step");
  const done = steps.find((r) => r.fields.slug === "done");
  assert.equal(done.fields.kind, "info");
  assert.equal(done.fields.codegen_key, "full_script");
});

test("fixtures: all info steps have validator_key=info, codegen_key=info (except done)", () => {
  const steps = data.filter((r) => r.model === "core.step");
  const infoSlugs = ["intro", "extract-step", "expand-step", "vs-pbkdf2"];
  for (const slug of infoSlugs) {
    const s = steps.find((r) => r.fields.slug === slug);
    assert.equal(s.fields.kind, "info");
    assert.equal(s.fields.validator_key, "info");
    assert.equal(s.fields.codegen_key, "info");
  }
});

test("fixtures: all steps belong to lesson 20 and have unique orders", () => {
  const steps = data.filter((r) => r.model === "core.step");
  const orders = steps.map((r) => r.fields.order);
  assert.equal(new Set(orders).size, steps.length);
  for (const s of steps) assert.equal(s.fields.lesson, 20);
});

test("fixtures: every step has a non-empty prompt_template", () => {
  const steps = data.filter((r) => r.model === "core.step");
  for (const s of steps) {
    assert.ok(s.fields.prompt_template);
    assert.ok(s.fields.prompt_template.length > 50);
  }
});
