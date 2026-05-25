// Sanity-check the fixtures JSON shape. Not strictly a unit test — but
// running it under node:test alongside the other validator tests catches
// PK / slug / intro_template-length regressions cheaply.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const fixturePath = resolve(here, "../../../../algorithms/hmac/fixtures.json");
const data = JSON.parse(readFileSync(fixturePath, "utf8"));

test("fixtures: one algorithm at pk=9, family=hash, slug=hmac", () => {
  const algos = data.filter((r) => r.model === "core.algorithm");
  assert.equal(algos.length, 1);
  const algo = algos[0];
  assert.equal(algo.pk, 9);
  assert.equal(algo.fields.slug, "hmac");
  assert.equal(algo.fields.family, "hash");
  assert.equal(algo.fields.status, "live");
});

test("fixtures: intro_template fits the 200-char model limit", () => {
  const algo = data.find((r) => r.model === "core.algorithm");
  assert.ok(
    algo.fields.intro_template.length <= 200,
    `intro_template is ${algo.fields.intro_template.length} chars (limit 200)`
  );
});

test("fixtures: one lesson at pk=9, slug mac-the-message", () => {
  const lessons = data.filter((r) => r.model === "core.lesson");
  assert.equal(lessons.length, 1);
  const lesson = lessons[0];
  assert.equal(lesson.pk, 9);
  assert.equal(lesson.fields.algorithm, 9);
  assert.equal(lesson.fields.slug, "mac-the-message");
});

test("fixtures: seven steps with pks 91-97 and the expected slug sequence", () => {
  const steps = data.filter((r) => r.model === "core.step");
  assert.equal(steps.length, 7);
  assert.deepEqual(
    steps.map((r) => r.pk).sort((a, b) => a - b),
    [91, 92, 93, 94, 95, 96, 97]
  );
  assert.deepEqual(
    steps.map((r) => r.fields.slug),
    [
      "intro",
      "naive-mac",
      "length-extension",
      "hmac-construction",
      "compute-hmac",
      "verify-and-tamper",
      "done",
    ]
  );
  // Validators wired correctly
  assert.equal(steps.find((r) => r.fields.slug === "compute-hmac").fields.validator_key, "compute_hmac");
  assert.equal(steps.find((r) => r.fields.slug === "verify-and-tamper").fields.validator_key, "verify_hmac");
});

test("fixtures: all steps belong to lesson 9 and have unique orders", () => {
  const steps = data.filter((r) => r.model === "core.step");
  const orders = steps.map((r) => r.fields.order);
  assert.equal(new Set(orders).size, steps.length);
  for (const s of steps) assert.equal(s.fields.lesson, 9);
});
