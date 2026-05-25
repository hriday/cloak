// Smoke test for the Django fixture JSON: structural sanity, PK uniqueness,
// 200-char intro_template ceiling, expected step slugs in order.
//
// This catches the common mistakes (over-long intro_template, missing field,
// duplicate PK, slug typo) without requiring Django at test time.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, "..", "..", "..", "..", "algorithms", "chacha20-poly1305", "fixtures.json");
const data = JSON.parse(readFileSync(fixturePath, "utf8"));

test("fixture parses as JSON array", () => {
  assert.equal(Array.isArray(data), true);
});

test("contains exactly 1 algorithm + 1 lesson + 7 steps", () => {
  const algos = data.filter((d) => d.model === "core.algorithm");
  const lessons = data.filter((d) => d.model === "core.lesson");
  const steps = data.filter((d) => d.model === "core.step");
  assert.equal(algos.length, 1);
  assert.equal(lessons.length, 1);
  assert.equal(steps.length, 7);
});

test("algorithm has pk=12 and correct top-level fields", () => {
  const algo = data.find((d) => d.model === "core.algorithm");
  assert.equal(algo.pk, 12);
  assert.equal(algo.fields.slug, "chacha20-poly1305");
  assert.equal(algo.fields.name, "ChaCha20-Poly1305");
  assert.equal(algo.fields.family, "symmetric");
  assert.equal(algo.fields.status, "live");
  assert.equal(algo.fields.order, 12);
});

test("intro_template is ≤200 characters (Algorithm.intro_template max_length)", () => {
  const algo = data.find((d) => d.model === "core.algorithm");
  assert.ok(
    algo.fields.intro_template.length <= 200,
    `intro_template is ${algo.fields.intro_template.length} chars, must be ≤200`,
  );
});

test("lesson has pk=12, algorithm=12, slug arx-aead", () => {
  const lesson = data.find((d) => d.model === "core.lesson");
  assert.equal(lesson.pk, 12);
  assert.equal(lesson.fields.algorithm, 12);
  assert.equal(lesson.fields.slug, "arx-aead");
  assert.equal(lesson.fields.order, 1);
});

test("steps have pks 121-127 in order with expected slugs", () => {
  const steps = data.filter((d) => d.model === "core.step")
    .sort((a, b) => a.fields.order - b.fields.order);
  assert.deepEqual(steps.map((s) => s.pk), [121, 122, 123, 124, 125, 126, 127]);
  assert.deepEqual(steps.map((s) => s.fields.slug), [
    "intro", "arx-design", "quarter-round", "block-function",
    "poly1305-construction", "encrypt-a-message", "done",
  ]);
});

test("interactive steps have the right validator + kind", () => {
  const steps = data.filter((d) => d.model === "core.step");
  const bySlug = Object.fromEntries(steps.map((s) => [s.fields.slug, s.fields]));
  assert.equal(bySlug["quarter-round"].kind, "input-numeric");
  assert.equal(bySlug["quarter-round"].validator_key, "quarter_round_line");
  assert.equal(bySlug["encrypt-a-message"].kind, "input-text");
  assert.equal(bySlug["encrypt-a-message"].validator_key, "encrypt_aead");
});

test("info-only steps use validator_key=info", () => {
  const steps = data.filter((d) => d.model === "core.step");
  const bySlug = Object.fromEntries(steps.map((s) => [s.fields.slug, s.fields]));
  for (const slug of ["intro", "arx-design", "block-function", "poly1305-construction", "done"]) {
    assert.equal(bySlug[slug].kind, "info");
    assert.equal(bySlug[slug].validator_key, "info");
  }
});

test("all steps belong to lesson=12", () => {
  const steps = data.filter((d) => d.model === "core.step");
  steps.forEach((s) => assert.equal(s.fields.lesson, 12));
});

test("step PKs are unique", () => {
  const steps = data.filter((d) => d.model === "core.step");
  const pks = new Set(steps.map((s) => s.pk));
  assert.equal(pks.size, steps.length);
});
