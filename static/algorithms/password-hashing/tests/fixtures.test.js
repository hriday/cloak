import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_PATH = resolve(
  __dirname,
  "../../../../algorithms/password-hashing/fixtures.json"
);
const data = JSON.parse(readFileSync(FIXTURES_PATH, "utf-8"));

const algo = data.find((e) => e.model === "core.algorithm");
const lesson = data.find((e) => e.model === "core.lesson");
const steps = data.filter((e) => e.model === "core.step");

test("fixtures: exactly one algorithm record", () => {
  assert.equal(data.filter((e) => e.model === "core.algorithm").length, 1);
});

test("fixtures: algorithm pk=15, slug='password-hashing', family='hash'", () => {
  assert.equal(algo.pk, 15);
  assert.equal(algo.fields.slug, "password-hashing");
  assert.equal(algo.fields.family, "hash");
  assert.equal(algo.fields.name, "Password Hashing");
  assert.equal(algo.fields.status, "live");
  assert.equal(algo.fields.order, 15);
});

test("fixtures: algorithm.intro_template <= 200 chars", () => {
  assert.ok(
    algo.fields.intro_template.length <= 200,
    `intro_template is ${algo.fields.intro_template.length} chars, must be <=200`
  );
});

test("fixtures: exactly one lesson record, pk=15, slug='slow-on-purpose'", () => {
  assert.equal(data.filter((e) => e.model === "core.lesson").length, 1);
  assert.equal(lesson.pk, 15);
  assert.equal(lesson.fields.algorithm, 15);
  assert.equal(lesson.fields.slug, "slow-on-purpose");
  assert.equal(lesson.fields.title, "Password hashing: slow on purpose");
  assert.equal(lesson.fields.order, 1);
});

test("fixtures: 8 step records with pks 151-158", () => {
  assert.equal(steps.length, 8);
  const pks = steps.map((s) => s.pk).sort();
  assert.deepEqual(pks, [151, 152, 153, 154, 155, 156, 157, 158]);
});

test("fixtures: step slugs in expected order", () => {
  const sorted = [...steps].sort((a, b) => a.fields.order - b.fields.order);
  const slugs = sorted.map((s) => s.fields.slug);
  assert.deepEqual(slugs, [
    "intro",
    "naive-sha256-failure",
    "pbkdf2",
    "bcrypt",
    "argon2-construction",
    "compare-hashes",
    "which-to-use",
    "done",
  ]);
});

test("fixtures: every step lesson=15", () => {
  for (const step of steps) {
    assert.equal(step.fields.lesson, 15, `step ${step.fields.slug} lesson`);
  }
});

test("fixtures: step kinds match spec (input-text on pbkdf2 + compare-hashes)", () => {
  const bySlug = Object.fromEntries(steps.map((s) => [s.fields.slug, s]));
  assert.equal(bySlug["intro"].fields.kind, "info");
  assert.equal(bySlug["naive-sha256-failure"].fields.kind, "info");
  assert.equal(bySlug["pbkdf2"].fields.kind, "input-text");
  assert.equal(bySlug["bcrypt"].fields.kind, "info");
  assert.equal(bySlug["argon2-construction"].fields.kind, "info");
  assert.equal(bySlug["compare-hashes"].fields.kind, "input-text");
  assert.equal(bySlug["which-to-use"].fields.kind, "info");
  assert.equal(bySlug["done"].fields.kind, "info");
});

test("fixtures: pbkdf2 step uses pbkdf2_compute validator", () => {
  const s = steps.find((e) => e.fields.slug === "pbkdf2");
  assert.equal(s.fields.validator_key, "pbkdf2_compute");
});

test("fixtures: compare-hashes step uses compare_all validator", () => {
  const s = steps.find((e) => e.fields.slug === "compare-hashes");
  assert.equal(s.fields.validator_key, "compare_all");
});

test("fixtures: done step uses done codegen", () => {
  const s = steps.find((e) => e.fields.slug === "done");
  assert.equal(s.fields.codegen_key, "done");
});

test("fixtures: every step has a non-empty prompt_template", () => {
  for (const step of steps) {
    assert.ok(
      step.fields.prompt_template.length > 0,
      `step ${step.fields.slug} prompt_template`
    );
  }
});

test("fixtures: every step has a help_template (may be the empty string only for done)", () => {
  for (const step of steps) {
    assert.equal(typeof step.fields.help_template, "string");
  }
});
