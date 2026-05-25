import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_PATH = resolve(
  __dirname,
  "../../../../algorithms/bcrypt/fixtures.json"
);
const data = JSON.parse(readFileSync(FIXTURES_PATH, "utf-8"));

const algo = data.find((e) => e.model === "core.algorithm");
const lesson = data.find((e) => e.model === "core.lesson");
const steps = data.filter((e) => e.model === "core.step");

test("fixtures: exactly one algorithm record", () => {
  assert.equal(data.filter((e) => e.model === "core.algorithm").length, 1);
});

test("fixtures: algorithm pk=31, slug='bcrypt', family='hash'", () => {
  assert.equal(algo.pk, 31);
  assert.equal(algo.fields.slug, "bcrypt");
  assert.equal(algo.fields.family, "hash");
  assert.equal(algo.fields.name, "bcrypt");
  assert.equal(algo.fields.status, "live");
  assert.equal(algo.fields.order, 31);
});

test("fixtures: algorithm.intro_template <= 200 chars", () => {
  assert.ok(
    algo.fields.intro_template.length <= 200,
    `intro_template is ${algo.fields.intro_template.length} chars, must be <=200`
  );
});

test("fixtures: exactly one lesson record, pk=31, slug='slowed-down-blowfish'", () => {
  assert.equal(data.filter((e) => e.model === "core.lesson").length, 1);
  assert.equal(lesson.pk, 31);
  assert.equal(lesson.fields.algorithm, 31);
  assert.equal(lesson.fields.slug, "slowed-down-blowfish");
  assert.equal(lesson.fields.title, "bcrypt: Blowfish slowed down on purpose");
  assert.equal(lesson.fields.order, 1);
});

test("fixtures: 7 step records with pks 311-317", () => {
  assert.equal(steps.length, 7);
  const pks = steps.map((s) => s.pk).sort();
  assert.deepEqual(pks, [311, 312, 313, 314, 315, 316, 317]);
});

test("fixtures: step slugs in expected order", () => {
  const sorted = [...steps].sort((a, b) => a.fields.order - b.fields.order);
  const slugs = sorted.map((s) => s.fields.slug);
  assert.deepEqual(slugs, [
    "intro",
    "the-blowfish-connection",
    "eksblowfish",
    "time-the-cost",
    "salt-and-format",
    "bcrypt-vs-argon2",
    "done",
  ]);
});

test("fixtures: every step lesson=31", () => {
  for (const step of steps) {
    assert.equal(step.fields.lesson, 31, `step ${step.fields.slug} lesson`);
  }
});

test("fixtures: step kinds match spec (input-numeric only on time-the-cost)", () => {
  const bySlug = Object.fromEntries(steps.map((s) => [s.fields.slug, s]));
  assert.equal(bySlug["intro"].fields.kind, "info");
  assert.equal(bySlug["the-blowfish-connection"].fields.kind, "info");
  assert.equal(bySlug["eksblowfish"].fields.kind, "info");
  assert.equal(bySlug["time-the-cost"].fields.kind, "input-numeric");
  assert.equal(bySlug["salt-and-format"].fields.kind, "info");
  assert.equal(bySlug["bcrypt-vs-argon2"].fields.kind, "info");
  assert.equal(bySlug["done"].fields.kind, "info");
});

test("fixtures: time-the-cost step uses time_cost validator", () => {
  const s = steps.find((e) => e.fields.slug === "time-the-cost");
  assert.equal(s.fields.validator_key, "time_cost");
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

test("fixtures: every step has a help_template", () => {
  for (const step of steps) {
    assert.equal(typeof step.fields.help_template, "string");
  }
});

test("fixtures: intro step cross-references blowfish and password-hashing lessons", () => {
  const intro = steps.find((e) => e.fields.slug === "intro");
  assert.match(intro.fields.prompt_template, /blowfish/i);
  assert.match(intro.fields.prompt_template, /password-hashing|Password Hashing/);
});

test("fixtures: the-blowfish-connection mentions ~521 Blowfish encryptions", () => {
  const s = steps.find((e) => e.fields.slug === "the-blowfish-connection");
  assert.match(s.fields.prompt_template, /521/);
});

test("fixtures: eksblowfish mentions OrpheanBeholderScryDoubt", () => {
  const s = steps.find((e) => e.fields.slug === "eksblowfish");
  assert.match(s.fields.prompt_template, /OrpheanBeholderScryDoubt/);
});

test("fixtures: salt-and-format mentions 72-byte truncation and $2b$", () => {
  const s = steps.find((e) => e.fields.slug === "salt-and-format");
  assert.match(s.fields.prompt_template, /72/);
  assert.match(s.fields.prompt_template, /\$2b\$/);
});

test("fixtures: bcrypt-vs-argon2 lists all three (bcrypt, Argon2id, PBKDF2)", () => {
  const s = steps.find((e) => e.fields.slug === "bcrypt-vs-argon2");
  assert.match(s.fields.prompt_template, /bcrypt/i);
  assert.match(s.fields.prompt_template, /Argon2id/i);
  assert.match(s.fields.prompt_template, /PBKDF2/);
});
