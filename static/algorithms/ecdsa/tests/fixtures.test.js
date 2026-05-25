// Sanity-check the Django fixtures JSON. Catches malformed JSON, drift
// between spec PKs and the file, missing slugs, and validator/codegen
// key mismatches *before* `manage.py loaddata` is asked to load them.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesPath = resolve(__dirname, "../../../../algorithms/ecdsa/fixtures.json");
const fixtures = JSON.parse(readFileSync(fixturesPath, "utf8"));

test("fixtures.json parses as JSON", () => {
  assert.ok(Array.isArray(fixtures));
});

test("fixtures.json has one Algorithm row pk=17, slug=ecdsa, family=asymmetric", () => {
  const algos = fixtures.filter((e) => e.model === "core.algorithm");
  assert.equal(algos.length, 1);
  const a = algos[0];
  assert.equal(a.pk, 17);
  assert.equal(a.fields.slug, "ecdsa");
  assert.equal(a.fields.family, "asymmetric");
  assert.equal(a.fields.name, "ECDSA");
  assert.equal(a.fields.status, "live");
});

test("Algorithm.intro_template is non-empty and ≤200 chars", () => {
  const a = fixtures.find((e) => e.model === "core.algorithm");
  assert.ok(a.fields.intro_template.length > 0);
  assert.ok(
    a.fields.intro_template.length <= 200,
    `intro_template is ${a.fields.intro_template.length} chars, must be ≤200`,
  );
});

test("fixtures.json has one Lesson row pk=17, slug=the-ps3-disaster", () => {
  const lessons = fixtures.filter((e) => e.model === "core.lesson");
  assert.equal(lessons.length, 1);
  const l = lessons[0];
  assert.equal(l.pk, 17);
  assert.equal(l.fields.slug, "the-ps3-disaster");
  assert.equal(l.fields.title, "ECDSA: the PS3 disaster");
  assert.equal(l.fields.algorithm, 17);
});

test("fixtures.json has 7 Step rows with pks 171..177 in order", () => {
  const steps = fixtures.filter((e) => e.model === "core.step");
  assert.equal(steps.length, 7);
  const pks = steps.map((s) => s.pk).sort((a, b) => a - b);
  assert.deepEqual(pks, [171, 172, 173, 174, 175, 176, 177]);
});

test("Step slugs match the spec sequence", () => {
  const steps = fixtures
    .filter((e) => e.model === "core.step")
    .sort((a, b) => a.fields.order - b.fields.order);
  const slugs = steps.map((s) => s.fields.slug);
  assert.deepEqual(slugs, [
    "intro",
    "curve-recap",
    "sign-mechanics",
    "verify-mechanics",
    "the-ps3-attack",
    "aftermath-and-defenses",
    "done",
  ]);
});

test("step `the-ps3-attack` is input-numeric with validator_key recover_k", () => {
  const step = fixtures
    .filter((e) => e.model === "core.step")
    .find((s) => s.fields.slug === "the-ps3-attack");
  assert.ok(step);
  assert.equal(step.fields.kind, "input-numeric");
  assert.equal(step.fields.validator_key, "recover_k");
});

test("all non-PS3-attack steps are info kind with info validator", () => {
  const steps = fixtures
    .filter((e) => e.model === "core.step")
    .filter((s) => s.fields.slug !== "the-ps3-attack");
  for (const s of steps) {
    assert.equal(s.fields.kind, "info", `${s.fields.slug} should be info`);
    assert.equal(
      s.fields.validator_key,
      "info",
      `${s.fields.slug} should validate via info`,
    );
  }
});

test("the done step uses full_script for codegen; all others use info", () => {
  const steps = fixtures.filter((e) => e.model === "core.step");
  for (const s of steps) {
    if (s.fields.slug === "done") {
      assert.equal(s.fields.codegen_key, "full_script");
    } else {
      assert.equal(s.fields.codegen_key, "info");
    }
  }
});

test("the-ps3-attack prompt includes the canonical signatures table", () => {
  const step = fixtures
    .filter((e) => e.model === "core.step")
    .find((s) => s.fields.slug === "the-ps3-attack");
  const p = step.fields.prompt_template;
  // The two given signature rows must literally appear in the prompt body.
  assert.match(p, /e₁ = 4/);
  assert.match(p, /e₂ = 10/);
  assert.match(p, /\| 8 \| 7 \|/);  // r=8, s=7
  assert.match(p, /\| 8 \| 9 \|/);  // r=8, s=9
  // And the recovery formula
  assert.match(p, /e₁\s*−\s*e₂/);
  assert.match(p, /s₁\s*−\s*s₂/);
});
