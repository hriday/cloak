import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const FIXTURE_PATH = path.resolve(
  process.cwd(),
  "algorithms/bleichenbacher/fixtures.json"
);

let fixture;
try {
  fixture = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));
} catch (e) {
  throw new Error(`fixtures.json not loadable: ${e.message}`);
}

test("fixtures.json is a JSON array", () => {
  assert.ok(Array.isArray(fixture));
});

test("fixtures.json contains exactly 1 algorithm, 1 lesson, 7 steps", () => {
  const algos = fixture.filter((r) => r.model === "core.algorithm");
  const lessons = fixture.filter((r) => r.model === "core.lesson");
  const steps = fixture.filter((r) => r.model === "core.step");
  assert.equal(algos.length, 1);
  assert.equal(lessons.length, 1);
  assert.equal(steps.length, 7);
});

test("algorithm record has pk=27, slug=bleichenbacher, family=asymmetric, name='Bleichenbacher Attack'", () => {
  const algo = fixture.find((r) => r.model === "core.algorithm");
  assert.equal(algo.pk, 27);
  assert.equal(algo.fields.slug, "bleichenbacher");
  assert.equal(algo.fields.name, "Bleichenbacher Attack");
  assert.equal(algo.fields.family, "asymmetric");
  assert.equal(algo.fields.status, "live");
  assert.equal(algo.fields.order, 27);
});

test("algorithm intro_template is ≤200 characters", () => {
  const algo = fixture.find((r) => r.model === "core.algorithm");
  assert.equal(typeof algo.fields.intro_template, "string");
  assert.ok(
    algo.fields.intro_template.length <= 200,
    `intro_template is ${algo.fields.intro_template.length} chars (>200)`
  );
});

test("lesson record has pk=27, slug=million-message-attack, algorithm=27", () => {
  const lesson = fixture.find((r) => r.model === "core.lesson");
  assert.equal(lesson.pk, 27);
  assert.equal(lesson.fields.slug, "million-message-attack");
  assert.equal(lesson.fields.algorithm, 27);
  assert.equal(lesson.fields.title, "Bleichenbacher: the million-message attack");
});

test("step pks are 271..277 in order 1..7 with expected slugs and kinds", () => {
  const steps = fixture
    .filter((r) => r.model === "core.step")
    .sort((a, b) => a.fields.order - b.fields.order);
  const expected = [
    { pk: 271, order: 1, slug: "intro", kind: "info" },
    { pk: 272, order: 2, slug: "pkcs1-v1-5-padding", kind: "info" },
    { pk: 273, order: 3, slug: "the-oracle", kind: "info" },
    { pk: 274, order: 4, slug: "the-search", kind: "info" },
    { pk: 275, order: 5, slug: "run-the-attack", kind: "input-text" },
    { pk: 276, order: 6, slug: "defenses", kind: "info" },
    { pk: 277, order: 7, slug: "done", kind: "info" },
  ];
  for (let i = 0; i < expected.length; i++) {
    assert.equal(steps[i].pk, expected[i].pk, `step ${i} pk`);
    assert.equal(steps[i].fields.order, expected[i].order, `step ${i} order`);
    assert.equal(steps[i].fields.slug, expected[i].slug, `step ${i} slug`);
    assert.equal(steps[i].fields.kind, expected[i].kind, `step ${i} kind`);
    assert.equal(steps[i].fields.lesson, 27, `step ${i} lesson`);
  }
});

test("step 275 (run-the-attack) uses run_attack validator", () => {
  const step = fixture.find((r) => r.model === "core.step" && r.pk === 275);
  assert.equal(step.fields.validator_key, "run_attack");
});

test("step 277 (done) uses full_script codegen", () => {
  const step = fixture.find((r) => r.model === "core.step" && r.pk === 277);
  assert.equal(step.fields.codegen_key, "full_script");
});

test("info-kind steps use info validator and (mostly) info codegen", () => {
  // Steps 271, 272, 273, 274, 276, 277 are info; 275 is input-text.
  const infoPks = [271, 272, 273, 274, 276, 277];
  for (const pk of infoPks) {
    const step = fixture.find((r) => r.model === "core.step" && r.pk === pk);
    assert.equal(step.fields.validator_key, "info", `step ${pk} validator_key`);
    if (pk !== 277) {
      assert.equal(step.fields.codegen_key, "info", `step ${pk} codegen_key`);
    }
  }
});

test("all step prompt_templates are non-empty", () => {
  const steps = fixture.filter((r) => r.model === "core.step");
  for (const s of steps) {
    assert.equal(typeof s.fields.prompt_template, "string", `step ${s.pk} prompt_template`);
    assert.ok(s.fields.prompt_template.length > 0, `step ${s.pk} prompt_template empty`);
    assert.equal(typeof s.fields.help_template, "string", `step ${s.pk} help_template`);
    assert.ok(s.fields.help_template.length > 0, `step ${s.pk} help_template empty`);
  }
});

test("state prefix: all state keys referenced in prompt_templates use 'bleich_' prefix", () => {
  // Soft check: nothing forbids referring to other state in prose, but the
  // validator output uses bleich_ prefix exclusively. Just sanity-check the
  // run-the-attack step's prompt doesn't contradict that.
  const step5 = fixture.find((r) => r.model === "core.step" && r.pk === 275);
  // Should not reference 'po_' state (that's the padding-oracle prefix).
  assert.doesNotMatch(step5.fields.prompt_template, /\bpo_[a-z]/);
});
