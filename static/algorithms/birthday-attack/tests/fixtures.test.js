import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const FIXTURE_PATH = path.resolve(
  process.cwd(),
  "algorithms/birthday-attack/fixtures.json"
);

let fixture;
try {
  fixture = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));
} catch (e) {
  throw new Error(`fixtures.json not loadable: ${e.message}`);
}

test("fixtures.json is valid JSON", () => {
  assert.ok(Array.isArray(fixture), "top-level must be an array");
});

test("fixtures.json contains exactly 1 algorithm, 1 lesson, 6 steps", () => {
  const algos = fixture.filter((r) => r.model === "core.algorithm");
  const lessons = fixture.filter((r) => r.model === "core.lesson");
  const steps = fixture.filter((r) => r.model === "core.step");
  assert.equal(algos.length, 1);
  assert.equal(lessons.length, 1);
  assert.equal(steps.length, 6);
});

test("algorithm has pk=29, slug=birthday-attack, family=hash, name=Birthday Attack", () => {
  const algo = fixture.find((r) => r.model === "core.algorithm");
  assert.equal(algo.pk, 29);
  assert.equal(algo.fields.slug, "birthday-attack");
  assert.equal(algo.fields.name, "Birthday Attack");
  assert.equal(algo.fields.family, "hash");
  assert.equal(algo.fields.status, "live");
  assert.equal(algo.fields.order, 29);
});

test("algorithm intro_template is <=200 characters", () => {
  const algo = fixture.find((r) => r.model === "core.algorithm");
  assert.equal(typeof algo.fields.intro_template, "string");
  assert.ok(
    algo.fields.intro_template.length <= 200,
    `intro_template is ${algo.fields.intro_template.length} chars (>200)`
  );
});

test("lesson has pk=29, slug=square-root-of-n, algorithm=29", () => {
  const lesson = fixture.find((r) => r.model === "core.lesson");
  assert.equal(lesson.pk, 29);
  assert.equal(lesson.fields.slug, "square-root-of-n");
  assert.equal(lesson.fields.algorithm, 29);
  assert.equal(
    lesson.fields.title,
    "The birthday attack: when √N is enough"
  );
});

test("step pks are 291..296 in order 1..6 with expected slugs and kinds", () => {
  const steps = fixture
    .filter((r) => r.model === "core.step")
    .sort((a, b) => a.fields.order - b.fields.order);
  const expected = [
    { pk: 291, order: 1, slug: "intro", kind: "info" },
    { pk: 292, order: 2, slug: "the-math", kind: "info" },
    { pk: 293, order: 3, slug: "find-a-collision", kind: "input-text" },
    { pk: 294, order: 4, slug: "more-bits-more-work", kind: "info" },
    { pk: 295, order: 5, slug: "hmac-and-other-defenses", kind: "info" },
    { pk: 296, order: 6, slug: "done", kind: "info" },
  ];
  for (let i = 0; i < expected.length; i++) {
    assert.equal(steps[i].pk, expected[i].pk, `step ${i} pk`);
    assert.equal(steps[i].fields.order, expected[i].order, `step ${i} order`);
    assert.equal(steps[i].fields.slug, expected[i].slug, `step ${i} slug`);
    assert.equal(steps[i].fields.kind, expected[i].kind, `step ${i} kind`);
    assert.equal(steps[i].fields.lesson, 29, `step ${i} lesson`);
  }
});

test("step 293 (find-a-collision) uses find_collision validator", () => {
  const step = fixture.find((r) => r.model === "core.step" && r.pk === 293);
  assert.equal(step.fields.validator_key, "find_collision");
});

test("step 296 (done) uses full_script codegen", () => {
  const step = fixture.find((r) => r.model === "core.step" && r.pk === 296);
  assert.equal(step.fields.codegen_key, "full_script");
});

test("info-kind steps use info validator", () => {
  const infoPks = [291, 292, 294, 295, 296];
  for (const pk of infoPks) {
    const step = fixture.find((r) => r.model === "core.step" && r.pk === pk);
    assert.equal(step.fields.validator_key, "info", `step ${pk} validator_key`);
  }
});

test("every step has prompt_template and help_template", () => {
  const steps = fixture.filter((r) => r.model === "core.step");
  for (const s of steps) {
    assert.equal(typeof s.fields.prompt_template, "string", `step ${s.pk} prompt`);
    assert.ok(s.fields.prompt_template.length > 0, `step ${s.pk} prompt empty`);
    assert.equal(typeof s.fields.help_template, "string", `step ${s.pk} help`);
    assert.ok(s.fields.help_template.length > 0, `step ${s.pk} help empty`);
  }
});
