import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

// Resolve relative to this file so the runner works from any cwd.
const FIXTURE_PATH = path.resolve(
  process.cwd(),
  "algorithms/length-extension/fixtures.json"
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

test("fixtures.json contains exactly 1 algorithm, 1 lesson, 7 steps", () => {
  const algos = fixture.filter((r) => r.model === "core.algorithm");
  const lessons = fixture.filter((r) => r.model === "core.lesson");
  const steps = fixture.filter((r) => r.model === "core.step");
  assert.equal(algos.length, 1);
  assert.equal(lessons.length, 1);
  assert.equal(steps.length, 7);
});

test("algorithm has pk=21, slug=length-extension, family=hash, name=Length Extension Attack", () => {
  const algo = fixture.find((r) => r.model === "core.algorithm");
  assert.equal(algo.pk, 21);
  assert.equal(algo.fields.slug, "length-extension");
  assert.equal(algo.fields.name, "Length Extension Attack");
  assert.equal(algo.fields.family, "hash");
  assert.equal(algo.fields.status, "live");
  assert.equal(algo.fields.order, 21);
});

test("algorithm intro_template is <=200 characters", () => {
  const algo = fixture.find((r) => r.model === "core.algorithm");
  assert.ok(typeof algo.fields.intro_template === "string");
  assert.ok(
    algo.fields.intro_template.length <= 200,
    `intro_template is ${algo.fields.intro_template.length} chars (>200)`
  );
});

test("lesson has pk=21, slug=forge-without-the-key, algorithm=21", () => {
  const lesson = fixture.find((r) => r.model === "core.lesson");
  assert.equal(lesson.pk, 21);
  assert.equal(lesson.fields.slug, "forge-without-the-key");
  assert.equal(lesson.fields.algorithm, 21);
  assert.equal(lesson.fields.title, "Length extension: forge without the key");
});

test("step pks are 211..217 in order 1..7 with expected slugs and kinds", () => {
  const steps = fixture
    .filter((r) => r.model === "core.step")
    .sort((a, b) => a.fields.order - b.fields.order);
  const expected = [
    { pk: 211, order: 1, slug: "intro", kind: "info" },
    { pk: 212, order: 2, slug: "merkle-damgard-recap", kind: "info" },
    { pk: 213, order: 3, slug: "the-attack", kind: "info" },
    { pk: 214, order: 4, slug: "run-the-attack", kind: "input-text" },
    { pk: 215, order: 5, slug: "why-hmac-fixes-it", kind: "info" },
    { pk: 216, order: 6, slug: "other-defenses", kind: "info" },
    { pk: 217, order: 7, slug: "done", kind: "info" },
  ];
  for (let i = 0; i < expected.length; i++) {
    assert.equal(steps[i].pk, expected[i].pk, `step ${i} pk`);
    assert.equal(steps[i].fields.order, expected[i].order, `step ${i} order`);
    assert.equal(steps[i].fields.slug, expected[i].slug, `step ${i} slug`);
    assert.equal(steps[i].fields.kind, expected[i].kind, `step ${i} kind`);
    assert.equal(steps[i].fields.lesson, 21, `step ${i} lesson`);
  }
});

test("step 214 (run-the-attack) uses run_attack validator", () => {
  const step = fixture.find((r) => r.model === "core.step" && r.pk === 214);
  assert.equal(step.fields.validator_key, "run_attack");
});

test("step 217 (done) uses full_script codegen", () => {
  const step = fixture.find((r) => r.model === "core.step" && r.pk === 217);
  assert.equal(step.fields.codegen_key, "full_script");
});

test("info-kind steps use info validator", () => {
  const infoPks = [211, 212, 213, 215, 216, 217];
  for (const pk of infoPks) {
    const step = fixture.find((r) => r.model === "core.step" && r.pk === pk);
    assert.equal(step.fields.validator_key, "info", `step ${pk} validator_key`);
  }
});

test("non-done info steps use info codegen", () => {
  const infoPks = [211, 212, 213, 215, 216];
  for (const pk of infoPks) {
    const step = fixture.find((r) => r.model === "core.step" && r.pk === pk);
    assert.equal(step.fields.codegen_key, "info", `step ${pk} codegen_key`);
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
