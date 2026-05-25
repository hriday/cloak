import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

// Locate the repo's algorithms/padding-oracle/fixtures.json. We resolve
// relative to this file so the test still works if the runner is invoked
// from a different cwd.
const FIXTURE_PATH = path.resolve(
  process.cwd(),
  "algorithms/padding-oracle/fixtures.json"
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

test("algorithm record has pk=14, slug=padding-oracle, family=symmetric, name=Padding Oracle Attack", () => {
  const algo = fixture.find((r) => r.model === "core.algorithm");
  assert.equal(algo.pk, 14);
  assert.equal(algo.fields.slug, "padding-oracle");
  assert.equal(algo.fields.name, "Padding Oracle Attack");
  assert.equal(algo.fields.family, "symmetric");
  assert.equal(algo.fields.status, "live");
});

test("algorithm intro_template is ≤200 characters", () => {
  const algo = fixture.find((r) => r.model === "core.algorithm");
  assert.ok(
    typeof algo.fields.intro_template === "string",
    "intro_template must be a string"
  );
  assert.ok(
    algo.fields.intro_template.length <= 200,
    `intro_template is ${algo.fields.intro_template.length} chars (>200)`
  );
});

test("lesson record has pk=14, slug=decrypt-without-the-key, algorithm=14", () => {
  const lesson = fixture.find((r) => r.model === "core.lesson");
  assert.equal(lesson.pk, 14);
  assert.equal(lesson.fields.slug, "decrypt-without-the-key");
  assert.equal(lesson.fields.algorithm, 14);
  assert.equal(lesson.fields.title, "Padding oracle: decrypt without the key");
});

test("step pks are 141..147 in order 1..7 with expected slugs", () => {
  const steps = fixture
    .filter((r) => r.model === "core.step")
    .sort((a, b) => a.fields.order - b.fields.order);
  const expected = [
    { pk: 141, order: 1, slug: "intro", kind: "info" },
    { pk: 142, order: 2, slug: "pkcs7-recap", kind: "info" },
    { pk: 143, order: 3, slug: "bit-flipping", kind: "info" },
    { pk: 144, order: 4, slug: "attack-one-byte", kind: "input-text" },
    { pk: 145, order: 5, slug: "attack-full-block", kind: "input-text" },
    { pk: 146, order: 6, slug: "defenses", kind: "info" },
    { pk: 147, order: 7, slug: "done", kind: "info" },
  ];
  for (let i = 0; i < expected.length; i++) {
    assert.equal(steps[i].pk, expected[i].pk, `step ${i} pk`);
    assert.equal(steps[i].fields.order, expected[i].order, `step ${i} order`);
    assert.equal(steps[i].fields.slug, expected[i].slug, `step ${i} slug`);
    assert.equal(steps[i].fields.kind, expected[i].kind, `step ${i} kind`);
    assert.equal(steps[i].fields.lesson, 14, `step ${i} lesson`);
  }
});

test("step 144 (attack-one-byte) uses recover_byte validator", () => {
  const step = fixture.find((r) => r.model === "core.step" && r.pk === 144);
  assert.equal(step.fields.validator_key, "recover_byte");
});

test("step 145 (attack-full-block) uses recover_block validator", () => {
  const step = fixture.find((r) => r.model === "core.step" && r.pk === 145);
  assert.equal(step.fields.validator_key, "recover_block");
});

test("step 147 (done) uses full_script codegen", () => {
  const step = fixture.find((r) => r.model === "core.step" && r.pk === 147);
  assert.equal(step.fields.codegen_key, "full_script");
});

test("info-kind steps use info validator and info codegen", () => {
  const infoPks = [141, 142, 143, 146, 147];
  for (const pk of infoPks) {
    const step = fixture.find((r) => r.model === "core.step" && r.pk === pk);
    assert.equal(step.fields.validator_key, "info", `step ${pk} validator_key`);
    // Step 147's codegen is full_script for the Done page; the rest are info.
    if (pk !== 147) {
      assert.equal(step.fields.codegen_key, "info", `step ${pk} codegen_key`);
    }
  }
});
