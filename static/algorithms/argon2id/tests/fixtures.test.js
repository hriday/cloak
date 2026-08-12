import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const data = JSON.parse(
  readFileSync(resolve(__dirname, "../../../../algorithms/argon2id/fixtures.json"), "utf-8")
);

const algo = data.find((e) => e.model === "core.algorithm");
const lesson = data.find((e) => e.model === "core.lesson");
const steps = data.filter((e) => e.model === "core.step");

test("fixtures: algorithm pk=34, slug/family/status/order", () => {
  assert.equal(algo.pk, 34);
  assert.equal(algo.fields.slug, "argon2id");
  assert.equal(algo.fields.family, "hash");
  assert.equal(algo.fields.status, "live");
  assert.equal(algo.fields.order, 34);
  assert.ok(algo.fields.intro_template.length <= 200);
});

test("fixtures: lesson pk=34 with 8 steps, PKs 341-348", () => {
  assert.equal(lesson.pk, 34);
  assert.equal(lesson.fields.slug, "the-one-the-committee-picked");
  assert.equal(steps.length, 8);
  assert.deepEqual(
    steps.map((s) => s.pk).sort(),
    [341, 342, 343, 344, 345, 346, 347, 348]
  );
});

test("fixtures: step slugs, kinds, validator keys", () => {
  const bySlug = Object.fromEntries(steps.map((s) => [s.fields.slug, s.fields]));
  assert.deepEqual(
    steps.sort((a, b) => a.fields.order - b.fields.order).map((s) => s.fields.slug),
    [
      "intro",
      "why-id",
      "the-block-matrix",
      "feel-the-memory",
      "anatomy-of-an-argon2-hash",
      "tuning",
      "argon2-vs-the-rest",
      "done",
    ]
  );
  assert.equal(bySlug["feel-the-memory"].kind, "input-numeric");
  assert.equal(bySlug["feel-the-memory"].validator_key, "memory_cost");
  assert.equal(bySlug["tuning"].kind, "input-numeric");
  assert.equal(bySlug["tuning"].validator_key, "tuning_math");
  assert.equal(bySlug["done"].codegen_key, "done");
});
