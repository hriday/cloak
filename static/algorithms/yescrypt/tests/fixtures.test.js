import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const data = JSON.parse(
  readFileSync(resolve(__dirname, "../../../../algorithms/yescrypt/fixtures.json"), "utf-8")
);

const algo = data.find((e) => e.model === "core.algorithm");
const lesson = data.find((e) => e.model === "core.lesson");
const steps = data.filter((e) => e.model === "core.step");

test("fixtures: algorithm pk=32, slug/family/status/order", () => {
  assert.equal(algo.pk, 32);
  assert.equal(algo.fields.slug, "yescrypt");
  assert.equal(algo.fields.family, "hash");
  assert.equal(algo.fields.status, "live");
  assert.equal(algo.fields.order, 32);
  assert.ok(algo.fields.intro_template.length <= 200);
});

test("fixtures: lesson pk=32 with 7 steps, PKs 321-327", () => {
  assert.equal(lesson.pk, 32);
  assert.equal(lesson.fields.slug, "the-default-nobody-noticed");
  assert.equal(steps.length, 7);
  assert.deepEqual(steps.map((s) => s.pk).sort(), [321, 322, 323, 324, 325, 326, 327]);
});

test("fixtures: step slugs, kinds, validator keys", () => {
  const bySlug = Object.fromEntries(steps.map((s) => [s.fields.slug, s.fields]));
  assert.deepEqual(
    steps.sort((a, b) => a.fields.order - b.fields.order).map((s) => s.fields.slug),
    ["intro", "scrypt-lineage", "feel-the-memory", "anatomy-of-a-y-hash",
     "rom-and-scale", "yescrypt-vs-argon2", "done"]
  );
  assert.equal(bySlug["feel-the-memory"].kind, "input-numeric");
  assert.equal(bySlug["feel-the-memory"].validator_key, "memory_cost");
  assert.equal(bySlug["done"].codegen_key, "done");
});
