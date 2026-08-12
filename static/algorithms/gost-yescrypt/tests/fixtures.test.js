import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const data = JSON.parse(
  readFileSync(resolve(__dirname, "../../../../algorithms/gost-yescrypt/fixtures.json"), "utf-8")
);

const algo = data.find((e) => e.model === "core.algorithm");
const lesson = data.find((e) => e.model === "core.lesson");
const steps = data.filter((e) => e.model === "core.step");

test("fixtures: algorithm pk=33, slug/family/status/order", () => {
  assert.equal(algo.pk, 33);
  assert.equal(algo.fields.slug, "gost-yescrypt");
  assert.equal(algo.fields.family, "hash");
  assert.equal(algo.fields.status, "live");
  assert.equal(algo.fields.order, 33);
  assert.ok(algo.fields.intro_template.length <= 200);
});

test("fixtures: lesson pk=33 with 6 steps, PKs 331-336", () => {
  assert.equal(lesson.pk, 33);
  assert.equal(lesson.fields.slug, "same-engine-russian-paperwork");
  assert.equal(steps.length, 6);
  assert.deepEqual(steps.map((s) => s.pk).sort(), [331, 332, 333, 334, 335, 336]);
});

test("fixtures: step slugs, kinds, validator keys", () => {
  const bySlug = Object.fromEntries(steps.map((s) => [s.fields.slug, s.fields]));
  assert.deepEqual(
    steps.sort((a, b) => a.fields.order - b.fields.order).map((s) => s.fields.slug),
    ["intro", "streebog", "the-wrapper", "spot-the-difference", "when-to-use", "done"]
  );
  assert.equal(bySlug["spot-the-difference"].kind, "choose-from-list");
  assert.equal(bySlug["spot-the-difference"].validator_key, "spot_difference");
  assert.equal(bySlug["done"].codegen_key, "done");
});
