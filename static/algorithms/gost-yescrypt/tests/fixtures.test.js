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

test("fixtures: spot-the-difference hash pair invariant (salt/params identical, hashes differ)", () => {
  const bySlug = Object.fromEntries(steps.map((s) => [s.fields.slug, s.fields]));
  const prompt = bySlug["spot-the-difference"].prompt_template;

  // Pull the two crypt strings out of the fenced code block only, to avoid
  // matching the inline `$y$`/`$gy$` mentions in the surrounding prose.
  const codeBlock = prompt.match(/```\n([\s\S]*?)\n```/);
  assert.ok(codeBlock, "expected a fenced code block in the prompt");
  const lines = codeBlock[1].split("\n").filter((l) => l.trim().length > 0);
  assert.equal(lines.length, 2, "expected exactly two lines in the code block");

  const [yLine, gyLine] = lines;
  const yParts = yLine.split("$"); // ["", "y", "<params>", "<salt>", "<hash>"]
  const gyParts = gyLine.split("$"); // ["", "gy", "<params>", "<salt>", "<hash>"]
  assert.equal(yParts.length, 5);
  assert.equal(gyParts.length, 5);
  assert.equal(yParts[1], "y");
  assert.equal(gyParts[1], "gy");

  // Param field (e.g. "j9T") must be identical between the two lines.
  assert.equal(yParts[2], gyParts[2]);

  // Salt field must be identical between the two lines.
  assert.equal(yParts[3], gyParts[3]);

  // Hash fields must both be 43 chars, and must differ from each other.
  assert.equal(yParts[4].length, 43);
  assert.equal(gyParts[4].length, 43);
  assert.notEqual(yParts[4], gyParts[4]);
});
