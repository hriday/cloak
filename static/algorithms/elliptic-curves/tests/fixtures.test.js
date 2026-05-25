// Sanity-checks for algorithms/elliptic-curves/fixtures.json — assert the
// PK / slug allocations, intro_template length, step count, and the 8
// slugs the brief pinned.

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const FIXTURE = path.resolve(
  new URL(".", import.meta.url).pathname,
  "../../../../algorithms/elliptic-curves/fixtures.json"
);

const data    = JSON.parse(fs.readFileSync(FIXTURE, "utf8"));
const algo    = data.find((d) => d.model === "core.algorithm");
const lesson  = data.find((d) => d.model === "core.lesson");
const steps   = data.filter((d) => d.model === "core.step");

test("fixture contains exactly 1 algorithm + 1 lesson + 8 steps", () => {
  assert.ok(algo, "expected one core.algorithm row");
  assert.ok(lesson, "expected one core.lesson row");
  assert.equal(steps.length, 8);
});

test("algorithm pk=24, slug 'elliptic-curves', name 'Elliptic curves', family 'asymmetric', live, order=9", () => {
  assert.equal(algo.pk, 24);
  assert.equal(algo.fields.slug, "elliptic-curves");
  assert.equal(algo.fields.name, "Elliptic curves");
  assert.equal(algo.fields.family, "asymmetric");
  assert.equal(algo.fields.status, "live");
  assert.equal(algo.fields.order, 9);
});

test("algorithm intro_template ≤ 200 chars (DB max_length)", () => {
  const len = algo.fields.intro_template.length;
  assert.ok(len <= 200, `intro_template is ${len} chars; must be ≤ 200`);
  assert.ok(len > 0, "intro_template should not be empty");
});

test("lesson pk=24, slug 'curves-visually', algorithm=24, title mentions elliptic curves", () => {
  assert.equal(lesson.pk, 24);
  assert.equal(lesson.fields.algorithm, 24);
  assert.equal(lesson.fields.slug, "curves-visually");
  assert.equal(lesson.fields.order, 1);
  assert.match(lesson.fields.title, /[Ee]lliptic curves/);
});

test("step PKs are 241–248 in order", () => {
  const pks = steps.map((s) => s.pk).sort((a, b) => a - b);
  assert.deepEqual(pks, [241, 242, 243, 244, 245, 246, 247, 248]);
});

test("step slugs and kinds match the spec, in order", () => {
  const expected = [
    [241, 1, "intro",                  "info"],
    [242, 2, "the-curve",              "info"],
    [243, 3, "point-addition",         "input-text"],
    [244, 4, "point-doubling",         "input-text"],
    [245, 5, "scalar-multiplication",  "input-numeric"],
    [246, 6, "finite-field-curve",     "info"],
    [247, 7, "discrete-log-problem",   "info"],
    [248, 8, "done",                   "info"],
  ];
  for (const [pk, order, slug, kind] of expected) {
    const s = steps.find((x) => x.pk === pk);
    assert.ok(s, `missing step pk=${pk}`);
    assert.equal(s.fields.lesson, 24);
    assert.equal(s.fields.order, order, `step pk=${pk} order`);
    assert.equal(s.fields.slug, slug, `step pk=${pk} slug`);
    assert.equal(s.fields.kind, kind, `step pk=${pk} kind`);
  }
});

test("validator_keys are wired correctly", () => {
  const byPk = Object.fromEntries(steps.map((s) => [s.pk, s.fields]));
  assert.equal(byPk[243].validator_key, "point_addition");
  assert.equal(byPk[244].validator_key, "point_doubling");
  assert.equal(byPk[245].validator_key, "scalar_multiplication");
  for (const pk of [241, 242, 246, 247, 248]) {
    assert.equal(byPk[pk].validator_key, "info", `step ${pk} validator`);
  }
});

test("codegen_keys are wired: actionable steps use slug; done uses full_script; info uses info", () => {
  const byPk = Object.fromEntries(steps.map((s) => [s.pk, s.fields]));
  assert.equal(byPk[241].codegen_key, "info");
  assert.equal(byPk[242].codegen_key, "the_curve");
  assert.equal(byPk[243].codegen_key, "point_addition");
  assert.equal(byPk[244].codegen_key, "point_doubling");
  assert.equal(byPk[245].codegen_key, "scalar_multiplication");
  assert.equal(byPk[246].codegen_key, "finite_field_curve");
  assert.equal(byPk[247].codegen_key, "discrete_log_problem");
  assert.equal(byPk[248].codegen_key, "full_script");
});

test("every step has a substantive prompt_template", () => {
  for (const s of steps) {
    assert.ok(s.fields.prompt_template, `step pk=${s.pk} has empty prompt`);
    assert.ok(
      s.fields.prompt_template.length > 100,
      `step pk=${s.pk} prompt too short (${s.fields.prompt_template.length} chars)`
    );
  }
});

test("intro step forward-links to X25519, Ed25519, and ECDSA", () => {
  const intro = steps.find((s) => s.pk === 241);
  assert.match(intro.fields.prompt_template, /X25519/);
  assert.match(intro.fields.prompt_template, /Ed25519/);
  assert.match(intro.fields.prompt_template, /ECDSA/);
});

test("done step forward-links to X25519, Ed25519, ECDSA, Schnorr", () => {
  const done = steps.find((s) => s.pk === 248);
  for (const link of ["X25519", "Ed25519", "ECDSA", "Schnorr"]) {
    assert.match(done.fields.prompt_template, new RegExp(link),
      `done step missing ${link} forward-link`);
  }
});
