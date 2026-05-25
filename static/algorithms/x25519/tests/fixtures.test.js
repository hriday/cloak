// Sanity-checks for algorithms/x25519/fixtures.json — assert the PK/slug
// allocations, intro_template length, step count, and the eight slugs the
// spec pinned.

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const FIXTURE = path.resolve(
  new URL(".", import.meta.url).pathname,
  "../../../../algorithms/x25519/fixtures.json"
);

const data = JSON.parse(fs.readFileSync(FIXTURE, "utf8"));
const algo    = data.find((d) => d.model === "core.algorithm");
const lesson  = data.find((d) => d.model === "core.lesson");
const steps   = data.filter((d) => d.model === "core.step");

test("fixture contains exactly 1 algorithm + 1 lesson + 8 steps", () => {
  assert.ok(algo, "expected one core.algorithm row");
  assert.ok(lesson, "expected one core.lesson row");
  assert.equal(steps.length, 8);
});

test("algorithm pk=10, slug 'x25519', name 'X25519', family 'asymmetric', live, order=10", () => {
  assert.equal(algo.pk, 10);
  assert.equal(algo.fields.slug, "x25519");
  assert.equal(algo.fields.name, "X25519");
  assert.equal(algo.fields.family, "asymmetric");
  assert.equal(algo.fields.status, "live");
  assert.equal(algo.fields.order, 10);
});

test("algorithm intro_template ≤ 200 chars (DB max_length)", () => {
  const len = algo.fields.intro_template.length;
  assert.ok(len <= 200, `intro_template is ${len} chars; must be ≤ 200`);
  assert.ok(len > 0, "intro_template should not be empty");
});

test("lesson pk=10, slug 'key-exchange-on-a-curve', algorithm=10, order=1", () => {
  assert.equal(lesson.pk, 10);
  assert.equal(lesson.fields.algorithm, 10);
  assert.equal(lesson.fields.slug, "key-exchange-on-a-curve");
  assert.equal(lesson.fields.order, 1);
  assert.match(lesson.fields.title, /X25519/);
});

test("step PKs are 101–108 in order", () => {
  const pks = steps.map((s) => s.pk).sort((a, b) => a - b);
  assert.deepEqual(pks, [101, 102, 103, 104, 105, 106, 107, 108]);
});

test("step slugs match the spec, in order", () => {
  const expected = [
    [101, 1, "intro",            "info"],
    [102, 2, "classical-dh",     "info"],
    [103, 3, "do-a-dh",          "input-numeric"],
    [104, 4, "why-curves",       "info"],
    [105, 5, "curve25519-spec",  "info"],
    [106, 6, "clamping",         "input-numeric"],
    [107, 7, "exchange-keys",    "input-text"],
    [108, 8, "done",             "info"],
  ];
  for (const [pk, order, slug, kind] of expected) {
    const s = steps.find((x) => x.pk === pk);
    assert.ok(s, `missing step pk=${pk}`);
    assert.equal(s.fields.lesson, 10);
    assert.equal(s.fields.order, order, `step pk=${pk} order`);
    assert.equal(s.fields.slug, slug, `step pk=${pk} slug`);
    assert.equal(s.fields.kind, kind, `step pk=${pk} kind`);
  }
});

test("validator_keys are wired correctly", () => {
  const byPk = Object.fromEntries(steps.map((s) => [s.pk, s.fields]));
  assert.equal(byPk[103].validator_key, "compute_dh");
  assert.equal(byPk[106].validator_key, "clamp_byte");
  assert.equal(byPk[107].validator_key, "exchange_keys");
  for (const pk of [101, 102, 104, 105, 108]) {
    assert.equal(byPk[pk].validator_key, "info", `step ${pk} validator`);
  }
});

test("each step has a prompt_template that mentions something substantive", () => {
  for (const s of steps) {
    assert.ok(s.fields.prompt_template, `step pk=${s.pk} has empty prompt`);
    assert.ok(
      s.fields.prompt_template.length > 50,
      `step pk=${s.pk} prompt too short`
    );
  }
});
