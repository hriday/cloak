import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

// cbc_walk — sentinel validator

test("cbc_walk accepts the 'run' sentinel", () => {
  const r = v.cbc_walk("run", {});
  assert.equal(r.ok, true);
});

test("cbc_walk accepts any non-empty string", () => {
  assert.equal(v.cbc_walk("anything", {}).ok, true);
});

test("cbc_walk rejects empty", () => {
  const r = v.cbc_walk("", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /Encrypt/);
});

test("cbc_walk rejects null", () => {
  const r = v.cbc_walk(null, {});
  assert.equal(r.ok, false);
});

// pick_a_mode — happy path

test("pick_a_mode happy: GCM/CBC/CTR", () => {
  const r = v.pick_a_mode({ s1: "GCM", s2: "CBC", s3: "CTR" }, {});
  assert.equal(r.ok, true);
  assert.deepEqual(r.value, {
    mode_scenario_1: "GCM",
    mode_scenario_2: "CBC",
    mode_scenario_3: "CTR",
  });
});

test("pick_a_mode also accepts GCM for s2 (anything-but-ECB)", () => {
  const r = v.pick_a_mode({ s1: "GCM", s2: "GCM", s3: "CTR" }, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.mode_scenario_2, "GCM");
});

test("pick_a_mode normalizes case and whitespace", () => {
  const r = v.pick_a_mode({ s1: " gcm ", s2: "cbc", s3: "Ctr" }, {});
  assert.equal(r.ok, true);
});

// pick_a_mode — per-scenario rejection messages

test("pick_a_mode rejects s1 = CBC with integrity hint", () => {
  const r = v.pick_a_mode({ s1: "CBC", s2: "CBC", s3: "CTR" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /integrity|authentication/i);
});

test("pick_a_mode rejects s1 = CTR with integrity hint", () => {
  const r = v.pick_a_mode({ s1: "CTR", s2: "CBC", s3: "CTR" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /integrity|authentication/i);
});

test("pick_a_mode rejects s1 = ECB with integrity hint", () => {
  const r = v.pick_a_mode({ s1: "ECB", s2: "CBC", s3: "CTR" }, {});
  assert.equal(r.ok, false);
});

test("pick_a_mode rejects s2 = ECB with identical-blocks hint", () => {
  const r = v.pick_a_mode({ s1: "GCM", s2: "ECB", s3: "CTR" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /identical/i);
});

test("pick_a_mode rejects s2 = CTR with idiom hint", () => {
  const r = v.pick_a_mode({ s1: "GCM", s2: "CTR", s3: "CTR" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /idiomatic|streaming|database/i);
});

test("pick_a_mode rejects s3 = CBC with random-access hint", () => {
  const r = v.pick_a_mode({ s1: "GCM", s2: "CBC", s3: "CBC" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /random access|counter/i);
});

test("pick_a_mode rejects s3 = GCM with overkill hint", () => {
  const r = v.pick_a_mode({ s1: "GCM", s2: "CBC", s3: "GCM" }, {});
  assert.equal(r.ok, false);
});

test("pick_a_mode rejects s3 = ECB", () => {
  const r = v.pick_a_mode({ s1: "GCM", s2: "CBC", s3: "ECB" }, {});
  assert.equal(r.ok, false);
});

// pick_a_mode — missing / malformed inputs

test("pick_a_mode rejects missing s1", () => {
  const r = v.pick_a_mode({ s2: "CBC", s3: "CTR" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /each scenario/i);
});

test("pick_a_mode rejects missing s2", () => {
  const r = v.pick_a_mode({ s1: "GCM", s3: "CTR" }, {});
  assert.equal(r.ok, false);
});

test("pick_a_mode rejects missing s3", () => {
  const r = v.pick_a_mode({ s1: "GCM", s2: "CBC" }, {});
  assert.equal(r.ok, false);
});

test("pick_a_mode rejects empty strings", () => {
  const r = v.pick_a_mode({ s1: "", s2: "", s3: "" }, {});
  assert.equal(r.ok, false);
});

test("pick_a_mode rejects unknown mode label", () => {
  const r = v.pick_a_mode({ s1: "AES", s2: "CBC", s3: "CTR" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /Unknown/i);
});

// info / walkthroughs

test("info always ok", () => {
  assert.deepEqual(v.info("anything", {}), { ok: true, value: {} });
});

test("walkthroughs is an object", () => {
  assert.equal(typeof v.walkthroughs, "object");
});
