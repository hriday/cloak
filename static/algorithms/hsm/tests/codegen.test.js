import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

test("full_script imports boto3", () => {
  const out = c.full_script({});
  assert.match(out, /import boto3/);
});

test("full_script creates a KMS client", () => {
  const out = c.full_script({});
  assert.match(out, /kms = boto3\.client\("kms"/);
});

test("full_script calls kms.encrypt", () => {
  const out = c.full_script({});
  assert.match(out, /kms\.encrypt\(/);
});

test("full_script calls kms.decrypt", () => {
  const out = c.full_script({});
  assert.match(out, /kms\.decrypt\(/);
});

test("full_script defines a KEY_ID constant with a placeholder ARN", () => {
  const out = c.full_script({});
  assert.match(out, /KEY_ID =/);
  assert.match(out, /arn:aws:kms:/);
});

test("full_script asserts the decrypted plaintext matches the original", () => {
  const out = c.full_script({});
  assert.match(out, /assert decrypted == PLAINTEXT/);
});

test("full_script uses state.hsm_message when provided", () => {
  const out = c.full_script({ hsm_message: "custom test message" });
  assert.match(out, /"custom test message"/);
});

test("full_script falls back to a default message when state is empty", () => {
  const out = c.full_script({});
  assert.match(out, /hello from the application/);
});

test("full_script tolerates a missing/undefined state object", () => {
  const out = c.full_script();
  assert.match(out, /import boto3/);
  assert.match(out, /hello from the application/);
});

test("intro returns empty string", () => {
  assert.equal(c.intro({}), "");
});

test("the_vault_analogy returns empty string", () => {
  assert.equal(c.the_vault_analogy({}), "");
});

test("operations_api returns empty string", () => {
  assert.equal(c.operations_api({}), "");
});

test("simulated_hsm returns empty string", () => {
  assert.equal(c.simulated_hsm({}), "");
});

test("kek_hierarchy returns empty string", () => {
  assert.equal(c.kek_hierarchy({}), "");
});

test("real_world_kms returns empty string", () => {
  assert.equal(c.real_world_kms({}), "");
});

test("where_required returns empty string", () => {
  assert.equal(c.where_required({}), "");
});

test("done returns empty string", () => {
  assert.equal(c.done({}), "");
});
