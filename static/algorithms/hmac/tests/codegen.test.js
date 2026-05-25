import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

test("full_script imports hmac and hashlib", () => {
  const out = c.full_script({});
  assert.match(out, /import hmac/);
  assert.match(out, /import hashlib/);
});

test("full_script calls hmac.new with hashlib.sha256", () => {
  const out = c.full_script({});
  assert.match(out, /hmac\.new\(/);
  assert.match(out, /hashlib\.sha256/);
});

test("full_script uses hmac.compare_digest, not ==", () => {
  const out = c.full_script({});
  assert.match(out, /hmac\.compare_digest/);
});

test("full_script includes a verify-OK assertion", () => {
  const out = c.full_script({});
  assert.match(out, /assert hmac\.compare_digest\(mac, expected\)/);
});

test("full_script includes a tamper-fails assertion", () => {
  const out = c.full_script({});
  assert.match(out, /assert not hmac\.compare_digest\(mac, tampered_mac\)/);
});

test("full_script uses state.hm_key when provided", () => {
  const out = c.full_script({ hm_key: "my-secret", hm_message: "x" });
  assert.match(out, /"my-secret"/);
});

test("full_script uses state.hm_message when provided", () => {
  const out = c.full_script({ hm_key: "k", hm_message: "custom test message" });
  assert.match(out, /"custom test message"/);
});

test("full_script falls back to defaults when state is empty", () => {
  const out = c.full_script({});
  assert.match(out, /"shared-secret"/);
  assert.match(out, /"transfer=100&to=alice"/);
});

test("full_script tolerates missing state object", () => {
  const out = c.full_script();
  assert.match(out, /import hmac/);
  assert.match(out, /hmac\.new\(/);
});

test("full_script escapes quotes safely inside string literals", () => {
  const out = c.full_script({ hm_key: 'k"ey', hm_message: "msg" });
  // JSON.stringify escapes the embedded quote.
  assert.match(out, /"k\\"ey"/);
});

test("intro returns empty string", () => {
  assert.equal(c.intro({}), "");
});

test("naive_mac returns empty string", () => {
  assert.equal(c.naive_mac({}), "");
});

test("length_extension returns empty string", () => {
  assert.equal(c.length_extension({}), "");
});

test("hmac_construction returns empty string", () => {
  assert.equal(c.hmac_construction({}), "");
});

test("compute_hmac returns empty string", () => {
  assert.equal(c.compute_hmac({}), "");
});

test("verify_and_tamper returns empty string", () => {
  assert.equal(c.verify_and_tamper({}), "");
});

test("done returns empty string", () => {
  assert.equal(c.done({}), "");
});
