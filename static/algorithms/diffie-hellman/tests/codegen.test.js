import { test } from "node:test";
import assert from "node:assert/strict";
import * as cg from "../codegen.js";

const STATE_DONE = {
  dh_alice_secret: 6,
  dh_bob_secret: 15,
  dh_shared: 2,
};

test("full_script imports the pyca DH module", () => {
  const s = cg.full_script(STATE_DONE);
  assert.match(s, /from cryptography\.hazmat\.primitives\.asymmetric import dh/);
});

test("full_script generates 2048-bit parameters with generator=2", () => {
  const s = cg.full_script(STATE_DONE);
  assert.match(s, /generate_parameters\(generator=2, key_size=2048\)/);
});

test("full_script calls .exchange() on both sides", () => {
  const s = cg.full_script(STATE_DONE);
  // Two exchange calls — Alice with Bob's pub, Bob with Alice's pub
  const matches = s.match(/\.exchange\(/g);
  assert.ok(matches && matches.length >= 2, "expected at least two .exchange( calls");
});

test("full_script asserts the two shared secrets match", () => {
  const s = cg.full_script(STATE_DONE);
  assert.match(s, /assert alice_shared == bob_shared/);
});

test("full_script references the toy lesson numbers (p=23, g=5)", () => {
  const s = cg.full_script(STATE_DONE);
  assert.match(s, /23/);
  assert.match(s, /g=5|g = 5/);
});

test("full_script comments the production g=2 vs lesson g=5 discrepancy", () => {
  const s = cg.full_script(STATE_DONE);
  // The comment must explicitly mention both g values
  assert.match(s, /g=2/);
  assert.match(s, /g=5/);
});

test("full_script includes the HKDF / KDF reminder", () => {
  const s = cg.full_script(STATE_DONE);
  assert.match(s, /HKDF|KDF/);
});

test("full_script includes RFC 3526 reference", () => {
  const s = cg.full_script(STATE_DONE);
  assert.match(s, /RFC 3526/);
});

test("full_script renders state values into the toy-numbers comment", () => {
  const s = cg.full_script({ dh_alice_secret: 6, dh_bob_secret: 15, dh_shared: 2 });
  // alice secret 6 and bob secret 15 should appear in the comment block
  assert.match(s, /a = 6/);
  assert.match(s, /b = 15/);
  assert.match(s, /shared s = .* = 2/);
});

test("full_script tolerates missing state (defaults to lesson values)", () => {
  const s = cg.full_script({});
  assert.match(s, /a = 6/);
  assert.match(s, /b = 15/);
});

test("full_script has no duplicate imports", () => {
  const s = cg.full_script(STATE_DONE);
  const imports = s.match(/^from cryptography\.hazmat\.primitives\.asymmetric import dh$/gm);
  assert.equal(imports.length, 1);
});

test("per-step codegen stubs return empty strings", () => {
  assert.equal(cg.info({}), "");
  assert.equal(cg.intro({}), "");
  assert.equal(cg.modular_exp({}), "");
  assert.equal(cg.the_handshake({}), "");
  assert.equal(cg.do_a_handshake({}), "");
  assert.equal(cg.discrete_log({}), "");
  assert.equal(cg.real_world_params({}), "");
  assert.equal(cg.done({}), "");
});
