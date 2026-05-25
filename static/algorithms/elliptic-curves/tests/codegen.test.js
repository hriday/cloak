import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

// ---- full_script: Part 1 (toy curve from scratch) ----

test("full_script defines A=1, B=6, P=11, G=(2,7) — same as the ECDSA lesson", () => {
  const out = c.full_script({});
  assert.match(out, /A, B, P = 1, 6, 11/);
  assert.match(out, /G = \(2, 7\)/);
});

test("full_script defines point_add, point_double, scalar_mul, and modinv", () => {
  const out = c.full_script({});
  assert.match(out, /def point_add\(p1, p2\):/);
  assert.match(out, /def point_double\(p\):/);
  assert.match(out, /def scalar_mul\(k, p\):/);
  assert.match(out, /def modinv\(a, m\):/);
});

test("full_script's slope formulas match the textbook", () => {
  const out = c.full_script({});
  // P + Q distinct: s = (y2 - y1) / (x2 - x1)
  assert.match(out, /s = \(y2 - y1\) \* modinv\(x2 - x1, P\) % P/);
  // Tangent at P: s = (3x² + a) / (2y)
  assert.match(out, /s = \(3\*x\*x \+ A\) \* modinv\(2\*y, P\) % P/);
});

test("full_script walks the full 13-element orbit in the worked example", () => {
  const out = c.full_script({});
  assert.match(out, /for k in range\(1, 14\):/);
});

test("full_script handles a missing state object", () => {
  const out = c.full_script();
  assert.match(out, /def point_add/);
  assert.match(out, /def scalar_mul/);
});

// ---- full_script: Part 2 (real curve via pyca) ----

test("full_script imports cryptography.hazmat and uses SECP256R1", () => {
  const out = c.full_script({});
  assert.match(out, /from cryptography\.hazmat\.primitives\.asymmetric import ec/);
  assert.match(out, /ec\.generate_private_key\(ec\.SECP256R1\(\)\)/);
});

test("full_script mentions secp256k1 + the other NIST curves in comments", () => {
  const out = c.full_script({});
  for (const name of ["SECP256R1", "SECP384R1", "SECP521R1", "SECP256K1"]) {
    assert.match(out, new RegExp(name));
  }
});

test("full_script forward-links to ECDH / Ed25519 / ECDSA / Schnorr", () => {
  const out = c.full_script({});
  assert.match(out, /ECDH/);
  assert.match(out, /Ed25519/);
  assert.match(out, /ECDSA/);
  assert.match(out, /Schnorr/);
});

// ---- captured-state comments ----

test("full_script embeds state.ec_scalar_k + ec_scalar_kp as comments when present", () => {
  const out = c.full_script({
    ec_scalar_k: 5,
    ec_scalar_kp: { x: -1.234, y: 0.567 },
  });
  assert.match(out, /you computed 5·P/);
  assert.match(out, /-1\.234/);
  assert.match(out, /0\.567/);
});

test("full_script omits captured-value comments when state is empty", () => {
  const out = c.full_script({});
  assert.doesNotMatch(out, /you computed/);
});

// ---- per-step stubs ----

test("per-step stubs all return empty string", () => {
  for (const slug of [
    "intro", "the_curve", "point_addition", "point_doubling",
    "scalar_multiplication", "finite_field_curve", "discrete_log_problem",
    "done", "info",
  ]) {
    assert.equal(typeof c[slug], "function", `${slug} should be exported`);
    assert.equal(c[slug]({}), "", `${slug} should return ""`);
  }
});
