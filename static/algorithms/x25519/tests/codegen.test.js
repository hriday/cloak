import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

test("full_script imports X25519PrivateKey from cryptography.hazmat", () => {
  const out = c.full_script({});
  assert.match(
    out,
    /from cryptography\.hazmat\.primitives\.asymmetric\.x25519 import X25519PrivateKey/
  );
});

test("full_script imports serialization", () => {
  const out = c.full_script({});
  assert.match(out, /from cryptography\.hazmat\.primitives import serialization/);
});

test("full_script uses X25519PrivateKey.generate() for both sides", () => {
  const out = c.full_script({});
  // Twice — once for Alice, once for Bob.
  const matches = out.match(/X25519PrivateKey\.generate\(\)/g) || [];
  assert.equal(matches.length, 2);
});

test("full_script exports raw public bytes via Encoding.Raw + PublicFormat.Raw", () => {
  const out = c.full_script({});
  assert.match(out, /serialization\.Encoding\.Raw/);
  assert.match(out, /serialization\.PublicFormat\.Raw/);
});

test("full_script calls .exchange() on both sides", () => {
  const out = c.full_script({});
  const matches = out.match(/\.exchange\(/g) || [];
  assert.equal(matches.length, 2);
});

test("full_script asserts shared_a == shared_b", () => {
  const out = c.full_script({});
  assert.match(out, /assert shared_a == shared_b/);
});

test("full_script prints the two public keys and the shared secret", () => {
  const out = c.full_script({});
  assert.match(out, /print\("Alice pub/);
  assert.match(out, /print\("Bob pub/);
  assert.match(out, /print\("shared/);
});

test("full_script tolerates a missing state object", () => {
  const out = c.full_script();
  assert.match(out, /X25519PrivateKey/);
  assert.match(out, /assert shared_a == shared_b/);
});

test("full_script embeds state.x25_alice_pub as a comment when present", () => {
  const out = c.full_script({
    x25_alice_pub: "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    x25_bob_pub:   "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
    x25_shared_secret: "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
  });
  assert.match(out, /# page captured Alice pub: 8520f0098930/);
  assert.match(out, /# page captured Bob pub: de9edb7d7b7d/);
  assert.match(out, /# page captured shared: 4a5d9d5ba4ce/);
});

test("full_script omits captured-value comments when state is empty", () => {
  const out = c.full_script({});
  assert.doesNotMatch(out, /# page captured/);
});

test("per-step stubs all return empty string", () => {
  for (const slug of [
    "intro",
    "classical_dh",
    "do_a_dh",
    "why_curves",
    "curve25519_spec",
    "clamping",
    "exchange_keys",
    "done",
  ]) {
    assert.equal(typeof c[slug], "function", `${slug} should be exported`);
    assert.equal(c[slug]({}), "", `${slug} should return ""`);
  }
});
