import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

test("full_script imports HKDF and HKDFExpand from pyca/cryptography", () => {
  const out = c.full_script({});
  assert.match(out, /from cryptography\.hazmat\.primitives\.kdf\.hkdf import HKDF, HKDFExpand/);
  assert.match(out, /from cryptography\.hazmat\.primitives import hashes/);
});

test("full_script shows the single-shot HKDF(...).derive(IKM) path", () => {
  const out = c.full_script({});
  assert.match(out, /HKDF\(/);
  assert.match(out, /algorithm=hashes\.SHA256\(\)/);
  assert.match(out, /\.derive\(IKM\)/);
});

test("full_script shows the HKDFExpand(...) path with a manual Extract via hmac.new", () => {
  const out = c.full_script({});
  assert.match(out, /HKDFExpand\(/);
  assert.match(out, /hmac\.new\(SALT, IKM, hashlib\.sha256\)\.digest\(\)/);
});

test("full_script derives all four TLS-style keys with the right info strings", () => {
  const out = c.full_script({});
  assert.match(out, /b"client write key"/);
  assert.match(out, /b"server write key"/);
  assert.match(out, /b"client iv"/);
  assert.match(out, /b"server iv"/);
});

test("full_script uses the right lengths (16-byte keys, 12-byte IVs)", () => {
  const out = c.full_script({});
  // The HKDFExpand block uses an `expand(info, length)` helper, so lengths
  // appear as bare integers; the single-shot HKDF block has length=16.
  assert.match(out, /length=16/);
  assert.match(out, /b"client write key", 16/);
  assert.match(out, /b"server write key", 16/);
  assert.match(out, /b"client iv", 12/);
  assert.match(out, /b"server iv", 12/);
});

test("full_script warns against using HKDF for passwords", () => {
  const out = c.full_script({});
  // Cheap check: mentions PBKDF2 (or scrypt/argon2) and "password".
  assert.match(out, /[Pp]assword/);
  assert.match(out, /PBKDF2|scrypt|[Aa]rgon2/);
});

test("full_script falls back to defaults when state is empty", () => {
  const out = c.full_script({});
  assert.match(out, /"x25519-shared-secret-stand-in"/);
});

test("full_script tolerates missing state object", () => {
  const out = c.full_script();
  assert.match(out, /HKDF\(/);
  assert.match(out, /HKDFExpand\(/);
});

test("full_script drops captured PRK in as a comment when state has it", () => {
  const prk = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";
  const out = c.full_script({ hkdf_prk: prk });
  assert.ok(out.includes(prk));
  assert.match(out, /page captured PRK/);
});

test("full_script drops captured client_key in as a comment when state has it", () => {
  const ck = "deadbeef".repeat(4); // 16 bytes hex
  const out = c.full_script({ hkdf_client_key: ck });
  assert.ok(out.includes(ck));
});

test("full_script drops all four captured OKMs in as comments", () => {
  const r = {
    hkdf_client_key: "aa".repeat(16),
    hkdf_server_key: "bb".repeat(16),
    hkdf_client_iv:  "cc".repeat(12),
    hkdf_server_iv:  "dd".repeat(12),
  };
  const out = c.full_script(r);
  assert.ok(out.includes(r.hkdf_client_key));
  assert.ok(out.includes(r.hkdf_server_key));
  assert.ok(out.includes(r.hkdf_client_iv));
  assert.ok(out.includes(r.hkdf_server_iv));
});

test("full_script uses state.hkdf_seed_used when provided", () => {
  const out = c.full_script({ hkdf_seed_used: "my-custom-seed" });
  assert.match(out, /"my-custom-seed"/);
});

test("full_script escapes quotes safely inside string literals", () => {
  const out = c.full_script({ hkdf_seed_used: 'seed"with"quotes' });
  // JSON.stringify escapes embedded quotes.
  assert.match(out, /"seed\\"with\\"quotes"/);
});

// Per-step stubs all return empty string for the inline code panel.

test("intro returns empty string", () => {
  assert.equal(c.intro({}), "");
});

test("extract_step returns empty string", () => {
  assert.equal(c.extract_step({}), "");
});

test("expand_step returns empty string", () => {
  assert.equal(c.expand_step({}), "");
});

test("derive_keys returns empty string", () => {
  assert.equal(c.derive_keys({}), "");
});

test("vs_pbkdf2 returns empty string", () => {
  assert.equal(c.vs_pbkdf2({}), "");
});

test("done returns empty string", () => {
  assert.equal(c.done({}), "");
});
