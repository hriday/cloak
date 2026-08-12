import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

test("full_script uses argon2-cffi's PasswordHasher", () => {
  const out = c.full_script({});
  assert.match(out, /pip install argon2-cffi/);
  assert.match(out, /from argon2 import PasswordHasher/);
  assert.match(out, /check_needs_rehash/);
});

test("full_script converts the learner's MiB choice to KiB m_cost", () => {
  assert.match(c.full_script({ a2_memory_mib: 16 }), /memory_cost=16384/);
  assert.match(c.full_script({}), /memory_cost=65536/); // default 64 MiB
});

test("full_script embeds the learner's password, defaulting when absent", () => {
  assert.match(c.full_script({ a2_password: "hunter2" }), /"hunter2"/);
  assert.match(c.full_script({}), /correct-horse-battery-staple/);
});

test("full_script demonstrates verify failure on a wrong password", () => {
  assert.match(c.full_script({}), /VerifyMismatchError/);
});
