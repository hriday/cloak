import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

const HAS_SUBTLE = typeof crypto !== "undefined" && !!crypto.subtle;

// ---- pbkdf2_compute ----

test("pbkdf2_compute rejects empty password", async () => {
  const r = await v.pbkdf2_compute({ password: "", iterations: 1000 }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /password/i);
});

test("pbkdf2_compute rejects null password", async () => {
  const r = await v.pbkdf2_compute({ password: null, iterations: 1000 }, {});
  assert.equal(r.ok, false);
});

test("pbkdf2_compute rejects oversized password (>200 chars)", async () => {
  const big = "a".repeat(201);
  const r = await v.pbkdf2_compute({ password: big, iterations: 1000 }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /200/);
});

test("pbkdf2_compute accepts exactly 200 chars", async (t) => {
  if (!HAS_SUBTLE) return t.skip("crypto.subtle not available");
  const r = await v.pbkdf2_compute(
    { password: "a".repeat(200), iterations: 1000 },
    {}
  );
  assert.equal(r.ok, true);
});

test("pbkdf2_compute rejects non-ASCII (emoji)", async () => {
  const r = await v.pbkdf2_compute(
    { password: "péssword", iterations: 1000 },
    {}
  );
  assert.equal(r.ok, false);
  assert.match(r.hint, /ASCII/i);
});

test("pbkdf2_compute rejects newlines", async () => {
  const r = await v.pbkdf2_compute(
    { password: "line\nbreak", iterations: 1000 },
    {}
  );
  assert.equal(r.ok, false);
});

test("pbkdf2_compute rejects iteration count not in dropdown", async () => {
  const r = await v.pbkdf2_compute({ password: "hunter2", iterations: 42 }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /dropdown/i);
});

test("pbkdf2_compute rejects missing iterations", async () => {
  const r = await v.pbkdf2_compute({ password: "hunter2" }, {});
  assert.equal(r.ok, false);
});

for (const iter of [1000, 10000, 100000, 1000000]) {
  test(`pbkdf2_compute accepts iterations=${iter}`, async (t) => {
    if (!HAS_SUBTLE) return t.skip("crypto.subtle not available");
    const r = await v.pbkdf2_compute({ password: "p", iterations: iter }, {});
    assert.equal(r.ok, true, r.hint);
    assert.equal(r.value.pw_pbkdf2_iter, iter);
  });
}

test("pbkdf2_compute happy path writes the 5 expected keys", async (t) => {
  if (!HAS_SUBTLE) return t.skip("crypto.subtle not available");
  const r = await v.pbkdf2_compute(
    { password: "hunter2", iterations: 1000 },
    {}
  );
  assert.equal(r.ok, true);
  assert.equal(r.value.pw_pbkdf2_password, "hunter2");
  assert.equal(r.value.pw_pbkdf2_iter, 1000);
  assert.equal(typeof r.value.pw_pbkdf2_hex, "string");
  assert.equal(r.value.pw_pbkdf2_hex.length, 64);
  assert.match(r.value.pw_pbkdf2_hex, /^[0-9a-f]{64}$/);
  assert.equal(typeof r.value.pw_pbkdf2_salt, "string");
  assert.equal(r.value.pw_pbkdf2_salt.length, 32);
  assert.match(r.value.pw_pbkdf2_salt, /^[0-9a-f]{32}$/);
  assert.equal(typeof r.value.pw_pbkdf2_ms, "number");
});

test("pbkdf2_compute no-crypto fallback returns ok with null hex", async () => {
  const original = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  Object.defineProperty(globalThis, "crypto", {
    value: { getRandomValues: () => new Uint8Array(16) }, // no .subtle
    configurable: true,
    writable: true,
  });
  try {
    const r = await v.pbkdf2_compute(
      { password: "p", iterations: 1000 },
      {}
    );
    assert.equal(r.ok, true);
    assert.equal(r.value.pw_pbkdf2_password, "p");
    assert.equal(r.value.pw_pbkdf2_iter, 1000);
    assert.equal(r.value.pw_pbkdf2_hex, null);
    assert.equal(r.value.pw_pbkdf2_salt, null);
    assert.equal(r.value.pw_pbkdf2_ms, null);
  } finally {
    if (original) {
      Object.defineProperty(globalThis, "crypto", original);
    } else {
      delete globalThis.crypto;
    }
  }
});

// ---- compare_all ----

test("compare_all happy path writes pw_compare_results with 5 rows", async (t) => {
  if (!HAS_SUBTLE) return t.skip("crypto.subtle not available");
  const r = await v.compare_all({ password: "hello" }, {});
  assert.equal(r.ok, true);
  assert.ok(Array.isArray(r.value.pw_compare_results));
  assert.equal(r.value.pw_compare_results.length, 5);
  for (const row of r.value.pw_compare_results) {
    assert.equal(typeof row.algo, "string");
    assert.equal(typeof row.hex, "string");
    assert.equal(typeof row.ms, "number");
    assert.equal(typeof row.cited, "boolean");
  }
});

test("compare_all uses a default password when none is supplied", async (t) => {
  if (!HAS_SUBTLE) return t.skip("crypto.subtle not available");
  const r = await v.compare_all({}, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.pw_compare_results.length, 5);
});

test("compare_all rejects a non-ASCII password", async () => {
  const r = await v.compare_all({ password: "pé" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /ASCII/i);
});

test("compare_all no-crypto fallback returns empty list", async () => {
  const original = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  Object.defineProperty(globalThis, "crypto", {
    value: { getRandomValues: () => new Uint8Array(16) }, // no .subtle
    configurable: true,
    writable: true,
  });
  try {
    const r = await v.compare_all({ password: "p" }, {});
    assert.equal(r.ok, true);
    assert.deepEqual(r.value.pw_compare_results, []);
  } finally {
    if (original) {
      Object.defineProperty(globalThis, "crypto", original);
    } else {
      delete globalThis.crypto;
    }
  }
});

// ---- info ----

test("info always ok", () => {
  assert.deepEqual(v.info("anything", {}), { ok: true, value: {} });
  assert.deepEqual(v.info(null, {}), { ok: true, value: {} });
});

// ---- walkthroughs ----

test("walkthroughs.pbkdf2_compute returns 3 non-empty rungs", () => {
  assert.equal(typeof v.walkthroughs.pbkdf2_compute, "function");
  const rungs = v.walkthroughs.pbkdf2_compute({});
  assert.equal(rungs.length, 3);
  rungs.forEach((r) => {
    assert.equal(typeof r, "string");
    assert.ok(r.length > 0);
  });
});

test("walkthroughs.pbkdf2_compute mentions salt and iteration count", () => {
  const joined = v.walkthroughs.pbkdf2_compute({}).join(" ");
  assert.match(joined, /salt/i);
  assert.match(joined, /iter/i);
});

test("walkthroughs.compare_all returns 3 rungs", () => {
  const rungs = v.walkthroughs.compare_all({});
  assert.equal(rungs.length, 3);
  rungs.forEach((r) => assert.ok(r.length > 0));
});

test("walkthroughs.compare_all calls out the log scale", () => {
  const joined = v.walkthroughs.compare_all({}).join(" ");
  assert.match(joined, /log/i);
});
