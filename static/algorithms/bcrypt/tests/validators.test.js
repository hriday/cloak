import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

const HAS_SUBTLE = typeof crypto !== "undefined" && !!crypto.subtle;

// ---- time_cost: input validation ----

test("time_cost rejects empty password", async () => {
  const r = await v.time_cost({ password: "", cost: 4 }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /password/i);
});

test("time_cost rejects null password", async () => {
  const r = await v.time_cost({ password: null, cost: 4 }, {});
  assert.equal(r.ok, false);
});

test("time_cost rejects missing password", async () => {
  const r = await v.time_cost({ cost: 4 }, {});
  assert.equal(r.ok, false);
});

test("time_cost rejects oversized password (>200 chars)", async () => {
  const big = "a".repeat(201);
  const r = await v.time_cost({ password: big, cost: 4 }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /200/);
});

test("time_cost rejects non-ASCII password (accented letter)", async () => {
  const r = await v.time_cost({ password: "péssword", cost: 4 }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /ASCII/i);
});

test("time_cost rejects newlines in password", async () => {
  const r = await v.time_cost({ password: "line\nbreak", cost: 4 }, {});
  assert.equal(r.ok, false);
});

// ---- time_cost: cost validation ----

test("time_cost rejects cost not in the dropdown set", async () => {
  // The dropdown is [4, 8, 10, 12, 14] — anything else is wrong even if
  // it's within bcrypt's broader 4-31 range.
  const r = await v.time_cost({ password: "p", cost: 5 }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /dropdown/i);
});

test("time_cost rejects cost below MIN", async () => {
  const r = await v.time_cost({ password: "p", cost: 3 }, {});
  assert.equal(r.ok, false);
});

test("time_cost rejects cost above the demo cap", async () => {
  const r = await v.time_cost({ password: "p", cost: 16 }, {});
  assert.equal(r.ok, false);
});

test("time_cost rejects non-integer cost", async () => {
  const r = await v.time_cost({ password: "p", cost: 4.5 }, {});
  assert.equal(r.ok, false);
});

test("time_cost rejects missing cost", async () => {
  const r = await v.time_cost({ password: "p" }, {});
  assert.equal(r.ok, false);
});

test("time_cost rejects string cost", async () => {
  const r = await v.time_cost({ password: "p", cost: "four" }, {});
  assert.equal(r.ok, false);
});

// ---- time_cost: happy path ----

for (const cost of [4, 8, 10, 12, 14]) {
  test(`time_cost accepts cost=${cost} from the dropdown`, async (t) => {
    if (!HAS_SUBTLE) return t.skip("crypto.subtle not available");
    const r = await v.time_cost({ password: "p", cost }, {});
    assert.equal(r.ok, true, r.hint);
    assert.equal(r.value.bcrypt_cost, cost);
  });
}

test("time_cost happy path writes all expected bcrypt_* state keys", async (t) => {
  if (!HAS_SUBTLE) return t.skip("crypto.subtle not available");
  const r = await v.time_cost(
    { password: "hunter2", cost: 4 },
    {}
  );
  assert.equal(r.ok, true);
  // The full bcrypt_* state contract.
  assert.equal(r.value.bcrypt_password, "hunter2");
  assert.equal(r.value.bcrypt_cost, 4);
  assert.equal(typeof r.value.bcrypt_hash, "string");
  assert.equal(r.value.bcrypt_hash.length, 64);
  assert.match(r.value.bcrypt_hash, /^[0-9a-f]{64}$/);
  assert.equal(typeof r.value.bcrypt_hash_ms, "number");
  assert.ok(r.value.bcrypt_hash_ms >= 0);
  assert.equal(r.value.bcrypt_iterations, 16000);
  assert.equal(r.value.bcrypt_cited_real_ms, 1);
});

test("time_cost cost=12 writes the cited 260 ms reference value", async (t) => {
  if (!HAS_SUBTLE) return t.skip("crypto.subtle not available");
  const r = await v.time_cost({ password: "p", cost: 12 }, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.bcrypt_cited_real_ms, 260);
  assert.equal(r.value.bcrypt_iterations, 4096000);
});

test("time_cost no-crypto fallback returns ok with null hash fields", async () => {
  const original = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  Object.defineProperty(globalThis, "crypto", {
    value: { getRandomValues: () => new Uint8Array(16) }, // no .subtle
    configurable: true,
    writable: true,
  });
  try {
    const r = await v.time_cost({ password: "p", cost: 4 }, {});
    assert.equal(r.ok, true);
    assert.equal(r.value.bcrypt_password, "p");
    assert.equal(r.value.bcrypt_cost, 4);
    assert.equal(r.value.bcrypt_hash, null);
    assert.equal(r.value.bcrypt_hash_ms, null);
    assert.equal(r.value.bcrypt_iterations, null);
    // Cited ms is a constant lookup — not gated on crypto.
    assert.equal(r.value.bcrypt_cited_real_ms, 1);
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

test("walkthroughs.time_cost returns 3 non-empty rungs", () => {
  assert.equal(typeof v.walkthroughs.time_cost, "function");
  const rungs = v.walkthroughs.time_cost({});
  assert.equal(rungs.length, 3);
  rungs.forEach((r) => {
    assert.equal(typeof r, "string");
    assert.ok(r.length > 0);
  });
});

test("walkthroughs.time_cost cross-references the Blowfish lesson", () => {
  const joined = v.walkthroughs.time_cost({}).join(" ");
  assert.match(joined, /blowfish/i);
});

test("walkthroughs.time_cost mentions the exponential cost factor", () => {
  const joined = v.walkthroughs.time_cost({}).join(" ");
  assert.match(joined, /cost/i);
  assert.match(joined, /doubl/i);
});
