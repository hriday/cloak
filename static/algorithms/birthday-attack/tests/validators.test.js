import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

// ---------- info ----------

test("info always ok", () => {
  assert.deepEqual(v.info("anything", {}), { ok: true, value: {} });
  assert.deepEqual(v.info(null, {}), { ok: true, value: {} });
});

// ---------- find_collision ----------

test("find_collision happy: ok=true, writes the expected state keys", async () => {
  const r = await v.find_collision(null, {});
  assert.equal(r.ok, true);
  const val = r.value;
  assert.equal(typeof val.bday_collision_a, "string");
  assert.equal(typeof val.bday_collision_b, "string");
  assert.match(val.bday_collision_hash, /^[0-9a-f]{4}$/);
  assert.equal(typeof val.bday_attempts, "number");
  assert.equal(val.bday_hash_bits, 16);
});

test("find_collision: the two inputs are distinct strings", async () => {
  const r = await v.find_collision(null, {});
  assert.equal(r.ok, true);
  assert.notEqual(r.value.bday_collision_a, r.value.bday_collision_b);
});

test("find_collision: attempts is positive and birthday-bounded", async () => {
  const r = await v.find_collision(null, {});
  assert.equal(r.ok, true);
  assert.ok(r.value.bday_attempts > 0);
  // 16-bit expected ~302; allow a generous ceiling.
  assert.ok(
    r.value.bday_attempts < 5000,
    `expected birthday-bounded attempts, got ${r.value.bday_attempts}`
  );
});

test("find_collision writes all state keys the lesson spec requires", async () => {
  const r = await v.find_collision(null, {});
  const expectedKeys = [
    "bday_collision_a",
    "bday_collision_b",
    "bday_collision_hash",
    "bday_attempts",
    "bday_hash_bits",
  ];
  for (const k of expectedKeys) {
    assert.ok(k in r.value, `state key missing: ${k}`);
  }
});

// ---------- walkthroughs ----------

test("walkthroughs has 3 rungs for find_collision", () => {
  assert.equal(typeof v.walkthroughs.find_collision, "function");
  const rungs = v.walkthroughs.find_collision({});
  assert.ok(Array.isArray(rungs));
  assert.equal(rungs.length, 3);
  rungs.forEach((r) => {
    assert.equal(typeof r, "string");
    assert.ok(r.length > 0);
  });
});

test("walkthrough rungs mention the birthday-bound numbers", () => {
  const rungs = v.walkthroughs.find_collision({});
  const all = rungs.join(" ");
  // 65,536 = 2^16, or 256 = sqrt(2^16), or sqrt explicitly.
  assert.ok(
    /65,?536|sqrt|256/i.test(all),
    "expected birthday-bound numbers in walkthrough"
  );
});

test("walkthroughs does NOT define info (no right answer to walk to)", () => {
  assert.equal(v.walkthroughs.info, undefined);
});
