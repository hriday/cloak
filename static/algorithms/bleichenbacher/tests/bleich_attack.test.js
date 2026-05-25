import { test } from "node:test";
import assert from "node:assert/strict";
import { runAttack, stripPadding } from "../bleich_attack.js";
import {
  _resetForTests,
  getPlaintext,
  TARGET_CT,
  PLAINTEXT,
  K,
} from "../bleich_simulator.js";
import { _bleichConfig as C } from "../bleich_config.js";

test("runAttack recovers the correct PKCS#1 v1.5 padded plaintext", async () => {
  _resetForTests();
  const result = await runAttack();
  // Recovered padded message should match the configured padded bytes.
  assert.equal(result.paddedInt, C.paddedInt);
  assert.deepEqual(Array.from(result.plaintext), C.paddedBytes);
});

test("runAttack — stripPadding recovers the original ASCII message", async () => {
  _resetForTests();
  const result = await runAttack();
  const msg = new TextDecoder().decode(stripPadding(result.plaintext));
  assert.equal(msg, getPlaintext());
  assert.equal(msg, PLAINTEXT);
});

test("runAttack converges in fewer than 200_000 queries (toy modulus)", async () => {
  _resetForTests();
  const result = await runAttack();
  assert.ok(
    result.totalQueries < 200000,
    `attack used ${result.totalQueries} queries; expected < 200_000`
  );
  assert.ok(
    result.totalQueries >= 1,
    `attack used ${result.totalQueries} queries — should be ≥ 1`
  );
  // Pedagogical log so the test output shows the actual cost.
  console.log(`[bench] runAttack used ${result.totalQueries} oracle queries; ` +
    `found ${result.conformingSValues.length} conforming s values`);
});

test("runAttack fires progressCallback at least a few times during the run", async () => {
  _resetForTests();
  const calls = [];
  const result = await runAttack(
    undefined,
    async (snap) => { calls.push(snap); },
    { progressEvery: 200 }
  );
  assert.ok(calls.length >= 3, `expected ≥ 3 progress emissions, got ${calls.length}`);
  // Last call should have done=true and intervalLow == intervalHigh == m.
  const last = calls[calls.length - 1];
  assert.equal(last.done, true);
  assert.equal(last.intervalLow, last.intervalHigh);
  assert.equal(last.intervalLow, result.paddedInt);
});

test("runAttack progress snapshots are monotonic in totalQueries", async () => {
  _resetForTests();
  const snaps = [];
  await runAttack(undefined, async (s) => { snaps.push(s); }, { progressEvery: 200 });
  for (let i = 1; i < snaps.length; i++) {
    assert.ok(
      snaps[i].totalQueries >= snaps[i - 1].totalQueries,
      `progress totals went backwards: ${snaps[i - 1].totalQueries} → ${snaps[i].totalQueries}`
    );
  }
});

test("runAttack respects maxQueries cap", async () => {
  _resetForTests();
  await assert.rejects(
    () => runAttack(undefined, undefined, { maxQueries: 5 }),
    /maxQueries/
  );
});

test("runAttack accepts a custom server with the same interface", async () => {
  _resetForTests();
  // Wrap the real simulator. Counts how many times each method is called.
  const counters = { query: 0, target: 0, pk: 0 };
  const sim = await import("../bleich_simulator.js");
  const wrapped = {
    query: (c) => { counters.query += 1; return sim.query(c); },
    targetCiphertext: () => { counters.target += 1; return sim.targetCiphertext(); },
    publicKey: () => { counters.pk += 1; return sim.publicKey(); },
  };
  const result = await runAttack(wrapped);
  assert.equal(result.paddedInt, C.paddedInt);
  assert.ok(counters.query > 0);
  assert.equal(counters.target, 1);
  assert.equal(counters.pk, 1);
});

test("stripPadding strips PKCS#1 v1.5 leading bytes", () => {
  const padded = new Uint8Array([0x00, 0x02, 0x42, 0x00, 0x68, 0x69, 0x21, 0x21]);
  const msg = stripPadding(padded);
  assert.deepEqual(Array.from(msg), [0x68, 0x69, 0x21, 0x21]);
});

test("stripPadding rejects messages without 00 02 prefix", () => {
  const bad = new Uint8Array([0x01, 0x02, 0x42, 0x00, 0x68]);
  assert.throws(() => stripPadding(bad), /not PKCS#1 v1\.5/);
});

test("stripPadding rejects messages without 0x00 separator", () => {
  const noSep = new Uint8Array([0x00, 0x02, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42]);
  assert.throws(() => stripPadding(noSep), /separator/);
});

test("stripPadding rejects too-short input", () => {
  assert.throws(() => stripPadding(new Uint8Array([0x00, 0x02])), /too short/);
});

test("stripPadding rejects non-Uint8Array input", () => {
  assert.throws(() => stripPadding([0x00, 0x02, 0x42, 0x00]), /Uint8Array/);
});

test("runAttack returns conformingSValues as BigInt array, all > 0", async () => {
  _resetForTests();
  const result = await runAttack();
  assert.ok(Array.isArray(result.conformingSValues));
  assert.ok(result.conformingSValues.length >= 1);
  for (const s of result.conformingSValues) {
    assert.equal(typeof s, "bigint");
    assert.ok(s > 0n);
  }
});

test("runAttack.plaintext is a Uint8Array of length K", async () => {
  _resetForTests();
  const result = await runAttack();
  assert.ok(result.plaintext instanceof Uint8Array);
  assert.equal(result.plaintext.length, K);
});
