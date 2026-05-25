import { test } from "node:test";
import assert from "node:assert/strict";
import { recoverByte, recoverBlock } from "../po_attack.js";
import { getPlaintext, _resetForTests } from "../po_simulator.js";

test("recoverByte recovers the last byte of the plaintext", async () => {
  _resetForTests();
  const pt = await getPlaintext();
  const expected = pt.charCodeAt(15);
  const { byte, queries } = await recoverByte(15, new Uint8Array(16));
  assert.equal(byte, expected, `expected last byte 0x${expected.toString(16)}, got 0x${byte.toString(16)}`);
  assert.ok(queries >= 1 && queries <= 257, `queries=${queries} out of expected range`);
});

test("recoverByte queries average roughly 128 with stdev — sample of 8 runs stays under 256", async () => {
  let totalQueries = 0;
  for (let i = 0; i < 8; i++) {
    _resetForTests();
    const { queries } = await recoverByte(15, new Uint8Array(16));
    assert.ok(queries <= 257, `queries=${queries} exceeded 257`);
    totalQueries += queries;
  }
  // Average across 8 runs should be roughly 128. We allow a generous
  // 32..224 range to avoid flakiness — the sample size is small.
  const avg = totalQueries / 8;
  assert.ok(avg >= 32 && avg <= 224, `avg queries ${avg} outside 32..224`);
});

test("recoverBlock recovers the full plaintext", async () => {
  _resetForTests();
  const expected = await getPlaintext();
  const { plaintext, totalQueries } = await recoverBlock();
  const recovered = new TextDecoder().decode(plaintext);
  assert.equal(recovered, expected, `expected '${expected}', got '${recovered}'`);
  // 16 bytes × 256 worst-case + 16 confirmation queries on the last-byte
  // step ≈ 4112. Real average is ~2048.
  assert.ok(totalQueries <= 4200, `totalQueries=${totalQueries} exceeded 4200`);
  assert.ok(totalQueries >= 16, `totalQueries=${totalQueries} too low`);
});

test("recoverBlock fires progressCallback once per byte, counting down 15..0", async () => {
  _resetForTests();
  const calls = [];
  await recoverBlock((i, b, total) => {
    calls.push({ i, b, total });
  });
  assert.equal(calls.length, 16);
  for (let k = 0; k < 16; k++) {
    assert.equal(calls[k].i, 15 - k, `call ${k}: i should be ${15 - k}, got ${calls[k].i}`);
    assert.ok(calls[k].b >= 0 && calls[k].b <= 255);
    assert.ok(calls[k].total >= 1);
  }
  // total should be monotonically non-decreasing
  for (let k = 1; k < 16; k++) {
    assert.ok(calls[k].total >= calls[k - 1].total);
  }
});

test("recoverByte rejects invalid targetBytePos", async () => {
  await assert.rejects(() => recoverByte(-1, new Uint8Array(16)), /0\.\.15/);
  await assert.rejects(() => recoverByte(16, new Uint8Array(16)), /0\.\.15/);
  await assert.rejects(() => recoverByte("a", new Uint8Array(16)), /0\.\.15/);
});

test("recoverByte rejects wrong-shape knownBytes", async () => {
  await assert.rejects(() => recoverByte(15, new Uint8Array(8)), /Uint8Array\(16\)/);
  await assert.rejects(() => recoverByte(15, [0, 0, 0]), /Uint8Array\(16\)/);
});

test("recoverByte at position 14 recovers the second-to-last byte once 15 is known", async () => {
  _resetForTests();
  const pt = await getPlaintext();
  const known = new Uint8Array(16);
  known[15] = pt.charCodeAt(15);
  const { byte } = await recoverByte(14, known);
  assert.equal(byte, pt.charCodeAt(14));
});

test("recoverBlock: average queries across 8 runs is roughly ~2048", async () => {
  let sum = 0;
  const N = 8;
  for (let i = 0; i < N; i++) {
    _resetForTests();
    const { totalQueries } = await recoverBlock();
    sum += totalQueries;
  }
  const avg = sum / N;
  // Theoretical average: 16 bytes × 128 avg queries per byte + ~16 confirm
  // queries for the last-byte step ≈ 2064. Allow a wide envelope to
  // accommodate the variance with small N.
  console.log(`[bench] recoverBlock average totalQueries across ${N} runs: ${avg}`);
  assert.ok(avg >= 800 && avg <= 3500, `avg=${avg} outside 800..3500`);
});
