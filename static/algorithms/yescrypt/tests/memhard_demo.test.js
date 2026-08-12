import { test } from "node:test";
import assert from "node:assert/strict";
import * as mh from "../memhard_demo.js";

test("ALLOWED_MEMORY_MIB is [1, 4, 16, 64]", () => {
  assert.deepEqual(mh.ALLOWED_MEMORY_MIB, [1, 4, 16, 64]);
});

test("cited tables cover every allowed size and grow with memory", () => {
  for (const table of [mh.CITED_YESCRYPT_MS, mh.CITED_ARGON2ID_MS]) {
    let prev = 0;
    for (const mib of mh.ALLOWED_MEMORY_MIB) {
      assert.ok(typeof table[mib] === "number", `${mib} MiB cited`);
      assert.ok(table[mib] > prev, "cited ms grows with memory");
      prev = table[mib];
    }
  }
});

test("mixMemory throws on a size not in ALLOWED_MEMORY_MIB", () => {
  assert.throws(() => mh.mixMemory("pw", 3));
  assert.throws(() => mh.mixMemory("pw", 0));
});

test("mixMemory: 1 MiB run reports blocks, bytes touched, digest", () => {
  const r = mh.mixMemory("hunter2", 1);
  assert.equal(r.allocationFailed, false);
  assert.equal(r.blocks, 1024);                       // 1 MiB of 1-KiB blocks
  assert.equal(r.bytesTouched, 2 * 1024 * 1024);      // fill pass + read pass
  assert.match(r.digestHex, /^[0-9a-f]{32}$/);
  assert.ok(typeof r.ms === "number" && r.ms >= 0);
});

test("mixMemory is deterministic for (password, memory) apart from ms", () => {
  const a = mh.mixMemory("hunter2", 1);
  const b = mh.mixMemory("hunter2", 1);
  assert.equal(a.digestHex, b.digestHex);
  assert.equal(a.bytesTouched, b.bytesTouched);
});

test("mixMemory digest changes with password and with memory size", () => {
  const base = mh.mixMemory("hunter2", 1);
  assert.notEqual(mh.mixMemory("hunter3", 1).digestHex, base.digestHex);
  assert.notEqual(mh.mixMemory("hunter2", 4).digestHex, base.digestHex);
});
