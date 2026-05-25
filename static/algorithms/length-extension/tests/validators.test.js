import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";
import {
  SECRET_LENGTH,
  ORIGINAL_REQUEST,
  ATTACK_EXTENSION,
} from "../vulnerable_server.js";

test("info always ok", () => {
  assert.deepEqual(v.info("anything", {}), { ok: true, value: {} });
});

test("walkthroughs has 3 rungs for run_attack", () => {
  assert.equal(typeof v.walkthroughs.run_attack, "function");
  const rungs = v.walkthroughs.run_attack({});
  assert.ok(Array.isArray(rungs));
  assert.equal(rungs.length, 3);
  rungs.forEach((r) => {
    assert.equal(typeof r, "string");
    assert.ok(r.length > 0);
  });
});

test("run_attack happy: ok=true, server accepts the forgery", async () => {
  const r = await v.run_attack(null, {});
  assert.equal(r.ok, true);
  const val = r.value;
  assert.equal(val.lenext_original, ORIGINAL_REQUEST);
  assert.equal(val.lenext_extension, ATTACK_EXTENSION);
  assert.equal(val.lenext_secret_len, SECRET_LENGTH);
  assert.equal(val.lenext_server_accepts, true);
  // Hex shapes.
  assert.match(val.lenext_signature, /^[0-9a-f]{64}$/);
  assert.match(val.lenext_forged_signature, /^[0-9a-f]{64}$/);
  assert.match(val.lenext_glue_padding_hex, /^[0-9a-f]+$/);
  assert.match(val.lenext_forged_request, /^[0-9a-f]+$/);
  // The glue padding starts with 0x80.
  assert.equal(val.lenext_glue_padding_hex.slice(0, 2), "80");
});

test("run_attack writes all state keys the lesson spec requires", async () => {
  const r = await v.run_attack(null, {});
  const expectedKeys = [
    "lenext_original",
    "lenext_signature",
    "lenext_extension",
    "lenext_secret_len",
    "lenext_glue_padding_hex",
    "lenext_forged_request",
    "lenext_forged_signature",
    "lenext_server_accepts",
  ];
  for (const k of expectedKeys) {
    assert.ok(k in r.value, `state key missing: ${k}`);
  }
});

test("run_attack: forged request contains both the original amount and the appended amount", async () => {
  const r = await v.run_attack(null, {});
  // Decode the hex back to bytes, then to UTF-8 (lossy for the glue padding region).
  const forgedHex = r.value.lenext_forged_request;
  const bytes = new Uint8Array(forgedHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(forgedHex.slice(i * 2, i * 2 + 2), 16);
  }
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  assert.ok(text.includes("amount=10"), "original amount missing");
  assert.ok(text.includes("amount=100000"), "extension amount missing");
});
