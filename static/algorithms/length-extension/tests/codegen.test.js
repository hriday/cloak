import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import * as c from "../codegen.js";
import { givenPair } from "../vulnerable_server.js";

// ---- shape / content of the emitted script -------------------------------

test("full_script imports hashlib + struct", () => {
  const out = c.full_script({});
  assert.match(out, /import hashlib/);
  assert.match(out, /import struct/);
});

test("full_script defines a Sha256 class with from_state", () => {
  const out = c.full_script({});
  assert.match(out, /class Sha256:/);
  assert.match(out, /def from_state\(/);
});

test("full_script defines sign_request, verify_request, forge", () => {
  const out = c.full_script({});
  assert.match(out, /def sign_request\(/);
  assert.match(out, /def verify_request\(/);
  assert.match(out, /def forge\(/);
});

test("full_script begins with a FOR LEARNING ONLY warning", () => {
  const out = c.full_script({});
  assert.match(out, /FOR LEARNING ONLY/i);
});

test("full_script hard-codes the SECRET", () => {
  const out = c.full_script({});
  assert.match(out, /SECRET = b'correct-horse'/);
});

test("full_script inlines lenext_signature from state when available", () => {
  const sig = "deadbeef".repeat(8); // 64 hex chars
  const out = c.full_script({ lenext_signature: sig });
  assert.ok(out.includes(sig));
  assert.match(out, /ORIGINAL_SIG = bytes\.fromhex/);
});

test("full_script inlines lenext_original and lenext_extension when available", () => {
  const out = c.full_script({
    lenext_original: "x=1",
    lenext_extension: "&y=2",
  });
  assert.match(out, /"x=1"/);
  assert.match(out, /"&y=2"/);
});

test("full_script inlines lenext_secret_len when present", () => {
  const out = c.full_script({ lenext_secret_len: 17 });
  assert.match(out, /SECRET_LEN = 17/);
});

test("full_script tolerates undefined state", () => {
  const out = c.full_script();
  assert.match(out, /def forge\(/);
});

// Per-step stubs --------------------------------------------------------

for (const name of [
  "intro",
  "merkle_damgard_recap",
  "the_attack",
  "run_attack",
  "why_hmac_fixes_it",
  "other_defenses",
  "done",
]) {
  test(`${name} returns empty string`, () => {
    assert.equal(c[name]({}), "");
  });
}

// ---- the load-bearing test: emitted Python actually runs the attack -----

// We only run this if `python3` exists. Skip otherwise — the JS tests
// already exercise the same attack end-to-end; this just confirms the
// shipped script will work in the user's terminal.

function hasPython() {
  try {
    const r = spawnSync("python3", ["--version"], { stdio: "ignore" });
    return r.status === 0;
  } catch (_e) {
    return false;
  }
}

test("emitted Python script: from-scratch SHA-256 matches hashlib and server accepts the forgery", { skip: !hasPython() && "python3 not on PATH" }, () => {
  const { request, signature } = givenPair();
  const py = c.full_script({
    lenext_original: request,
    lenext_signature: signature,
    lenext_extension: "&amount=100000",
    lenext_secret_len: 13,
  });

  // Write to a temp file and run.
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "lenext-codegen-"));
  const scriptPath = path.join(tmpDir, "demo.py");
  fs.writeFileSync(scriptPath, py);

  try {
    const r = spawnSync("python3", [scriptPath], {
      encoding: "utf-8",
      timeout: 30_000,
    });
    // The script asserts internally; status 0 + the success line is the
    // confirmation.
    assert.equal(
      r.status,
      0,
      `python3 demo.py exited with status ${r.status}\n` +
        `stdout:\n${r.stdout}\nstderr:\n${r.stderr}`
    );
    assert.match(r.stdout, /our SHA-256 matches hashlib/);
    assert.match(r.stdout, /server accepts forged signature: True/);
    assert.match(r.stdout, /attack succeeded/);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
