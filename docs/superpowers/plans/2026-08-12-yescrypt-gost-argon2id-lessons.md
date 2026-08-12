# yescrypt / gost-yescrypt / argon2id Lessons Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add three password-hashing lessons (yescrypt, gost-yescrypt, argon2id) as separate algorithm cards, plus a "How Linux stores your password" bundle.

**Architecture:** Data-driven lessons: each algorithm is a `fixtures.json` (Algorithm + Lesson + Steps rows) plus a JS module directory (`validators.js`, `codegen.js`, optional demo). One shared toy memory-hard mixer (`memhard_demo.js`, in yescrypt's dir) powers the interactive step in both memory lessons. One new `lesson.html` template branch per interactive-widget slug. No model/view/API changes.

**Tech Stack:** Django 5 (fixtures + pytest), vanilla ES modules + Alpine.js (wizard), `node --test` for JS tests.

**Spec:** `docs/superpowers/specs/2026-08-12-yescrypt-gost-argon2id-lessons-design.md`

## Global Constraints

- Step PKs: `<algo-pk> * 10 + order`. yescrypt: algo/lesson PK 32, steps 321–327. gost-yescrypt: PK 33, steps 331–336. argon2id: PK 34, steps 341–348.
- `Algorithm.intro_template` ≤ 200 chars (model `max_length=200`; fixture tests assert it).
- All three algorithms: `family: "hash"`, `status: "live"`; orders 32, 33, 34.
- JS modules must run under `node --test` on Node ≥ 19 AND as browser ES modules (no Node-only imports outside `tests/`).
- JS-only house pattern: `algorithms/<slug>/` contains ONLY `fixtures.json` — no Python validators/codegen mirrors.
- No real yescrypt/argon2 in the browser. The toy mixer must state this in its header comment (bcrypt honesty pattern) and every UI/prompt that shows toy output must label it synthetic; cited real-implementation numbers carry the honest magnitudes.
- Password guard everywhere: printable ASCII, 1–200 chars, hint wording matching bcrypt's `checkPassword`.
- Python tests: `.venv/bin/pytest <path> -v`. JS tests: `node --test static/algorithms/<slug>/tests/`.
- Commit after every task; messages follow house style `feat(<slug>): ...`, ending with `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

---

### Task 1: Sync the spec with three plan-time corrections

Recon during planning found three facts the spec got wrong. Fix the spec first so implementers never follow the stale version.

**Files:**
- Modify: `docs/superpowers/specs/2026-08-12-yescrypt-gost-argon2id-lessons-design.md`

**Interfaces:**
- Produces: corrected spec; later tasks follow THIS plan where they differ from the old spec text.

- [ ] **Step 1: Edit the spec's "Wizard + template integration" section**

Replace the `DEMO_FILENAMES` bullet and the `hasCustomInputBranch`/`MULTI_INPUT_SLUGS` bullets with:

```markdown
`static/core/wizard.js`:
- NO `DEMO_FILENAMES` entries: the template branches only call `check()`;
  the validators import the mixer directly (precedent: hkdf, hybrid,
  length-extension have no demo entry). The argon2id re-export shim is
  therefore not needed either.
- `hasCustomInputBranch` SLUGS: add `"feel-the-memory"` (shared by yescrypt
  and argon2id) and `"spot-the-difference"` (gost-yescrypt).
- `MULTI_INPUT_SLUGS`: add `"feel-the-memory"` (`{password, memoryMiB}`).
  `spot-the-difference` stays single-input (`inputValue`).

`core/templates/core/lesson.html`:
- The default `input-numeric` renderer does not consult
  `hasCustomInputBranch` (bcrypt's `time-the-cost` currently double-renders
  a stray "your answer" box) and the stock `choose-from-list` renderer is
  hardwired to RSA's `coprimeOptions`. Fix both guards:
  `!hasCustomInputBranch(step)` is added to the `input-numeric` and
  `choose-from-list` conditions.
- TWO new input branches: `feel-the-memory` (password + memory picker +
  run button) and `spot-the-difference` (three choice buttons). Plus result
  panels. `tuning` uses the stock numeric renderer; no other branches.
```

Also update the argon2id module list in "JS modules" to drop the `memhard_demo.js` shim line, and change the gost-yescrypt step-4 row's note from "Standard choose-from-list rendering, no custom branch" to "Custom three-button branch (stock choose-from-list renderer is RSA-specific)".

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/specs/2026-08-12-yescrypt-gost-argon2id-lessons-design.md
git commit -m "docs(spec): plan-time corrections — no demo shim, custom branches, renderer guards"
```

---

### Task 2: Toy memory-hard mixer (`memhard_demo.js`)

**Files:**
- Create: `static/algorithms/yescrypt/memhard_demo.js`
- Test: `static/algorithms/yescrypt/tests/memhard_demo.test.js`

**Interfaces:**
- Produces: `mixMemory(password: string, memoryMiB: number) -> {allocationFailed: boolean, ms?: number, blocks?: number, bytesTouched?: number, digestHex?: string}` (sync), `ALLOWED_MEMORY_MIB = [1, 4, 16, 64]`, `BLOCK_WORDS = 256`, `CITED_YESCRYPT_MS`, `CITED_ARGON2ID_MS` (objects keyed by MiB). Consumed by Tasks 3 and 8.

- [ ] **Step 1: Write the failing test**

`static/algorithms/yescrypt/tests/memhard_demo.test.js`:

```js
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test static/algorithms/yescrypt/tests/`
Expected: FAIL — cannot find module `../memhard_demo.js`.

- [ ] **Step 3: Write the implementation**

`static/algorithms/yescrypt/memhard_demo.js`:

```js
// Toy memory-hard mixer for the yescrypt and argon2id lessons.
//
// IMPORTANT — this file does NOT implement yescrypt or argon2. Real yescrypt
// has no maintained JS port and a WASM argon2 build would add ~100 KB and
// block the main thread. What we CAN make real in a browser is the thing
// bcrypt's lesson couldn't: the MEMORY. This mixer genuinely allocates the
// chosen number of mebibytes and genuinely touches every byte — a sequential
// fill pass, then a data-dependent random-read pass (the two-loop shape of
// scrypt's ROMix, which is the ancestor of both yescrypt and argon2's
// block-mixing schedule). The mixing function itself is a toy (xorshift32),
// so the wall-time constant factor is wrong; the CITED_* tables carry honest
// numbers from real implementations (libxcrypt yescrypt and argon2-cffi with
// t=3, p=4 on a typical 2024 laptop, single run, rounded).
//
// Node >=19-compatible: no browser globals required.

export const ALLOWED_MEMORY_MIB = [1, 4, 16, 64];
export const BLOCK_WORDS = 256; // 256 × 4-byte words = 1 KiB per block

export const CITED_YESCRYPT_MS = { 1: 3, 4: 12, 16: 50, 64: 210 };
export const CITED_ARGON2ID_MS = { 1: 6, 4: 24, 16: 95, 64: 380 };

function nowMs() {
  if (typeof performance !== "undefined" && typeof performance.now === "function") {
    return performance.now();
  }
  return Date.now();
}

// FNV-1a over the password string → 32-bit seed. Deterministic so the
// digest is testable; NOT a KDF, and never presented as one.
function fnv1a(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

function xorshift32(x) {
  x ^= x << 13; x >>>= 0;
  x ^= x >>> 17;
  x ^= x << 5; x >>>= 0;
  return x >>> 0;
}

export function mixMemory(password, memoryMiB) {
  if (!ALLOWED_MEMORY_MIB.includes(memoryMiB)) {
    throw new Error(`memoryMiB must be one of ${ALLOWED_MEMORY_MIB.join(", ")}`);
  }
  const nBlocks = memoryMiB * 1024; // 1-KiB blocks
  let v;
  try {
    v = new Uint32Array(nBlocks * BLOCK_WORDS);
  } catch {
    return { allocationFailed: true };
  }

  const t0 = nowMs();

  // Pass 1 — sequential fill (ROMix loop 1 shape).
  let x = fnv1a(password) || 1;
  for (let i = 0; i < v.length; i++) {
    x = xorshift32(x);
    v[i] = x;
  }

  // Pass 2 — data-dependent random block reads (ROMix loop 2 shape). The
  // NEXT block index depends on data just read, which is exactly what makes
  // time-memory trade-offs expensive for attackers.
  let a = x, b = 0x9e3779b9, c = 0x85ebca6b, d = 0xc2b2ae35;
  for (let r = 0; r < nBlocks; r++) {
    const base = (a % nBlocks) * BLOCK_WORDS;
    for (let w = 0; w < BLOCK_WORDS; w += 4) {
      a = (a ^ v[base + w]) >>> 0;
      b = (b ^ v[base + w + 1]) >>> 0;
      c = (c ^ v[base + w + 2]) >>> 0;
      d = (d ^ v[base + w + 3]) >>> 0;
    }
    a = xorshift32(a);
  }

  const ms = nowMs() - t0;
  const digestHex = [a, b, c, d]
    .map((w) => (w >>> 0).toString(16).padStart(8, "0"))
    .join("");
  return {
    allocationFailed: false,
    ms,
    blocks: nBlocks,
    bytesTouched: (v.length + nBlocks * BLOCK_WORDS) * 4, // fill + read pass
    digestHex,
  };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test static/algorithms/yescrypt/tests/`
Expected: PASS (all 6 tests).

- [ ] **Step 5: Commit**

```bash
git add static/algorithms/yescrypt/memhard_demo.js static/algorithms/yescrypt/tests/memhard_demo.test.js
git commit -m "feat(yescrypt): memhard_demo.js — toy memory-hard mixer shared with argon2id"
```

---

### Task 3: yescrypt validators + walkthroughs

**Files:**
- Create: `static/algorithms/yescrypt/validators.js`
- Test: `static/algorithms/yescrypt/tests/validators.test.js`

**Interfaces:**
- Consumes: `mixMemory`, `ALLOWED_MEMORY_MIB`, `CITED_YESCRYPT_MS` from `./memhard_demo.js` (Task 2).
- Produces: `memory_cost(input: {password, memoryMiB}, state) -> {ok, hint?|value?}` writing state keys `ys_password, ys_memory_mib, ys_blocks, ys_bytes_touched, ys_ms, ys_digest, ys_cited_real_ms`; `info()`; `walkthroughs.memory_cost`. Fixture Task 5 references validator keys `memory_cost` and `info`.

- [ ] **Step 1: Write the failing test**

`static/algorithms/yescrypt/tests/validators.test.js`:

```js
import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

test("info always ok with empty value", () => {
  assert.deepEqual(v.info(null, {}), { ok: true, value: {} });
});

test("memory_cost rejects empty password", () => {
  const r = v.memory_cost({ password: "", memoryMiB: 1 }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /password/i);
});

test("memory_cost rejects non-printable-ASCII password", () => {
  const r = v.memory_cost({ password: "pässwörd", memoryMiB: 1 }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /ASCII/);
});

test("memory_cost rejects memory size not in the allowed list", () => {
  const r = v.memory_cost({ password: "hunter2", memoryMiB: 3 }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /1, 4, 16, 64/);
});

test("memory_cost happy path writes ys_* state keys", () => {
  const r = v.memory_cost({ password: "hunter2", memoryMiB: 1 }, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.ys_password, "hunter2");
  assert.equal(r.value.ys_memory_mib, 1);
  assert.equal(r.value.ys_blocks, 1024);
  assert.equal(r.value.ys_bytes_touched, 2 * 1024 * 1024);
  assert.match(r.value.ys_digest, /^[0-9a-f]{32}$/);
  assert.equal(typeof r.value.ys_ms, "number");
  assert.equal(r.value.ys_cited_real_ms, 3);
});

test("walkthroughs cover memory_cost", () => {
  const lines = v.walkthroughs.memory_cost({});
  assert.ok(Array.isArray(lines) && lines.length >= 2);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test static/algorithms/yescrypt/tests/validators.test.js`
Expected: FAIL — cannot find module `../validators.js`.

- [ ] **Step 3: Write the implementation**

`static/algorithms/yescrypt/validators.js`:

```js
// yescrypt lesson validators.
//
// Step 3 (feel-the-memory) — memory_cost. Input: {password, memoryMiB}.
// Runs the toy mixer from memhard_demo.js (which really allocates and
// touches the memory — see that file's header for what is and isn't real),
// captures wall time, writes ys_* state keys. All other steps use the
// info validator (always ok).

import { mixMemory, ALLOWED_MEMORY_MIB, CITED_YESCRYPT_MS } from "./memhard_demo.js";

// Same guard shape as bcrypt's checkPassword so the hash-family lessons
// feel consistent.
function checkPassword(password) {
  if (typeof password !== "string" || password.length === 0) {
    return "Type a password (any string).";
  }
  if (password.length > 200) {
    return "Keep it under 200 characters for the demo.";
  }
  for (let i = 0; i < password.length; i++) {
    const code = password.charCodeAt(i);
    if (code < 32 || code > 126) {
      return "Stick to printable ASCII for the demo.";
    }
  }
  return null;
}

export function memory_cost(input, _state) {
  const password = input?.password == null ? "" : String(input.password);
  const hint = checkPassword(password);
  if (hint) return { ok: false, hint };

  const memoryMiB = Number(input?.memoryMiB);
  if (!ALLOWED_MEMORY_MIB.includes(memoryMiB)) {
    return {
      ok: false,
      hint: `Pick a memory size from the buttons (${ALLOWED_MEMORY_MIB.join(", ")} MiB).`,
    };
  }

  const result = mixMemory(password, memoryMiB);
  if (result.allocationFailed) {
    return {
      ok: false,
      hint: "Your browser refused the memory allocation — pick a smaller size.",
    };
  }

  return {
    ok: true,
    value: {
      ys_password: password,
      ys_memory_mib: memoryMiB,
      ys_blocks: result.blocks,
      ys_bytes_touched: result.bytesTouched,
      ys_ms: result.ms,
      ys_digest: result.digestHex,
      ys_cited_real_ms: CITED_YESCRYPT_MS[memoryMiB] ?? null,
    },
  };
}

export function info(_input, _state) {
  return { ok: true, value: {} };
}

export const walkthroughs = {
  memory_cost: (_state) => [
    `**The construction:** scrypt (and yescrypt after it) forces two passes over a big array: fill it sequentially, then read it back in a data-dependent random order. The widget really does both passes over the memory size you pick — watch **bytes touched** double the memory size. What's toy here is the mixing function; the cited column shows real libxcrypt yescrypt timings for the same memory.`,
    `**Try this:** run 1 MiB, then 64 MiB. Time should scale roughly linearly with memory — that's the point. A GPU cracker with 10,000 cores doesn't have 10,000 × 64 MiB of fast RAM per core, so the memory knob hurts attackers far more than the CPU-time knob bcrypt offers.`,
    `**Practical numbers:** libxcrypt's default (the \`j9T\` you'll see in step 4) is 16 MiB and ~50 ms per login on a 2024 laptop. Nobody notices at login; a cracking rig notices immediately.`,
  ],
};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test static/algorithms/yescrypt/tests/validators.test.js`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add static/algorithms/yescrypt/validators.js static/algorithms/yescrypt/tests/validators.test.js
git commit -m "feat(yescrypt): validators + walkthroughs"
```

---

### Task 4: yescrypt codegen

**Files:**
- Create: `static/algorithms/yescrypt/codegen.js`
- Test: `static/algorithms/yescrypt/tests/codegen.test.js`

**Interfaces:**
- Consumes: state key `ys_password` (Task 3).
- Produces: `full_script(state) -> string` (Python source). The wizard calls `codegen.full_script(this.state)` on the Done step — the export name is fixed.

- [ ] **Step 1: Write the failing test**

`static/algorithms/yescrypt/tests/codegen.test.js`:

```js
import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

test("full_script loads libcrypt via ctypes and uses the $y$ prefix", () => {
  const out = c.full_script({});
  assert.match(out, /import ctypes/);
  assert.match(out, /libcrypt\.so\.1/);
  assert.match(out, /\$y\$j9T\$/);
});

test("full_script embeds the learner's password, defaulting when absent", () => {
  assert.match(c.full_script({ ys_password: "hunter2" }), /"hunter2"/);
  assert.match(c.full_script({}), /correct-horse-battery-staple/);
});

test("full_script verifies right and wrong passwords", () => {
  const out = c.full_script({});
  assert.match(out, /wrong-password/);
  assert.match(out, /verify/i);
});

test("full_script handles missing libcrypt and failed hashing", () => {
  const out = c.full_script({});
  assert.match(out, /except OSError/);
  assert.match(out, /startswith\("\*"\)/);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test static/algorithms/yescrypt/tests/codegen.test.js`
Expected: FAIL — cannot find module `../codegen.js`.

- [ ] **Step 3: Write the implementation**

`static/algorithms/yescrypt/codegen.js`:

```js
// Generates the Python yescrypt demo shown on the Done step.
//
// Deliberately dependency-free: on any modern Linux, glibc delegates
// crypt(3) to libxcrypt, which speaks $y$. So the take-home script is
// ctypes + the system library — the same code path `passwd` and `login`
// use, which is the whole point of the Linux-flavored lesson.

export function full_script(state) {
  const raw = typeof state?.ys_password === "string" ? state.ys_password : "";
  const ok = raw.length > 0 && raw.length <= 200 && /^[\x20-\x7e]+$/.test(raw);
  const password = ok ? raw : "correct-horse-battery-staple";

  return [
    "# yescrypt demo — generated by cloak.moosha.org",
    "#",
    "# Runs on any modern Linux (glibc + libxcrypt). No pip installs. This is",
    "# the exact code path your system's passwd/login use for the $y$ hashes",
    "# in /etc/shadow.",
    "",
    "import ctypes",
    "import ctypes.util",
    "import secrets",
    "import string",
    "import sys",
    "import time",
    "",
    'libname = ctypes.util.find_library("crypt") or "libcrypt.so.1"',
    "try:",
    "    libcrypt = ctypes.CDLL(libname)",
    "except OSError:",
    '    sys.exit("libcrypt not found — run this on Linux with libxcrypt (any modern distro).")',
    "",
    "libcrypt.crypt.restype = ctypes.c_char_p",
    "libcrypt.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]",
    "",
    "# --- Build a $y$ setting string ------------------------------------",
    "# $y$ <params> $ <salt>   — 'j9T' encodes libxcrypt's default cost",
    "# (N=4096 blocks x r=32 => 16 MiB). Salt: 24 chars of the itoa64",
    "# alphabet. (itoa64 decodes 4 chars -> 3 bytes, so the length must be",
    "# a multiple of 4 for arbitrary random chars; distros emit 22 chars",
    "# with a restricted final char, which needs care we don't.)",
    'ITOA64 = "./" + string.digits + string.ascii_uppercase + string.ascii_lowercase',
    'setting = "$y$j9T$" + "".join(secrets.choice(ITOA64) for _ in range(24))',
    "",
    `PASSWORD = ${JSON.stringify(password)}`,
    "",
    "t0 = time.perf_counter()",
    "hashed = libcrypt.crypt(PASSWORD.encode(), setting.encode())",
    "t1 = time.perf_counter()",
    'if hashed is None or hashed.decode().startswith("*"):',
    '    sys.exit("crypt() rejected $y$ — your libcrypt is pre-libxcrypt (very old distro).")',
    "hashed = hashed.decode()",
    'print(f"shadow-format hash: {hashed}")',
    'print(f"  took {(t1 - t0) * 1000:.1f} ms (16 MiB filled and mixed)")',
    "",
    "# --- Verify --------------------------------------------------------",
    "# crypt(password, full_hash) re-derives using the params + salt embedded",
    "# in the hash itself; equality means match. Same trick as bcrypt.",
    "assert libcrypt.crypt(PASSWORD.encode(), hashed.encode()).decode() == hashed",
    'print("verify (right password): OK")',
    'assert libcrypt.crypt(b"wrong-password", hashed.encode()).decode() != hashed',
    'print("verify (wrong password): rejected")',
    "",
    '# Compare with your own /etc/shadow (root): sudo grep "^$USER:" /etc/shadow',
    "# The second field should start with $y$ on Fedora 35+/Debian 11+/Ubuntu 22.04+.",
  ].join("\n");
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test static/algorithms/yescrypt/tests/codegen.test.js`
Expected: PASS.

- [ ] **Step 5: Sanity-run the generated Python in Docker (Linux + libxcrypt)**

```bash
node -e "import('./static/algorithms/yescrypt/codegen.js').then(m => console.log(m.full_script({})))" > /tmp/ys_demo.py
docker run --rm -v /tmp/ys_demo.py:/demo.py python:3.12-slim python /demo.py
```

Expected: prints a `$y$j9T$...` hash, both verify lines. If Docker is unavailable, note it and move on — the string-level tests still gate the task.

- [ ] **Step 6: Commit**

```bash
git add static/algorithms/yescrypt/codegen.js static/algorithms/yescrypt/tests/codegen.test.js
git commit -m "feat(yescrypt): codegen — ctypes crypt(3) take-home script"
```

---

### Task 5: yescrypt fixtures

**Files:**
- Create: `algorithms/yescrypt/fixtures.json`
- Test: `static/algorithms/yescrypt/tests/fixtures.test.js`
- Modify: `core/tests/test_fixtures.py` (append one test)

**Interfaces:**
- Consumes: validator keys `memory_cost`, `info` (Task 3).
- Produces: Algorithm PK 32 (`yescrypt`), Lesson PK 32 (`the-default-nobody-noticed`), steps PK 321–327. Task 11's template branch matches step slug `feel-the-memory`; Task 12's bundle references slug `yescrypt`.

- [ ] **Step 1: Write the failing tests**

`static/algorithms/yescrypt/tests/fixtures.test.js` (mirror bcrypt's `fixtures.test.js` shape):

```js
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const data = JSON.parse(
  readFileSync(resolve(__dirname, "../../../../algorithms/yescrypt/fixtures.json"), "utf-8")
);

const algo = data.find((e) => e.model === "core.algorithm");
const lesson = data.find((e) => e.model === "core.lesson");
const steps = data.filter((e) => e.model === "core.step");

test("fixtures: algorithm pk=32, slug/family/status/order", () => {
  assert.equal(algo.pk, 32);
  assert.equal(algo.fields.slug, "yescrypt");
  assert.equal(algo.fields.family, "hash");
  assert.equal(algo.fields.status, "live");
  assert.equal(algo.fields.order, 32);
  assert.ok(algo.fields.intro_template.length <= 200);
});

test("fixtures: lesson pk=32 with 7 steps, PKs 321-327", () => {
  assert.equal(lesson.pk, 32);
  assert.equal(lesson.fields.slug, "the-default-nobody-noticed");
  assert.equal(steps.length, 7);
  assert.deepEqual(steps.map((s) => s.pk).sort(), [321, 322, 323, 324, 325, 326, 327]);
});

test("fixtures: step slugs, kinds, validator keys", () => {
  const bySlug = Object.fromEntries(steps.map((s) => [s.fields.slug, s.fields]));
  assert.deepEqual(
    steps.sort((a, b) => a.fields.order - b.fields.order).map((s) => s.fields.slug),
    ["intro", "scrypt-lineage", "feel-the-memory", "anatomy-of-a-y-hash",
     "rom-and-scale", "yescrypt-vs-argon2", "done"]
  );
  assert.equal(bySlug["feel-the-memory"].kind, "input-numeric");
  assert.equal(bySlug["feel-the-memory"].validator_key, "memory_cost");
  assert.equal(bySlug["done"].codegen_key, "done");
});
```

Append to `core/tests/test_fixtures.py`:

```python
@pytest.mark.django_db
def test_yescrypt_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/yescrypt/fixtures.json")
    from core.models import Algorithm, Lesson, Step
    a = Algorithm.objects.get(pk=32)
    assert a.slug == "yescrypt" and a.family == "hash" and len(a.intro_template) <= 200
    l = Lesson.objects.get(pk=32)
    assert l.slug == "the-default-nobody-noticed"
    steps = list(Step.objects.filter(lesson=l).order_by("order"))
    assert [s.slug for s in steps] == [
        "intro", "scrypt-lineage", "feel-the-memory", "anatomy-of-a-y-hash",
        "rom-and-scale", "yescrypt-vs-argon2", "done",
    ]
    assert steps[2].validator_key == "memory_cost"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test static/algorithms/yescrypt/tests/fixtures.test.js` → FAIL (no fixtures.json).
Run: `.venv/bin/pytest core/tests/test_fixtures.py -k yescrypt -v` → FAIL.

- [ ] **Step 3: Write `algorithms/yescrypt/fixtures.json`**

Structure (all step objects have `lesson: 32` and both `validator_key`/`codegen_key` set — `info`/`info` unless noted):

```json
[
  {"model": "core.algorithm", "pk": 32, "fields": {
    "slug": "yescrypt", "name": "yescrypt", "family": "hash",
    "intro_template": "The hash guarding most Linux logins since 2020 — scrypt's memory-hard idea tuned for /etc/shadow. Meet the $y$ prefix.",
    "status": "live", "order": 32}},
  {"model": "core.lesson", "pk": 32, "fields": {
    "algorithm": 32, "slug": "the-default-nobody-noticed",
    "title": "yescrypt: the default nobody noticed", "order": 1}},
  {"model": "core.step", "pk": 321, "fields": {"lesson": 32, "order": 1, "slug": "intro", "kind": "info", "prompt_template": "…", "help_template": "…", "validator_key": "info", "codegen_key": "info"}},
  …steps 322-327 same shape…
]
```

`prompt_template` content requirements per step (write full markdown prose from these facts; match the voice and length of bcrypt's prompts — 150–350 words each, `###` sub-headings, tables where noted):

1. **intro** — `$y$` is the second field of `/etc/shadow` on Fedora 35+, Debian 11+, Ubuntu 22.04+ (via libxcrypt); billions of logins daily; almost nobody knows its name; Solar Designer (Alexander Peslyak), Openwall, Password Hashing Competition 2013–2015 finalist with "special recognition"; show a full example shadow line with the `$y$j9T$<salt>$<hash>` field highlighted.
2. **scrypt-lineage** — Colin Percival, 2009, Tarsnap backups; first *memory-hard* password KDF; the ROMix two-loop idea (fill N blocks sequentially, then read them back in a data-dependent random order); why memory hurts GPUs/ASICs more than CPU time does (a cracking rig can add cores cheaply, it cannot add 16 MiB of low-latency RAM per core cheaply); yescrypt = scrypt + tweaks for the auth-server use case (pwxform rounds, optional ROM — teased for step 5).
3. **feel-the-memory** (kind `input-numeric`, validator `memory_cost`) — explain what the widget REALLY does (allocates the chosen MiB, two passes, reports bytes touched) and what's synthetic (toy mixing function, so ms constant factor is off); include this cited table:

   | Memory | Real yescrypt (libxcrypt, 2024 laptop) |
   |---|---|
   | 1 MiB | ~3 ms |
   | 4 MiB | ~12 ms |
   | 16 MiB | ~50 ms |
   | 64 MiB | ~210 ms |

   "What to look for": time scales ~linearly with memory; 16 MiB is the libxcrypt default; compare with bcrypt where the only knob is CPU time.
4. **anatomy-of-a-y-hash** — decode `$y$j9T$LdJMENpBABJJ3hIHjB1Bi.$HboGM6qPrsK.StKYGt6KErmUYtioHreJd98oIeMIGT7` field by field: `y` = yescrypt, `j9T` = itoa64-encoded params (N=4096, r=32 → 16 MiB), 22-char salt, 43-char hash; the itoa64 alphabet `./0-9A-Za-z`; everything self-contained in one string — same one-column-per-user property as bcrypt.
5. **rom-and-scale** — yescrypt's optional ROM: a multi-GiB table shared by all hashes on the box; an attacker must steal the ROM too, and can't fit it in GPU memory per-core; who uses this (large auth farms); why the shadow default doesn't (a laptop doesn't want a resident 4 GiB table).
6. **yescrypt-vs-argon2** — same goal, different bets: argon2id won the PHC and OWASP recommends it; yescrypt took "special recognition" and won the deployment war via libxcrypt; yescrypt's CPU-friendly pwxform vs argon2's simpler Blake2b filling; either is a fine answer — the wrong answer is fast hashes (SHA-256/MD5).
7. **done** (codegen_key `done`) — recap; point at the generated script; "In the real world" notes: check your own `/etc/shadow`; `yescrypt` params are tunable via `/etc/login.defs` (`YESCRYPT_COST_FACTOR`); if you're building an app, use argon2id or bcrypt via a maintained library rather than calling crypt(3).

`help_template` for each non-info step: 2–3 plain-English sentences (same voice as bcrypt's help strings).

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test static/algorithms/yescrypt/tests/` → PASS.
Run: `.venv/bin/pytest core/tests/test_fixtures.py -k yescrypt -v` → PASS.

- [ ] **Step 5: Commit**

```bash
git add algorithms/yescrypt/fixtures.json static/algorithms/yescrypt/tests/fixtures.test.js core/tests/test_fixtures.py
git commit -m "feat(yescrypt): fixtures — algorithm + lesson + 7 steps; fixture tests"
```

---

### Task 6: gost-yescrypt validators + codegen

**Files:**
- Create: `static/algorithms/gost-yescrypt/validators.js`
- Create: `static/algorithms/gost-yescrypt/codegen.js`
- Test: `static/algorithms/gost-yescrypt/tests/validators.test.js`
- Test: `static/algorithms/gost-yescrypt/tests/codegen.test.js`

**Interfaces:**
- Produces: `spot_difference(input: string, state) -> {ok, hint?|value?}` writing `gy_choice`; `info()`; `walkthroughs.spot_difference`; `full_script(state) -> string`. Valid choices: `"salt"`, `"params"`, `"prefix-and-hash"` (correct). Task 7's fixture uses validator key `spot_difference`; Task 11's branch buttons submit exactly these three strings via `inputValue`.

- [ ] **Step 1: Write the failing tests**

`static/algorithms/gost-yescrypt/tests/validators.test.js`:

```js
import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

test("info always ok", () => {
  assert.deepEqual(v.info(null, {}), { ok: true, value: {} });
});

test("spot_difference rejects empty input", () => {
  const r = v.spot_difference("", {});
  assert.equal(r.ok, false);
});

test("spot_difference: 'salt' is wrong, hint teaches why", () => {
  const r = v.spot_difference("salt", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /salt/i);
});

test("spot_difference: 'params' is wrong, hint teaches why", () => {
  const r = v.spot_difference("params", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /j9T|param/i);
});

test("spot_difference: 'prefix-and-hash' is correct", () => {
  const r = v.spot_difference("prefix-and-hash", {});
  assert.equal(r.ok, true);
  assert.equal(r.value.gy_choice, "prefix-and-hash");
});
```

`static/algorithms/gost-yescrypt/tests/codegen.test.js`:

```js
import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

test("full_script uses the $gy$ prefix via ctypes", () => {
  const out = c.full_script({});
  assert.match(out, /import ctypes/);
  assert.match(out, /\$gy\$j9T\$/);
});

test("full_script explains a GOST-less libxcrypt instead of crashing", () => {
  const out = c.full_script({});
  assert.match(out, /GOST/);
  assert.match(out, /startswith\("\*"\)/);
});

test("full_script verifies right and wrong passwords", () => {
  const out = c.full_script({});
  assert.match(out, /wrong-password/);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test static/algorithms/gost-yescrypt/tests/`
Expected: FAIL — modules not found.

- [ ] **Step 3: Write the implementations**

`static/algorithms/gost-yescrypt/validators.js`:

```js
// gost-yescrypt lesson validators.
//
// Step 4 (spot-the-difference) — spot_difference. The step's prompt shows
// the same password hashed as $y$ and $gy$ with identical salt + params;
// the learner picks which field actually changed. Input is one of the
// three button values (a plain string via inputValue).

const CORRECT = "prefix-and-hash";

export function spot_difference(input, _state) {
  const choice = String(input ?? "").trim();
  if (!choice) return { ok: false, hint: "Pick one of the three options." };
  if (choice === "salt") {
    return {
      ok: false,
      hint: "Look again — both strings carry the exact same salt field. The salt doesn't care which hash function mixes it.",
    };
  }
  if (choice === "params") {
    return {
      ok: false,
      hint: "Both strings say j9T — same N, same r, same 16 MiB. The GOST wrapper changes the hash function, not the memory-hardness parameters.",
    };
  }
  if (choice !== CORRECT) {
    return { ok: false, hint: "Pick one of the three options." };
  }
  return { ok: true, value: { gy_choice: choice } };
}

export function info(_input, _state) {
  return { ok: true, value: {} };
}

export const walkthroughs = {
  spot_difference: (_state) => [
    `**What changed:** the method prefix (\`$y$\` → \`$gy$\`) and every byte of the final hash field. gost-yescrypt runs the same yescrypt engine, then keys an HMAC built from Streebog (GOST R 34.11-2012) into the result — different outer function, different output bytes.`,
    `**What didn't:** salt and params. Compliance wrappers deliberately leave the cost machinery alone — that's the whole trick: satisfy the regulator by using the national-standard hash, keep the battle-tested KDF underneath.`,
  ],
};
```

`static/algorithms/gost-yescrypt/codegen.js`:

```js
// Generates the Python gost-yescrypt demo shown on the Done step.
//
// Same ctypes + libxcrypt approach as the yescrypt lesson, with a $gy$
// setting string. libxcrypt only speaks $gy$ when built with GOST support
// (--enable-hashes includes gost-yescrypt); the script detects the
// "*"-failure return and explains, instead of crashing with an assert.

export function full_script(state) {
  const raw = typeof state?.gy_password === "string" ? state.gy_password : "";
  const ok = raw.length > 0 && raw.length <= 200 && /^[\x20-\x7e]+$/.test(raw);
  const password = ok ? raw : "correct-horse-battery-staple";

  return [
    "# gost-yescrypt demo — generated by cloak.moosha.org",
    "#",
    "# Needs Linux with a libxcrypt built with GOST support. Fedora/RHEL",
    "# enable it; some distros don't — the script tells you if yours doesn't.",
    "",
    "import ctypes",
    "import ctypes.util",
    "import secrets",
    "import string",
    "import sys",
    "",
    'libname = ctypes.util.find_library("crypt") or "libcrypt.so.1"',
    "try:",
    "    libcrypt = ctypes.CDLL(libname)",
    "except OSError:",
    '    sys.exit("libcrypt not found — run this on Linux with libxcrypt.")',
    "",
    "libcrypt.crypt.restype = ctypes.c_char_p",
    "libcrypt.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]",
    "",
    '# $gy$ = gost-yescrypt: yescrypt inside, HMAC-Streebog-256 outside.',
    "# Salt: 24 itoa64 chars (multiple of 4 decodes cleanly; see yescrypt lesson).",
    'ITOA64 = "./" + string.digits + string.ascii_uppercase + string.ascii_lowercase',
    'setting = "$gy$j9T$" + "".join(secrets.choice(ITOA64) for _ in range(24))',
    "",
    `PASSWORD = ${JSON.stringify(password)}`,
    "",
    "hashed = libcrypt.crypt(PASSWORD.encode(), setting.encode())",
    'if hashed is None or hashed.decode().startswith("*"):',
    "    sys.exit(",
    '        "Your libxcrypt was built without GOST support (no $gy$).\\n"',
    '        "Fedora/RHEL enable it by default; on other distros rebuild libxcrypt\\n"',
    '        "with --enable-hashes=strong,gost-yescrypt — or just use plain $y$ yescrypt."',
    "    )",
    "hashed = hashed.decode()",
    'print(f"shadow-format hash: {hashed}")',
    "",
    "assert libcrypt.crypt(PASSWORD.encode(), hashed.encode()).decode() == hashed",
    'print("verify (right password): OK")',
    'assert libcrypt.crypt(b"wrong-password", hashed.encode()).decode() != hashed',
    'print("verify (wrong password): rejected")',
  ].join("\n");
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test static/algorithms/gost-yescrypt/tests/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add static/algorithms/gost-yescrypt/
git commit -m "feat(gost-yescrypt): validators + codegen"
```

---

### Task 7: gost-yescrypt fixtures

**Files:**
- Create: `algorithms/gost-yescrypt/fixtures.json`
- Test: `static/algorithms/gost-yescrypt/tests/fixtures.test.js`
- Modify: `core/tests/test_fixtures.py` (append one test)

**Interfaces:**
- Consumes: validator keys `spot_difference`, `info` (Task 6).
- Produces: Algorithm PK 33 (`gost-yescrypt`), Lesson PK 33 (`same-engine-russian-paperwork`), steps PK 331–336. Step slug `spot-the-difference` matches Task 11's branch.

- [ ] **Step 1: Write the failing tests**

`static/algorithms/gost-yescrypt/tests/fixtures.test.js` — same skeleton as Task 5's fixtures test with these assertions: algorithm pk 33 / slug `gost-yescrypt` / family `hash` / status `live` / order 33 / intro ≤ 200; lesson pk 33 slug `same-engine-russian-paperwork`; 6 steps, PKs 331–336; ordered slugs `["intro", "streebog", "the-wrapper", "spot-the-difference", "when-to-use", "done"]`; `spot-the-difference` has kind `choose-from-list` and validator_key `spot_difference`; `done` has codegen_key `done`.

Append to `core/tests/test_fixtures.py`:

```python
@pytest.mark.django_db
def test_gost_yescrypt_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/gost-yescrypt/fixtures.json")
    from core.models import Algorithm, Lesson, Step
    a = Algorithm.objects.get(pk=33)
    assert a.slug == "gost-yescrypt" and a.family == "hash" and len(a.intro_template) <= 200
    l = Lesson.objects.get(pk=33)
    assert l.slug == "same-engine-russian-paperwork"
    steps = list(Step.objects.filter(lesson=l).order_by("order"))
    assert [s.slug for s in steps] == [
        "intro", "streebog", "the-wrapper", "spot-the-difference", "when-to-use", "done",
    ]
    assert steps[3].kind == "choose-from-list"
    assert steps[3].validator_key == "spot_difference"
```

- [ ] **Step 2: Run tests to verify they fail**

`node --test static/algorithms/gost-yescrypt/tests/fixtures.test.js` and `.venv/bin/pytest core/tests/test_fixtures.py -k gost -v` → both FAIL.

- [ ] **Step 3: Generate an honest `$y$`/`$gy$` example pair for the prompt**

The spot-the-difference prompt shows two real hash strings. Generate them with the same password and salt:

```bash
docker run --rm python:3.12-slim python -c "
import crypt
salt = 'cloakcloakcloakcloakcloa'  # 24 itoa64 chars (multiple of 4)
for prefix in ('\$y\$j9T\$', '\$gy\$j9T\$'):
    print(crypt.crypt('correct-horse-battery-staple', prefix + salt))
"
```

(Controller pre-verified 2026-08-12: both `$y$` and `$gy$` produce hashes on
`python:3.12-slim`, so the honest pair is obtainable — no fallback needed.)

If the `$gy$` line fails (Debian's libxcrypt may lack GOST), run the same command in `fedora:latest` with `python3`. If neither works, use the `$y$` real output plus a `$gy$` string with the same salt/params and a clearly different hash field, and add a footnote to the prompt: "the `$gy$` example is representative — generate your own with the Done-step script on Fedora."

- [ ] **Step 4: Write `algorithms/gost-yescrypt/fixtures.json`**

Same JSON shape as Task 5. `intro_template` (≤200 chars): `"yescrypt wrapped in Russia's national-standard Streebog HMAC. Same engine, different paperwork — the $gy$ prefix."`. Lesson title: `"GOST-yescrypt: same engine, Russian paperwork"`.

`prompt_template` content requirements:

1. **intro** — some jurisdictions legally require nationally-certified crypto (Russia: GOST standards); rather than invent a new KDF, libxcrypt ships yescrypt with a GOST-certified hash wrapped around it: prefix `$gy$`; where you'd meet it (Russian government/enterprise Linux, Astra Linux).
2. **streebog** — GOST R 34.11-2012 "Streebog", Russia's SHA-2 analog: 256/512-bit digests, Merkle–Damgård-like with an LPS (linear-permutation-substitution) round; internationally analyzed, no practical breaks; in this construction it needs only to be a solid HMAC hash — the cracking resistance still comes from yescrypt's memory-hardness.
3. **the-wrapper** — the construction, shown as a flow: `password → yescrypt(N, r, salt) → HMAC-Streebog-256 → $gy$ hash`; compliance by wrapping beats compliance by reinventing (the KDF keeps its 10 years of analysis); general lesson: this is how you swap a certified primitive into an existing design.
4. **spot-the-difference** (kind `choose-from-list`, validator `spot_difference`) — show the Task-7-Step-3 hash pair in a code block; ask "same password, same salt, same params — which field actually changed?"; the three choices are rendered as buttons by the template branch (salt / params / prefix-and-hash-bytes).
5. **when-to-use** — honest scoping: if a regulator requires GOST, `$gy$` is the answer; otherwise plain yescrypt or argon2id (no security advantage, smaller ecosystem); note some distros build libxcrypt without GOST so `$gy$` isn't universally portable.
6. **done** — recap; generated script; real-world note: `crypt(5)` lists `gy` support; Fedora/RHEL enable it at build time.

- [ ] **Step 5: Run tests to verify they pass**

`node --test static/algorithms/gost-yescrypt/tests/` and `.venv/bin/pytest core/tests/test_fixtures.py -k gost -v` → PASS.

- [ ] **Step 6: Commit**

```bash
git add algorithms/gost-yescrypt/ static/algorithms/gost-yescrypt/tests/fixtures.test.js core/tests/test_fixtures.py
git commit -m "feat(gost-yescrypt): fixtures — algorithm + lesson + 6 steps; fixture tests"
```

---

### Task 8: argon2id validators + walkthroughs

**Files:**
- Create: `static/algorithms/argon2id/validators.js`
- Test: `static/algorithms/argon2id/tests/validators.test.js`

**Interfaces:**
- Consumes: `mixMemory`, `ALLOWED_MEMORY_MIB`, `CITED_ARGON2ID_MS` from `../yescrypt/memhard_demo.js` (Task 2; cross-directory import precedent: hybrid → rsa/math.js).
- Produces: `memory_cost` writing `a2_password, a2_memory_mib, a2_blocks, a2_bytes_touched, a2_ms, a2_digest, a2_cited_real_ms`; `tuning_math(input: string|number, state)` writing `a2_tuning_mib: 64`; `info()`; `walkthroughs` covering both. Task 10's fixture uses validator keys `memory_cost` and `tuning_math`.

- [ ] **Step 1: Write the failing test**

`static/algorithms/argon2id/tests/validators.test.js`:

```js
import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

test("info always ok", () => {
  assert.deepEqual(v.info(null, {}), { ok: true, value: {} });
});

test("memory_cost happy path writes a2_* keys with argon2id cited ms", () => {
  const r = v.memory_cost({ password: "hunter2", memoryMiB: 1 }, {});
  assert.equal(r.ok, true);
  assert.equal(r.value.a2_password, "hunter2");
  assert.equal(r.value.a2_memory_mib, 1);
  assert.equal(r.value.a2_blocks, 1024);
  assert.match(r.value.a2_digest, /^[0-9a-f]{32}$/);
  assert.equal(r.value.a2_cited_real_ms, 6);
});

test("memory_cost rejects bad password and bad memory size", () => {
  assert.equal(v.memory_cost({ password: "", memoryMiB: 1 }, {}).ok, false);
  assert.equal(v.memory_cost({ password: "x", memoryMiB: 5 }, {}).ok, false);
});

test("tuning_math: 64 is correct", () => {
  const r = v.tuning_math("64", {});
  assert.equal(r.ok, true);
  assert.equal(r.value.a2_tuning_mib, 64);
});

test("tuning_math: 65536 gets the KiB-vs-MiB hint", () => {
  const r = v.tuning_math("65536", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /KiB/);
});

test("tuning_math: other numbers get the division hint; junk gets a number hint", () => {
  assert.match(v.tuning_math("128", {}).hint, /1024/);
  assert.match(v.tuning_math("banana", {}).hint, /number/i);
});

test("walkthroughs cover memory_cost and tuning_math", () => {
  assert.ok(v.walkthroughs.memory_cost({}).length >= 2);
  assert.ok(v.walkthroughs.tuning_math({}).length >= 1);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test static/algorithms/argon2id/tests/` → FAIL (module not found).

- [ ] **Step 3: Write the implementation**

`static/algorithms/argon2id/validators.js`:

```js
// argon2id lesson validators.
//
// Step 4 (feel-the-memory) — memory_cost: same toy mixer as the yescrypt
// lesson (imported from ../yescrypt/memhard_demo.js — see that header for
// what is and isn't real), writing a2_* state keys.
// Step 6 (tuning) — tuning_math: pure arithmetic on the m/t/p parameters.

import { mixMemory, ALLOWED_MEMORY_MIB, CITED_ARGON2ID_MS } from "../yescrypt/memhard_demo.js";

function checkPassword(password) {
  if (typeof password !== "string" || password.length === 0) {
    return "Type a password (any string).";
  }
  if (password.length > 200) {
    return "Keep it under 200 characters for the demo.";
  }
  for (let i = 0; i < password.length; i++) {
    const code = password.charCodeAt(i);
    if (code < 32 || code > 126) {
      return "Stick to printable ASCII for the demo.";
    }
  }
  return null;
}

export function memory_cost(input, _state) {
  const password = input?.password == null ? "" : String(input.password);
  const hint = checkPassword(password);
  if (hint) return { ok: false, hint };

  const memoryMiB = Number(input?.memoryMiB);
  if (!ALLOWED_MEMORY_MIB.includes(memoryMiB)) {
    return {
      ok: false,
      hint: `Pick a memory size from the buttons (${ALLOWED_MEMORY_MIB.join(", ")} MiB).`,
    };
  }

  const result = mixMemory(password, memoryMiB);
  if (result.allocationFailed) {
    return {
      ok: false,
      hint: "Your browser refused the memory allocation — pick a smaller size.",
    };
  }

  return {
    ok: true,
    value: {
      a2_password: password,
      a2_memory_mib: memoryMiB,
      a2_blocks: result.blocks,
      a2_bytes_touched: result.bytesTouched,
      a2_ms: result.ms,
      a2_digest: result.digestHex,
      a2_cited_real_ms: CITED_ARGON2ID_MS[memoryMiB] ?? null,
    },
  };
}

// Step 6 — the RAM bill for m=65536 KiB, t=3, p=4. The teaching point:
// m is the TOTAL memory regardless of t (extra passes over the same
// memory) and p (lanes split it, they don't multiply it).
export function tuning_math(input, _state) {
  const raw = String(input ?? "").trim();
  const v = Number(raw);
  if (raw === "" || !Number.isFinite(v)) {
    return { ok: false, hint: "Enter a number of MiB." };
  }
  if (v === 65536) {
    return { ok: false, hint: "That's the raw m value — but m counts KiB. Convert to MiB." };
  }
  if (v !== 64) {
    return {
      ok: false,
      hint: "m = 65536 KiB total. 65536 / 1024 = ? MiB. (t re-walks the same memory; p splits it into lanes — neither adds RAM.)",
    };
  }
  return { ok: true, value: { a2_tuning_mib: 64 } };
}

export function info(_input, _state) {
  return { ok: true, value: {} };
}

export const walkthroughs = {
  memory_cost: (_state) => [
    `**The construction:** argon2 fills m KiB of 1-KiB blocks (arranged in p lanes), then re-mixes them for t passes, each block mixed via Blake2b from a previous block and a reference block. In argon2**id**, reference indexes are data-independent for the first half-pass (side-channel safety), data-dependent after (cracking resistance). The widget really allocates and touches your chosen memory; the mixing function is a toy — the cited column has real argon2-cffi numbers (t=3, p=4).`,
    `**Try this:** 1 MiB vs 64 MiB — roughly linear scaling. Then compare the cited column against bcrypt's cost-12 ~260 ms: argon2id at 64 MiB costs an attacker 64 MiB of RAM *per guess in flight*, which is what melts GPU cracking farms.`,
  ],
  tuning_math: (_state) => [
    `**The three knobs:** m (memory, KiB) is the security workhorse; t (passes) adds time without RAM; p (lanes) adds parallelism within one hash. RAM per login = m, full stop. 65536 KiB / 1024 = **64 MiB** — multiply by your peak concurrent logins before you copy OWASP's numbers onto a small VPS.`,
  ],
};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test static/algorithms/argon2id/tests/` → PASS.

- [ ] **Step 5: Commit**

```bash
git add static/algorithms/argon2id/
git commit -m "feat(argon2id): validators + walkthroughs"
```

---

### Task 9: argon2id codegen

**Files:**
- Create: `static/algorithms/argon2id/codegen.js`
- Test: `static/algorithms/argon2id/tests/codegen.test.js`

**Interfaces:**
- Consumes: state keys `a2_password`, `a2_memory_mib` (Task 8).
- Produces: `full_script(state) -> string`.

- [ ] **Step 1: Write the failing test**

`static/algorithms/argon2id/tests/codegen.test.js`:

```js
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test static/algorithms/argon2id/tests/codegen.test.js` → FAIL.

- [ ] **Step 3: Write the implementation**

`static/algorithms/argon2id/codegen.js`:

```js
// Generates the Python argon2id demo shown on the Done step. Uses
// argon2-cffi — the maintained binding of the reference C implementation
// and what Django's Argon2PasswordHasher wraps.

const ALLOWED_MIB = [1, 4, 16, 64];

export function full_script(state) {
  const raw = typeof state?.a2_password === "string" ? state.a2_password : "";
  const ok = raw.length > 0 && raw.length <= 200 && /^[\x20-\x7e]+$/.test(raw);
  const password = ok ? raw : "correct-horse-battery-staple";
  const mib = ALLOWED_MIB.includes(Number(state?.a2_memory_mib))
    ? Number(state.a2_memory_mib)
    : 64;

  return [
    "# argon2id demo — generated by cloak.moosha.org",
    "#",
    "# argon2-cffi wraps the reference C implementation (and is what Django's",
    "# Argon2PasswordHasher uses). Install once:",
    "#",
    "#   pip install argon2-cffi",
    "",
    "import time",
    "",
    "from argon2 import PasswordHasher",
    "from argon2.exceptions import VerifyMismatchError",
    "",
    `PASSWORD = ${JSON.stringify(password)}`,
    "",
    "# m is in KiB; t is passes over that memory; p is parallel lanes.",
    `# Your lesson pick: ${mib} MiB. OWASP's floor is m=19 MiB, t=2, p=1;`,
    "# RFC 9106's first recommendation is m=2 GiB, t=1, p=4.",
    "ph = PasswordHasher(",
    "    time_cost=3,",
    `    memory_cost=${mib * 1024},  # KiB`,
    "    parallelism=4,",
    ")",
    "",
    "t0 = time.perf_counter()",
    "hashed = ph.hash(PASSWORD)",
    "t1 = time.perf_counter()",
    'print(f"hash: {hashed}")',
    'print(f"  took {(t1 - t0) * 1000:.1f} ms filling ' + `${mib}` + ' MiB, 3 passes, 4 lanes")',
    "",
    "# --- Verify --------------------------------------------------------",
    "# The $argon2id$v=19$m=...,t=...,p=...$salt$hash string is self-",
    "# describing, so verify() needs no separate salt or params.",
    "ph.verify(hashed, PASSWORD)",
    'print("verify (right password): OK")',
    "try:",
    '    ph.verify(hashed, "wrong-password")',
    "except VerifyMismatchError:",
    '    print("verify (wrong password): rejected")',
    "",
    "# --- Parameter upgrades -------------------------------------------",
    "# When you raise the params next year, old rows verify fine but flag",
    "# themselves for a transparent rehash on next successful login:",
    'print(f"needs rehash under current params? {ph.check_needs_rehash(hashed)}")',
  ].join("\n");
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test static/algorithms/argon2id/tests/codegen.test.js` → PASS.

- [ ] **Step 5: Sanity-run the generated Python in Docker**

```bash
node -e "import('./static/algorithms/argon2id/codegen.js').then(m => console.log(m.full_script({})))" > /tmp/a2_demo.py
docker run --rm -v /tmp/a2_demo.py:/demo.py python:3.12-slim sh -c "pip install -q argon2-cffi && python /demo.py"
```

Expected: `$argon2id$v=19$...` hash + both verify lines + `needs rehash ... False`. If Docker is unavailable, note it and move on.

- [ ] **Step 6: Commit**

```bash
git add static/algorithms/argon2id/codegen.js static/algorithms/argon2id/tests/codegen.test.js
git commit -m "feat(argon2id): codegen — argon2-cffi take-home script"
```

---

### Task 10: argon2id fixtures

**Files:**
- Create: `algorithms/argon2id/fixtures.json`
- Test: `static/algorithms/argon2id/tests/fixtures.test.js`
- Modify: `core/tests/test_fixtures.py` (append one test)

**Interfaces:**
- Consumes: validator keys `memory_cost`, `tuning_math`, `info` (Task 8).
- Produces: Algorithm PK 34 (`argon2id`), Lesson PK 34 (`the-one-the-committee-picked`), steps PK 341–348.

- [ ] **Step 1: Write the failing tests**

`static/algorithms/argon2id/tests/fixtures.test.js` — same skeleton as Task 5's with: algorithm pk 34 / slug `argon2id` / family `hash` / status `live` / order 34 / intro ≤ 200; lesson pk 34 slug `the-one-the-committee-picked`; 8 steps, PKs 341–348; ordered slugs `["intro", "why-id", "the-block-matrix", "feel-the-memory", "anatomy-of-an-argon2-hash", "tuning", "argon2-vs-the-rest", "done"]`; `feel-the-memory` kind `input-numeric` validator `memory_cost`; `tuning` kind `input-numeric` validator `tuning_math`; `done` codegen_key `done`.

Append to `core/tests/test_fixtures.py`:

```python
@pytest.mark.django_db
def test_argon2id_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/argon2id/fixtures.json")
    from core.models import Algorithm, Lesson, Step
    a = Algorithm.objects.get(pk=34)
    assert a.slug == "argon2id" and a.family == "hash" and len(a.intro_template) <= 200
    l = Lesson.objects.get(pk=34)
    assert l.slug == "the-one-the-committee-picked"
    steps = list(Step.objects.filter(lesson=l).order_by("order"))
    assert [s.slug for s in steps] == [
        "intro", "why-id", "the-block-matrix", "feel-the-memory",
        "anatomy-of-an-argon2-hash", "tuning", "argon2-vs-the-rest", "done",
    ]
    assert steps[3].validator_key == "memory_cost"
    assert steps[5].validator_key == "tuning_math"
```

- [ ] **Step 2: Run tests to verify they fail**

`node --test static/algorithms/argon2id/tests/fixtures.test.js` and `.venv/bin/pytest core/tests/test_fixtures.py -k argon2id -v` → FAIL.

- [ ] **Step 3: Write `algorithms/argon2id/fixtures.json`**

`intro_template` (≤200 chars): `"Winner of the Password Hashing Competition, first pick of OWASP. Memory-hard by design — the $argon2id$ everyone recommends."`. Lesson title: `"Argon2id: the one the committee picked"`.

`prompt_template` content requirements:

1. **intro** — Password Hashing Competition 2013–2015, 24 entries, argon2 won (Biryukov, Dinu, Khovratovich — University of Luxembourg); where you meet it: Django's recommended hasher, libsodium's `pwhash`, 1Password/Bitwarden KDF options, `$argon2id$` in shadow where enabled; RFC 9106.
2. **why-id** — the 2d/2i split: data-**d**ependent indexing (strong vs cracking, leaks timing via cache side channels) vs data-**i**ndependent (side-channel-safe, ~weaker vs TMTO attacks); argon2**id** = first half-pass 2i, rest 2d — both protections where each matters; this hybrid is what everyone standardizes on.
3. **the-block-matrix** — m KiB carved into 1-KiB blocks arranged as p lanes × columns; t passes; each block = Blake2b-based mix of the previous block and a reference block; include a small monospace diagram of a 4-lane matrix with an arrow showing a reference read crossing lanes.
4. **feel-the-memory** (kind `input-numeric`, validator `memory_cost`) — same honest-widget framing as yescrypt's step 3, with this cited table:

   | Memory | Real argon2id (argon2-cffi, t=3, p=4, 2024 laptop) |
   |---|---|
   | 1 MiB | ~6 ms |
   | 4 MiB | ~24 ms |
   | 16 MiB | ~95 ms |
   | 64 MiB | ~380 ms |

   "What to look for": linear scaling with m; contrast with bcrypt's time-only knob.
5. **anatomy-of-an-argon2-hash** — decode `$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQAAAAAAAAAAA$xkyxBHDDF9C4zHfY/y1I4YvXBvi80RJJcNGGYUZfSbo` field by field: variant, version 19 (0x13), the self-describing param list, base64 salt, base64 tag; contrast with `$y$`'s terse itoa64 encoding — same idea, chattier format.
6. **tuning** (kind `input-numeric`, validator `tuning_math`) — prompt: "A common web-backend choice is `m=65536, t=3, p=4`. **How many MiB of RAM does ONE login consume?**"; explain each knob above the question (m = total KiB; t = extra passes over the same memory; p = lanes that split it); after they answer, the hint chain teaches the KiB→MiB conversion.
7. **argon2-vs-the-rest** — decision table: argon2id (new apps, best parameters research, OWASP first choice) / bcrypt (25 years deployed, fine at cost 12+, 72-byte limit) / yescrypt (your OS already uses it; great default via crypt) / scrypt (fine, superseded by its own descendants) / PBKDF2 (FIPS-constrained environments only) / plain SHA-x (never for passwords); OWASP cheat-sheet numbers: m=19 MiB t=2 p=1 minimum, or m=64 MiB+ when you can afford it.
8. **done** — recap; generated script; real-world notes: Django `PASSWORD_HASHERS` one-liner; `check_needs_rehash` upgrade pattern; peak-concurrent-logins × m = your RAM budget.

- [ ] **Step 4: Run tests to verify they pass**

`node --test static/algorithms/argon2id/tests/` and `.venv/bin/pytest core/tests/test_fixtures.py -k argon2id -v` → PASS.

- [ ] **Step 5: Commit**

```bash
git add algorithms/argon2id/ static/algorithms/argon2id/tests/fixtures.test.js core/tests/test_fixtures.py
git commit -m "feat(argon2id): fixtures — algorithm + lesson + 8 steps; fixture tests"
```

---

### Task 11: Wizard + template integration

**Files:**
- Modify: `static/core/wizard.js` (two slug sets: `hasCustomInputBranch` SLUGS ~line 324, `MULTI_INPUT_SLUGS` ~line 377)
- Modify: `core/templates/core/lesson.html` (renderer guards ~lines 35 and 436; new input branches after the bcrypt branch ~line 406; result panels after the bcrypt result panel ~line 1055)

**Interfaces:**
- Consumes: step slugs `feel-the-memory`, `spot-the-difference` (Tasks 5, 7, 10); state keys `ys_*`, `a2_*`, `gy_choice` (Tasks 3, 6, 8); choice strings `salt` / `params` / `prefix-and-hash` (Task 6).
- Produces: working lesson pages for all three algorithms.

- [ ] **Step 1: wizard.js — register the new slugs**

In `hasCustomInputBranch`'s `SLUGS` set, after the `"time-the-cost"` entry, add:

```js
        "feel-the-memory",                    // yescrypt + argon2id (shared branch)
        "spot-the-difference",                // gost-yescrypt
```

In `MULTI_INPUT_SLUGS`, after the `"time-the-cost"` entry, add:

```js
        "feel-the-memory",            // yescrypt + argon2id: {password, memoryMiB}
```

(`spot-the-difference` is deliberately NOT in `MULTI_INPUT_SLUGS` — its buttons set `inputValue` and the validator receives a plain string.)

In `EXPLORATORY_SLUGS` (inside `check()`, ~line 410 — steps that do NOT
auto-advance on a successful check because their branches render their own
Continue button), after the `"time-the-cost",` entry, add:

```js
        "feel-the-memory",            // yescrypt + argon2id: re-runnable memory demo
        "spot-the-difference",        // gost-yescrypt: show the answer panel before advancing
```

(Discovered by live smoke testing: without this, a successful check
auto-advances and the learner never sees the result panel.)

- [ ] **Step 2: lesson.html — fix the two default-renderer guards**

Line ~35, change:

```html
<template x-if="step.kind === 'input-numeric' && step.slug !== 'pin-translation'">
```

to:

```html
<template x-if="step.kind === 'input-numeric' && step.slug !== 'pin-translation' && !hasCustomInputBranch(step)">
```

(This also fixes bcrypt's `time-the-cost` double-render — the stray default "your answer" box.)

Line ~436, change:

```html
<template x-if="step.kind === 'choose-from-list'">
```

to:

```html
<template x-if="step.kind === 'choose-from-list' && !hasCustomInputBranch(step)">
```

- [ ] **Step 3: lesson.html — add the two input branches**

Insert after the bcrypt `time-the-cost` branch (after its closing `</template>`, ~line 406):

```html
      <!-- yescrypt + argon2id: feel-the-memory — password + memory picker + Run -->
      <template x-if="step.slug === 'feel-the-memory'">
        <div style="margin-top:12px;display:flex;flex-direction:column;gap:8px;">
          <div>
            <label style="color:var(--muted);font-size:0.85em;display:block;margin-bottom:3px;">Password</label>
            <input type="text" x-model="multiInput.password" placeholder="any password" style="width:100%;font-family:ui-monospace, monospace;padding:6px 8px;">
          </div>
          <div>
            <label style="color:var(--muted);font-size:0.85em;display:block;margin-bottom:3px;">Memory to fill (MiB)</label>
            <div style="display:flex;gap:6px;flex-wrap:wrap;">
              <template x-for="n in [1, 4, 16, 64]" :key="n">
                <button :class="multiInput.memoryMiB === n ? 'btn' : 'btn secondary'" @click="multiInput.memoryMiB = n" x-text="n"></button>
              </template>
            </div>
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;">
            <button class="btn" :disabled="!multiInput.password || !multiInput.memoryMiB" @click="check()">Fill and mix the memory</button>
            <button class="btn secondary" x-show="state.ys_digest || state.a2_digest" @click="advance()">Continue →</button>
            <button x-show="hasWalkthrough()" class="btn secondary" @click="showWalkthrough()" x-text="walkthroughLabel()"></button>
          </div>
        </div>
      </template>

      <!-- gost-yescrypt: spot-the-difference — three choice buttons -->
      <template x-if="step.slug === 'spot-the-difference'">
        <div style="margin-top:12px;">
          <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <button class="btn secondary" @click="inputValue = 'salt'; check()">The salt</button>
            <button class="btn secondary" @click="inputValue = 'params'; check()">The params (j9T)</button>
            <button class="btn secondary" @click="inputValue = 'prefix-and-hash'; check()">The prefix + hash bytes</button>
          </div>
          <div style="margin-top:10px;" x-show="state.gy_choice">
            <button class="btn" @click="advance()">Continue →</button>
          </div>
        </div>
      </template>
```

- [ ] **Step 4: lesson.html — add the result panels**

Insert after the bcrypt timing-result panel (after its closing `</template>`, ~line 1055):

```html
      <!-- yescrypt: feel-the-memory result -->
      <template x-if="step.slug === 'feel-the-memory' && state.ys_digest">
        <div style="margin-top:14px;padding:12px 14px;border:1px dashed var(--border, #444);border-radius:6px;font-size:0.92em;line-height:1.6;font-family:ui-monospace, monospace;">
          <div><strong>Memory filled:</strong> <span x-text="`${state.ys_memory_mib} MiB`"></span> (<span x-text="state.ys_blocks.toLocaleString()"></span> × 1 KiB blocks)</div>
          <div><strong>Bytes touched:</strong> <span x-text="state.ys_bytes_touched.toLocaleString()"></span> (fill pass + random-read pass)</div>
          <div style="margin-top:4px;"><strong>Time:</strong> <span style="color:var(--ok, #22c55e);font-weight:600;" x-text="`${Math.round(state.ys_ms)} ms`"></span> <span style="color:var(--muted);" x-text="`(real yescrypt at this memory: ~${state.ys_cited_real_ms} ms)`"></span></div>
          <div style="margin-top:4px;word-break:break-all;"><strong>Output (toy mixer, not a real hash):</strong> <span style="color:var(--muted);" x-text="state.ys_digest"></span></div>
          <div style="margin-top:8px;color:var(--muted);font-size:0.88em;">Time scales with memory, and an attacker must pay the memory bill once per guess in flight. That's the knob bcrypt doesn't have.</div>
        </div>
      </template>

      <!-- argon2id: feel-the-memory result -->
      <template x-if="step.slug === 'feel-the-memory' && state.a2_digest">
        <div style="margin-top:14px;padding:12px 14px;border:1px dashed var(--border, #444);border-radius:6px;font-size:0.92em;line-height:1.6;font-family:ui-monospace, monospace;">
          <div><strong>Memory filled:</strong> <span x-text="`${state.a2_memory_mib} MiB`"></span> (<span x-text="state.a2_blocks.toLocaleString()"></span> × 1 KiB blocks)</div>
          <div><strong>Bytes touched:</strong> <span x-text="state.a2_bytes_touched.toLocaleString()"></span> (fill pass + random-read pass)</div>
          <div style="margin-top:4px;"><strong>Time:</strong> <span style="color:var(--ok, #22c55e);font-weight:600;" x-text="`${Math.round(state.a2_ms)} ms`"></span> <span style="color:var(--muted);" x-text="`(real argon2id at this memory: ~${state.a2_cited_real_ms} ms)`"></span></div>
          <div style="margin-top:4px;word-break:break-all;"><strong>Output (toy mixer, not a real hash):</strong> <span style="color:var(--muted);" x-text="state.a2_digest"></span></div>
          <div style="margin-top:8px;color:var(--muted);font-size:0.88em;">m KiB per guess, every guess, no shortcuts — this is why OWASP puts argon2id first.</div>
        </div>
      </template>

      <!-- gost-yescrypt: spot-the-difference result -->
      <template x-if="step.slug === 'spot-the-difference' && state.gy_choice">
        <div style="margin-top:14px;padding:12px 14px;border:1px dashed var(--border, #444);border-radius:6px;font-size:0.92em;line-height:1.6;">
          <div><strong>Right:</strong> only the method prefix (<code>$y$</code> → <code>$gy$</code>) and the final hash bytes differ.</div>
          <div style="margin-top:6px;color:var(--muted);font-size:0.9em;">Salt and params pass through untouched — the GOST wrapper swaps the outer hash function and nothing else. Compliance by wrapping, not reinventing.</div>
        </div>
      </template>
```

- [ ] **Step 5: Run the full test suites**

```bash
.venv/bin/pytest -v
for d in static/algorithms/*/tests; do node --test "$d"; done
```

Expected: all PASS (the template/wizard change has no unit tests of its own; regression cover comes from the e2e suite).

- [ ] **Step 6: Manual smoke check in the browser**

```bash
.venv/bin/python manage.py migrate
for f in algorithms/*/fixtures.json; do .venv/bin/python manage.py loaddata "$f"; done
.venv/bin/python manage.py runserver
```

Visit and screenshot each: `/algorithms/yescrypt/learn/the-default-nobody-noticed/` (run feel-the-memory at 1 MiB and 64 MiB — result panel appears, bcrypt-style stray input box absent), `/algorithms/gost-yescrypt/learn/same-engine-russian-paperwork/` (wrong choice shows hint, right choice shows result panel), `/algorithms/argon2id/learn/the-one-the-committee-picked/` (feel-the-memory + tuning step accepts 64, hints on 65536), and `/algorithms/bcrypt/learn/slowed-down-blowfish/` step 4 (regression: custom branch still renders, stray default input gone). Walk each lesson to Done and confirm the generated script renders.

- [ ] **Step 7: Commit**

```bash
git add static/core/wizard.js core/templates/core/lesson.html
git commit -m "feat(lessons): wizard + template integration for yescrypt/gost-yescrypt/argon2id"
```

---

### Task 12: "How Linux stores your password" bundle

**Files:**
- Modify: `core/bundles.py` (append one entry to `BUNDLES`)
- Test: `core/tests/test_views.py` (append one test)

**Interfaces:**
- Consumes: algorithm slugs `password-hashing`, `bcrypt`, `yescrypt`, `gost-yescrypt`, `argon2id` (existing + Tasks 5/7/10).

- [ ] **Step 1: Write the failing test**

Append to `core/tests/test_views.py`:

```python
def test_linux_passwords_bundle_resolves():
    from core.bundles import resolve_bundles
    class FakeAlgo:
        def __init__(self, slug):
            self.slug = slug
    live = {s: FakeAlgo(s) for s in
            ["password-hashing", "bcrypt", "yescrypt", "gost-yescrypt", "argon2id"]}
    bundles = resolve_bundles(live)
    b = next((x for x in bundles if x["slug"] == "how-linux-stores-your-password"), None)
    assert b is not None
    assert [a.slug for a in b["algorithms"]] == [
        "password-hashing", "bcrypt", "yescrypt", "gost-yescrypt", "argon2id",
    ]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest core/tests/test_views.py -k linux_passwords -v` → FAIL.

- [ ] **Step 3: Add the bundle entry**

Append to `BUNDLES` in `core/bundles.py` (matching the existing entries' shape; include `stations` so the journey essay page renders):

```python
    {
        "slug": "how-linux-stores-your-password",
        "title": "How Linux stores your password",
        "tagline": (
            "From `openssl passwd` to /etc/shadow's $y$, $gy$ and $argon2id$ prefixes. "
            "Why password storage got slow on purpose, then memory-hungry on purpose."
        ),
        "algorithms": ["password-hashing", "bcrypt", "yescrypt", "gost-yescrypt", "argon2id"],
        "stations": [
            {
                "algorithm": "password-hashing",
                "prose": (
                    "Run `sudo cat /etc/shadow` on any Linux box and the second field of your own row is "
                    "a little time capsule: a `$`-separated string that records which algorithm hashed your "
                    "password, with what salt, at what cost. This journey reads that string end to end.\n\n"
                    "First, the ground rules. Passwords are never stored — only hashes. But a *fast* hash "
                    "(SHA-256, MD5) is a catastrophe here: an RTX 4090 guesses tens of billions of SHA-256 "
                    "candidates per second. The survey lesson walks the fix — salting, then deliberately slow "
                    "key derivation (PBKDF2 → bcrypt → the memory-hard generation)."
                ),
            },
            {
                "algorithm": "bcrypt",
                "prose": (
                    "bcrypt (1999) made slowness *tunable*: a cost factor `c` means 2^c passes of the Blowfish "
                    "key schedule, so every +1 doubles the work for defender and attacker alike. It's the `$2b$` "
                    "prefix you'll still meet everywhere from old shadow files to modern web frameworks.\n\n"
                    "Its blind spot: bcrypt spends only *time*. 4 KiB of state fits snugly in a GPU's shared "
                    "memory, so a cracking rig still parallelizes it thousands of lanes wide. Fixing that "
                    "requires a different kind of expensive."
                ),
            },
            {
                "algorithm": "yescrypt",
                "prose": (
                    "Enter memory-hardness: force each guess to fill and re-walk megabytes, and the attacker's "
                    "10,000 cores suddenly need 10,000 × 16 MiB of low-latency RAM they don't have. yescrypt — "
                    "scrypt's descendant, hardened for the login use case — is the `$y$` your distro almost "
                    "certainly writes today (Fedora 35+, Debian 11+, Ubuntu 22.04+). The most widely deployed "
                    "password hash that almost nobody can name."
                ),
            },
            {
                "algorithm": "gost-yescrypt",
                "prose": (
                    "A short detour that teaches a big pattern: when a regulator requires nationally certified "
                    "crypto, you don't reinvent the KDF — you wrap it. `$gy$` is yescrypt's engine with an "
                    "HMAC built from Russia's Streebog hash around the output. Same salt, same params, same "
                    "memory-hardness; different paperwork."
                ),
            },
            {
                "algorithm": "argon2id",
                "prose": (
                    "And the modern default for everything that isn't /etc/shadow: Argon2id, winner of the "
                    "Password Hashing Competition, first recommendation of OWASP and RFC 9106. Its m/t/p "
                    "knobs make the memory/time/parallelism trade-offs explicit — and its `$argon2id$...` "
                    "string is self-describing, so parameter upgrades are a one-line config change plus a "
                    "rehash-on-login. Finish here and that shadow field reads like plain prose."
                ),
            },
        ],
    },
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest core/tests/test_views.py -v` → PASS (new test + no regressions).

- [ ] **Step 5: Commit**

```bash
git add core/bundles.py core/tests/test_views.py
git commit -m "feat(bundles): How Linux stores your password journey"
```

---

### Task 13: Full verification sweep

**Files:** none created — verification only.

- [ ] **Step 1: Full Python + JS test suites**

```bash
.venv/bin/pytest -v
for d in static/algorithms/*/tests; do node --test "$d"; done
```

Expected: everything PASS. Fix anything red before proceeding.

- [ ] **Step 2: Fixture idempotence (entrypoint.sh reloads every fixture on every deploy)**

```bash
.venv/bin/python manage.py migrate
for f in algorithms/*/fixtures.json; do .venv/bin/python manage.py loaddata "$f"; done
for f in algorithms/*/fixtures.json; do .venv/bin/python manage.py loaddata "$f"; done
```

Expected: second pass loads cleanly (loaddata upserts by PK — this is how prod restarts behave; a PK collision here means a wrong PK in a new fixture).

- [ ] **Step 3: Landing sanity**

Run the dev server; confirm the landing shows 34 algorithm cards, the three new cards sit at the end of the Hash & MAC family group, and the new bundle card appears with all five stations. Screenshot for the record.

- [ ] **Step 4: Commit anything outstanding, then hand off**

Deployment is NOT part of this plan — after merge, the operator runs `git push origin main && ./deploy.sh` per `docs/deploy.md`.
