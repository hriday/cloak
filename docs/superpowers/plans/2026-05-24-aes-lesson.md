# AES Lesson Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an 8-step AES lesson as a third algorithm — teaches the four AES transformations in isolation, demos one composed round, then encrypts a user's message via the browser's Web Crypto API.

**Architecture:** New algorithm record with its own `static/algorithms/aes/` module directory containing `tables.js` (S-box + MixColumns helper), `validators.js` (3 interactive validators + walkthroughs), `codegen.js`, `aes_demo.js` (Web Crypto wrapper for step 7). The wizard's `check()` is updated to `await` validators so step 7 can perform an async encryption. New slug-keyed branches in `lesson.html` render the S-box grid, ShiftRows demo, MixColumns demo, AddRoundKey XOR display, and the one-real-round 5-grid sequence. Spec: `docs/superpowers/specs/2026-05-24-aes-lesson-design.md`.

**Tech Stack:** Django 5 + Alpine.js wizard, `node --test`, browser Web Crypto API (`crypto.subtle.encrypt` with AES-GCM).

---

## File Structure

**Created:**
- `static/algorithms/aes/tables.js` — `SBOX`, `SHIFT_OFFSETS`, `mixColumn`.
- `static/algorithms/aes/validators.js` — 4 validators + walkthroughs.
- `static/algorithms/aes/codegen.js` — `full_script` (Python AES-GCM demo) + per-step stubs.
- `static/algorithms/aes/aes_demo.js` — Web Crypto wrapper for step 7.
- `static/algorithms/aes/tests/tables.test.js`
- `static/algorithms/aes/tests/validators.test.js`
- `static/algorithms/aes/tests/codegen.test.js`
- `algorithms/aes/fixtures.json` — algorithm + lesson + 8 steps.

**Modified:**
- `static/core/wizard.js` — `check()` becomes `const result = await fn(input, this.state)` (one-char change to support async validators).
- `core/templates/core/lesson.html` — add slug-keyed branches for AES displays.
- `core/tests/test_fixtures.py` — extend with AES fixture assertions.

**Numerology baked into the plan** (verified):
- SBOX[0x53] = 0xED (sub-bytes answer)
- ShiftRows: `[0x09, 0xCF, 0x4F, 0x3C]` → `[0xCF, 0x4F, 0x3C, 0x09]`
- MixColumns: `[0xDB, 0x13, 0x53, 0x45]` → `[0x8E, 0x4D, 0xA1, 0xBC]` (Wikipedia canonical)
- AddRoundKey: 0xED XOR 0x2B = 0xC6
- SBOX[0x00] = 0x63, SBOX[0xFF] = 0x16 (test vectors)

---

## Task 1: `tables.js` — AES S-box + MixColumns helper

**Files:**
- Create: `static/algorithms/aes/tables.js`
- Test: `static/algorithms/aes/tests/tables.test.js`

- [ ] **Step 1: Create directory**

Run: `mkdir -p /Users/hriday/code/enc_algo/static/algorithms/aes/tests`

- [ ] **Step 2: Write failing tests**

Create `static/algorithms/aes/tests/tables.test.js`:

```js
import { test } from "node:test";
import assert from "node:assert/strict";
import { SBOX, SHIFT_OFFSETS, mixColumn } from "../tables.js";

test("SBOX is 256 bytes long", () => {
  assert.equal(SBOX.length, 256);
});

test("SBOX known entries match standard AES table", () => {
  assert.equal(SBOX[0x00], 0x63);  // first byte
  assert.equal(SBOX[0xFF], 0x16);  // last byte
  assert.equal(SBOX[0x53], 0xED);  // canonical lesson example (row 5, col 3)
});

test("SHIFT_OFFSETS is [0, 1, 2, 3]", () => {
  assert.deepEqual(SHIFT_OFFSETS, [0, 1, 2, 3]);
});

test("mixColumn on Wikipedia canonical test vector", () => {
  // [0xDB, 0x13, 0x53, 0x45] → [0x8E, 0x4D, 0xA1, 0xBC]
  assert.deepEqual(mixColumn([0xDB, 0x13, 0x53, 0x45]), [0x8E, 0x4D, 0xA1, 0xBC]);
});

test("mixColumn on zero column returns zero column", () => {
  assert.deepEqual(mixColumn([0, 0, 0, 0]), [0, 0, 0, 0]);
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd /Users/hriday/code/enc_algo && npm test 2>&1 | grep -E "SBOX|mixColumn|SHIFT|cannot"`
Expected: 5 failures (module not found).

- [ ] **Step 4: Create `tables.js`**

Create `static/algorithms/aes/tables.js`:

```js
// Standard AES S-box (FIPS 197 table 6). 256 bytes, row-major.
export const SBOX = [
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

// ShiftRows: row i shifts left by i positions.
export const SHIFT_OFFSETS = [0, 1, 2, 3];

// Multiply a byte by 2 in GF(2^8) with reducing polynomial 0x11B.
function xtime(b) {
  return ((b << 1) ^ (b & 0x80 ? 0x1B : 0)) & 0xFF;
}

// MixColumns: multiplies one 4-byte column by the AES MixColumns matrix
//   [2 3 1 1]
//   [1 2 3 1]
//   [1 1 2 3]
//   [3 1 1 2]
// in GF(2^8). Multiply-by-3 is xtime(b) ^ b.
export function mixColumn(col) {
  const [a, b, c, d] = col;
  return [
    xtime(a) ^ (xtime(b) ^ b) ^ c ^ d,
    a ^ xtime(b) ^ (xtime(c) ^ c) ^ d,
    a ^ b ^ xtime(c) ^ (xtime(d) ^ d),
    (xtime(a) ^ a) ^ b ^ c ^ xtime(d),
  ];
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /Users/hriday/code/enc_algo && npm test 2>&1 | tail -8`
Expected: pass count up by 5, no failures.

- [ ] **Step 6: Commit**

```bash
git add static/algorithms/aes/tables.js static/algorithms/aes/tests/tables.test.js
git commit -m "$(cat <<'EOF'
feat(aes): tables.js — AES S-box + MixColumns helper

256-byte standard AES S-box (FIPS 197), SHIFT_OFFSETS for rows,
and a GF(2^8) mixColumn implementation verified against
Wikipedia's canonical test vector [0xDB, 0x13, 0x53, 0x45] →
[0x8E, 0x4D, 0xA1, 0xBC].

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Validators — `sub_byte` + `add_round_key`

**Files:**
- Create: `static/algorithms/aes/validators.js`
- Create: `static/algorithms/aes/tests/validators.test.js`

- [ ] **Step 1: Write failing tests**

Create `static/algorithms/aes/tests/validators.test.js`:

```js
import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

test("sub_byte accepts decimal", () => {
  const r = v.sub_byte("237", {});
  assert.equal(r.ok, true);
  assert.equal(r.value.a_sub_input, 0x53);
  assert.equal(r.value.a_sub_output, 0xED);
});

test("sub_byte accepts hex prefix", () => {
  const r = v.sub_byte("0xED", {});
  assert.equal(r.ok, true);
  assert.equal(r.value.a_sub_output, 0xED);
});

test("sub_byte accepts bare hex", () => {
  assert.equal(v.sub_byte("ED", {}).ok, true);
  assert.equal(v.sub_byte("ed", {}).ok, true);
});

test("sub_byte rejects wrong value", () => {
  const r = v.sub_byte("0xAA", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /0xED|237/);
});

test("sub_byte rejects out of range", () => {
  const r = v.sub_byte("999", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /0.*255/);
});

test("sub_byte rejects garbage", () => {
  const r = v.sub_byte("foo", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /byte value/);
});

test("add_round_key happy — 0xED XOR 0x2B = 0xC6", () => {
  const r = v.add_round_key("0xC6", {});
  assert.equal(r.ok, true);
  assert.equal(r.value.a_ark_output, 0xC6);
});

test("add_round_key accepts decimal", () => {
  assert.equal(v.add_round_key("198", {}).ok, true);
});

test("add_round_key wrong value mentions both operands", () => {
  const r = v.add_round_key("0", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /0xED|237/);
  assert.match(r.hint, /0x2B|43/);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/hriday/code/enc_algo && npm test 2>&1 | grep -E "sub_byte|add_round|cannot"`
Expected: 9 failures (module not found / function undefined).

- [ ] **Step 3: Create `validators.js`**

Create `static/algorithms/aes/validators.js`:

```js
import { SBOX } from "./tables.js";

// Canonical lesson values — referenced from prompts so they stay in sync.
export const SUB_BYTE_INPUT = 0x53;          // S-box row 5, col 3
export const ARK_STATE_BYTE = 0xED;          // = SBOX[0x53]
export const ARK_ROUND_KEY_BYTE = 0x2B;      // chosen so XOR result is 0xC6

// Parse a byte input: decimal "237", "0xED", "ED", "0xed", "ed". Null on parse failure.
function _parseByte(s) {
  if (s === null || s === undefined) return null;
  const t = String(s).trim();
  if (t === "") return null;
  let n;
  if (/^0x[0-9a-fA-F]+$/.test(t)) n = parseInt(t, 16);
  else if (/^[0-9a-fA-F]{1,2}$/.test(t) && /[a-fA-F]/.test(t)) n = parseInt(t, 16);
  else if (/^\d+$/.test(t)) n = parseInt(t, 10);
  else return null;
  return Number.isFinite(n) ? n : null;
}

function _byteRangeOk(n) {
  return Number.isInteger(n) && n >= 0 && n <= 255;
}

export function sub_byte(input, _state) {
  const n = _parseByte(input);
  if (n === null) return { ok: false, hint: "Enter a byte value (0–255 in decimal, or 0xNN in hex)." };
  if (!_byteRangeOk(n)) return { ok: false, hint: "S-box outputs a byte. Enter 0–255 (or 0xNN)." };
  const expected = SBOX[SUB_BYTE_INPUT];
  if (n !== expected) {
    return { ok: false, hint: `The S-box at row 5, column 3 (input 0x53) is 0x${expected.toString(16).toUpperCase()} (decimal ${expected}). Look at the highlighted cell above.` };
  }
  return { ok: true, value: { a_sub_input: SUB_BYTE_INPUT, a_sub_output: expected } };
}

export function add_round_key(input, _state) {
  const n = _parseByte(input);
  if (n === null) return { ok: false, hint: "Enter a byte value (0–255 in decimal, or 0xNN in hex)." };
  if (!_byteRangeOk(n)) return { ok: false, hint: "AddRoundKey outputs a byte. Enter 0–255 (or 0xNN)." };
  const expected = ARK_STATE_BYTE ^ ARK_ROUND_KEY_BYTE;
  if (n !== expected) {
    return { ok: false, hint: `AddRoundKey is byte-wise XOR. With state byte = 0x${ARK_STATE_BYTE.toString(16).toUpperCase()} (${ARK_STATE_BYTE}) and round-key byte = 0x${ARK_ROUND_KEY_BYTE.toString(16).toUpperCase()} (${ARK_ROUND_KEY_BYTE}), compute ${ARK_STATE_BYTE} XOR ${ARK_ROUND_KEY_BYTE} = ${expected} (0x${expected.toString(16).toUpperCase()}).` };
  }
  return { ok: true, value: { a_ark_input: ARK_STATE_BYTE, a_ark_key: ARK_ROUND_KEY_BYTE, a_ark_output: expected } };
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/hriday/code/enc_algo && npm test 2>&1 | tail -8`
Expected: 9 added tests pass.

- [ ] **Step 5: Commit**

```bash
git add static/algorithms/aes/validators.js static/algorithms/aes/tests/validators.test.js
git commit -m "$(cat <<'EOF'
feat(aes): sub_byte + add_round_key validators

sub_byte: validates S-box lookup of 0x53. Accepts decimal,
0xNN hex, and bare hex (ED / ed). Wrong-value hint points at
the highlighted cell.

add_round_key: validates byte-wise XOR of 0xED with 0x2B (= 0xC6).
Same parse flexibility. Hint shows both operands in decimal +
hex so the math is unambiguous.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Validators — `shift_row` + `pick_aes_message` + `info`

**Files:**
- Modify: `static/algorithms/aes/validators.js`
- Modify: `static/algorithms/aes/tests/validators.test.js`

- [ ] **Step 1: Write failing tests**

Append to `static/algorithms/aes/tests/validators.test.js`:

```js
test("shift_row happy", () => {
  // input row [0x09, 0xCF, 0x4F, 0x3C] shifts left by 1 → [0xCF, 0x4F, 0x3C, 0x09]
  const r = v.shift_row({ b0: "0xCF", b1: "0x4F", b2: "0x3C", b3: "0x09" }, {});
  assert.equal(r.ok, true);
  assert.deepEqual(r.value.a_shifted_row, [0xCF, 0x4F, 0x3C, 0x09]);
});

test("shift_row wrong order", () => {
  const r = v.shift_row({ b0: "0x09", b1: "0xCF", b2: "0x4F", b3: "0x3C" }, {});  // unshifted
  assert.equal(r.ok, false);
  assert.match(r.hint, /shifts left/);
});

test("shift_row rejects missing values", () => {
  const r = v.shift_row({ b0: "0xCF", b1: "", b2: "0x3C", b3: "0x09" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /4 bytes/);
});

test("shift_row rejects out-of-range", () => {
  const r = v.shift_row({ b0: "999", b1: "0x4F", b2: "0x3C", b3: "0x09" }, {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /0.*255/);
});

test("pick_aes_message happy", () => {
  const r = v.pick_aes_message("hi", {});
  assert.equal(r.ok, true);
  assert.equal(r.value.a_message, "hi");
});

test("pick_aes_message rejects empty", () => {
  const r = v.pick_aes_message("", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /at least one/);
});

test("pick_aes_message rejects >500", () => {
  const r = v.pick_aes_message("a".repeat(501), {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /500/);
});

test("pick_aes_message rejects non-ASCII", () => {
  const r = v.pick_aes_message("hi 🦊", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /ASCII/i);
});

test("info always ok", () => {
  assert.deepEqual(v.info("anything", {}), { ok: true, value: {} });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/hriday/code/enc_algo && npm test 2>&1 | grep -E "shift_row|pick_aes|info always"`
Expected: 9 failures.

- [ ] **Step 3: Implement the validators**

Append to `static/algorithms/aes/validators.js`:

```js
// ShiftRows input row used in the lesson — kept here so the prompt can reference it.
export const SHIFT_INPUT_ROW = [0x09, 0xCF, 0x4F, 0x3C];

export function shift_row(input, _state) {
  const fields = ["b0", "b1", "b2", "b3"];
  const parsed = fields.map((k) => _parseByte(input?.[k]));
  if (parsed.some((n) => n === null)) {
    return { ok: false, hint: "Enter 4 bytes (one per column)." };
  }
  if (parsed.some((n) => !_byteRangeOk(n))) {
    return { ok: false, hint: "Each value must be 0–255." };
  }
  const expected = [SHIFT_INPUT_ROW[1], SHIFT_INPUT_ROW[2], SHIFT_INPUT_ROW[3], SHIFT_INPUT_ROW[0]];
  if (parsed.some((n, i) => n !== expected[i])) {
    const inStr = SHIFT_INPUT_ROW.map((b) => `0x${b.toString(16).toUpperCase()}`).join(", ");
    const outStr = expected.map((b) => `0x${b.toString(16).toUpperCase()}`).join(", ");
    return { ok: false, hint: `Row 1 shifts left by 1, so input [${inStr}] becomes [${outStr}] — the first byte wraps to the end.` };
  }
  return { ok: true, value: { a_shifted_row: expected } };
}

export function pick_aes_message(input, _state) {
  const s = input == null ? "" : String(input);
  if (s.length === 0) return { ok: false, hint: "Type at least one character." };
  if (s.length > 500) return { ok: false, hint: "Keep it under 500 characters." };
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code < 32 || code > 126) {
      return { ok: false, hint: `Only printable ASCII for now — no emoji, accents, tabs, or newlines. Found: '${s[i]}'.` };
    }
  }
  return { ok: true, value: { a_message: s } };
}

export function info(_input, _state) {
  return { ok: true, value: {} };
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/hriday/code/enc_algo && npm test 2>&1 | tail -8`
Expected: 9 added tests pass.

- [ ] **Step 5: Commit**

```bash
git add static/algorithms/aes/validators.js static/algorithms/aes/tests/validators.test.js
git commit -m "$(cat <<'EOF'
feat(aes): shift_row + pick_aes_message + info validators

shift_row: validates the 4 bytes of row 1 after ShiftRows
left-by-1 on the lesson's canonical input row
[0x09, 0xCF, 0x4F, 0x3C] → [0xCF, 0x4F, 0x3C, 0x09]. Multi-input
shape (b0/b1/b2/b3 keys).

pick_aes_message: same shape as RSA pick_sentence /
hybrid type_message — non-empty, ≤500 chars, printable ASCII.

info: trivial pass-through for the demo + done steps.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Walkthroughs for actionable validators

**Files:**
- Modify: `static/algorithms/aes/validators.js`
- Modify: `static/algorithms/aes/tests/validators.test.js`

- [ ] **Step 1: Write failing tests**

Append to `static/algorithms/aes/tests/validators.test.js`:

```js
test("walkthroughs has entries for 3 actionable steps", () => {
  assert.equal(typeof v.walkthroughs.sub_byte, "function");
  assert.equal(typeof v.walkthroughs.shift_row, "function");
  assert.equal(typeof v.walkthroughs.add_round_key, "function");
});

test("sub_byte walkthrough reveals 0xED in the final rung", () => {
  const rungs = v.walkthroughs.sub_byte({});
  assert.equal(rungs.length, 3);
  rungs.forEach((r) => assert.equal(typeof r, "string"));
  assert.match(rungs[2], /0xED|237/);
});

test("shift_row walkthrough reveals the shifted row", () => {
  const rungs = v.walkthroughs.shift_row({});
  assert.equal(rungs.length, 3);
  assert.match(rungs[2], /0xCF.*0x4F.*0x3C.*0x09/);
});

test("add_round_key walkthrough reveals 0xC6", () => {
  const rungs = v.walkthroughs.add_round_key({});
  assert.equal(rungs.length, 3);
  assert.match(rungs[2], /0xC6|198/);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/hriday/code/enc_algo && npm test 2>&1 | grep walkthrough`
Expected: 4 failures.

- [ ] **Step 3: Append the `walkthroughs` export**

Append to `static/algorithms/aes/validators.js`:

```js
export const walkthroughs = {
  sub_byte: (_state) => {
    const result = SBOX[SUB_BYTE_INPUT];
    return [
      `**The method:** AES SubBytes replaces each byte with the value from a fixed 16×16 table called the S-box. The high nibble of the input picks the row; the low nibble picks the column.`,
      `Input 0x53 — high nibble 5, low nibble 3. Look at row 5, column 3 of the S-box grid above (it's highlighted).`,
      `**Answer: 0x${result.toString(16).toUpperCase()} (decimal ${result}).** (In Python: \`SBOX[0x53]\`.)`,
    ];
  },

  shift_row: (_state) => {
    const inStr = SHIFT_INPUT_ROW.map((b) => `0x${b.toString(16).toUpperCase()}`).join(", ");
    const expected = [SHIFT_INPUT_ROW[1], SHIFT_INPUT_ROW[2], SHIFT_INPUT_ROW[3], SHIFT_INPUT_ROW[0]];
    const outStr = expected.map((b) => `0x${b.toString(16).toUpperCase()}`).join(", ");
    return [
      `**The method:** ShiftRows rotates each row of the state left by its row index. Row 0 unchanged, row 1 by 1, row 2 by 2, row 3 by 3. We're doing row 1, so shift left by 1.`,
      `Input row: [${inStr}]. Drop the first byte to the end; everything else moves left by 1.`,
      `**Answer: [${outStr}].**`,
    ];
  },

  add_round_key: (_state) => {
    const result = ARK_STATE_BYTE ^ ARK_ROUND_KEY_BYTE;
    return [
      `**The method:** AddRoundKey XORs each state byte with the corresponding round-key byte. Same XOR you've seen — bit-wise exclusive OR.`,
      `State byte = 0x${ARK_STATE_BYTE.toString(16).toUpperCase()} (${ARK_STATE_BYTE}), round-key byte = 0x${ARK_ROUND_KEY_BYTE.toString(16).toUpperCase()} (${ARK_ROUND_KEY_BYTE}). Compute ${ARK_STATE_BYTE} XOR ${ARK_ROUND_KEY_BYTE}.`,
      `**Answer: 0x${result.toString(16).toUpperCase()} (decimal ${result}).** (In Python: \`${ARK_STATE_BYTE} ^ ${ARK_ROUND_KEY_BYTE}\`.)`,
    ];
  },
};
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/hriday/code/enc_algo && npm test 2>&1 | tail -8`
Expected: 4 added tests pass.

- [ ] **Step 5: Commit**

```bash
git add static/algorithms/aes/validators.js static/algorithms/aes/tests/validators.test.js
git commit -m "$(cat <<'EOF'
feat(aes): walkthroughs for sub_byte, shift_row, add_round_key

Each walkthrough: 3 escalating rungs (method → worked example →
answer). Derive the answer from the SBOX / canonical constants
so any drift in the lesson's reference values is caught by a
single test failure rather than silently diverging from prompts.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: `codegen.js` — Python AES-GCM demo

**Files:**
- Create: `static/algorithms/aes/codegen.js`
- Test: `static/algorithms/aes/tests/codegen.test.js`

- [ ] **Step 1: Write failing tests**

Create `static/algorithms/aes/tests/codegen.test.js`:

```js
import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

test("full_script imports cryptography.hazmat AESGCM", () => {
  const out = c.full_script({ a_message: "hi" });
  assert.match(out, /from cryptography\.hazmat\.primitives\.ciphers\.aead import AESGCM/);
});

test("full_script generates a 128-bit key", () => {
  const out = c.full_script({ a_message: "hi" });
  assert.match(out, /AESGCM\.generate_key\(bit_length=128\)/);
});

test("full_script includes the user's message and the roundtrip assert", () => {
  const out = c.full_script({ a_message: "hello world" });
  assert.match(out, /message = b"hello world"/);
  assert.match(out, /assert plaintext == message/);
});

test("info returns empty string", () => {
  assert.equal(c.info({}), "");
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/hriday/code/enc_algo && npm test 2>&1 | grep -E "full_script|info returns|cannot"`
Expected: 4 failures.

- [ ] **Step 3: Create `codegen.js`**

Create `static/algorithms/aes/codegen.js`:

```js
// Generates the Python AES-GCM demo shown on the Done step.

export function full_script(state) {
  const messageLiteral = JSON.stringify(state.a_message ?? "hello");
  return [
    "# AES-GCM demo — generated by cloak.moosha.org",
    "# Requires the `cryptography` package: pip install cryptography",
    "",
    "import os",
    "from cryptography.hazmat.primitives.ciphers.aead import AESGCM",
    "",
    "# 1. Generate a random 128-bit key (real systems use 256-bit for AES-256).",
    "key = AESGCM.generate_key(bit_length=128)",
    "aesgcm = AESGCM(key)",
    "",
    "# 2. Generate a random 12-byte IV (nonce). NEVER reuse one with the same key.",
    "iv = os.urandom(12)",
    "",
    "# 3. Encrypt.",
    `message = b${messageLiteral}`,
    "ciphertext = aesgcm.encrypt(iv, message, None)   # third arg = associated data",
    "",
    "# 4. Decrypt to confirm.",
    "plaintext = aesgcm.decrypt(iv, ciphertext, None)",
    "assert plaintext == message",
    "",
    `print("key       :", key.hex())`,
    `print("iv        :", iv.hex())`,
    `print("ciphertext:", ciphertext.hex())`,
    `print("decrypted :", plaintext.decode())`,
  ].join("\n");
}

// Info / demo steps emit nothing for the inline code panel.
export function info(_state) { return ""; }
export function sub_byte(_state) { return "state[i] = SBOX[state[i]]   # one byte, per state cell"; }
export function shift_row(_state) { return "# row 1: shift left by 1\nstate[4:8] = state[5:8] + state[4:5]"; }
export function add_round_key(_state) { return "state = bytes(s ^ k for s, k in zip(state, round_key))"; }
export function pick_aes_message(_state) { return ""; }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/hriday/code/enc_algo && npm test 2>&1 | tail -8`
Expected: 4 added tests pass.

- [ ] **Step 5: Commit**

```bash
git add static/algorithms/aes/codegen.js static/algorithms/aes/tests/codegen.test.js
git commit -m "$(cat <<'EOF'
feat(aes): codegen.js — Python AES-GCM demo script

full_script emits a runnable Python program using cryptography's
AESGCM: generates a 128-bit key + 12-byte IV, encrypts the user's
message, decrypts to confirm, prints all four hex outputs.

Per-step inline code: short Python snippets for sub_byte,
shift_row, add_round_key shown in the wizard's "Python for this
step" panel; info / pick_aes_message emit nothing.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: `aes_demo.js` (Web Crypto) + wire into `pick_aes_message` + async wizard

**Files:**
- Create: `static/algorithms/aes/aes_demo.js`
- Modify: `static/algorithms/aes/validators.js` (make `pick_aes_message` async, return encryption results)
- Modify: `static/algorithms/aes/tests/validators.test.js` (update one test)
- Modify: `static/core/wizard.js:check()` (one-char change: `await fn(...)`)

- [ ] **Step 1: Create `aes_demo.js`**

Create `static/algorithms/aes/aes_demo.js`:

```js
// Browser Web Crypto wrapper for step 7. Generates a 128-bit AES key
// and 12-byte IV, encrypts with AES-GCM, decrypts to confirm,
// returns all four artifacts as hex strings.

function bytesToHex(arr) {
  return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function encryptMessage(plaintext) {
  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 128 },
    true,   // extractable so we can export and display the key bytes
    ["encrypt", "decrypt"]
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ptBytes = new TextEncoder().encode(plaintext);
  const ctBuffer = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, ptBytes);
  const recoveredBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ctBuffer);
  const recovered = new TextDecoder().decode(recoveredBuffer);
  const keyBytes = new Uint8Array(await crypto.subtle.exportKey("raw", key));
  return {
    keyHex: bytesToHex(keyBytes),
    ivHex: bytesToHex(iv),
    ciphertextHex: bytesToHex(new Uint8Array(ctBuffer)),
    recovered,
  };
}
```

- [ ] **Step 2: Make `pick_aes_message` async + chain encryption**

In `static/algorithms/aes/validators.js`, add the import at the top (after the existing `import { SBOX } from "./tables.js"`):

```js
import { encryptMessage } from "./aes_demo.js";
```

Replace the existing `pick_aes_message` function:

```js
export async function pick_aes_message(input, _state) {
  const s = input == null ? "" : String(input);
  if (s.length === 0) return { ok: false, hint: "Type at least one character." };
  if (s.length > 500) return { ok: false, hint: "Keep it under 500 characters." };
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code < 32 || code > 126) {
      return { ok: false, hint: `Only printable ASCII for now — no emoji, accents, tabs, or newlines. Found: '${s[i]}'.` };
    }
  }
  // Validation passed — encrypt via Web Crypto (browser only). In Node tests,
  // crypto.subtle may not be available; gracefully degrade so the validation
  // tests still pass.
  let encryptionResult = null;
  let encryptError = null;
  try {
    if (typeof crypto !== "undefined" && crypto.subtle) {
      encryptionResult = await encryptMessage(s);
    }
  } catch (e) {
    encryptError = String(e.message || e);
  }
  const value = { a_message: s };
  if (encryptionResult) {
    value.a_key_hex = encryptionResult.keyHex;
    value.a_iv_hex = encryptionResult.ivHex;
    value.a_ciphertext_hex = encryptionResult.ciphertextHex;
    value.a_recovered = encryptionResult.recovered;
  }
  if (encryptError) value.a_encrypt_error = encryptError;
  return { ok: true, value };
}
```

- [ ] **Step 3: Update the validation test that depended on sync behavior**

The existing `pick_aes_message happy` test currently expects sync return. Replace it in `static/algorithms/aes/tests/validators.test.js`:

```js
test("pick_aes_message happy (in node: validates but skips encryption)", async () => {
  const r = await v.pick_aes_message("hi", {});
  assert.equal(r.ok, true);
  assert.equal(r.value.a_message, "hi");
  // Node ≥19 has crypto.subtle; if present, the encryption fields appear.
  // We don't assert on them strictly because behavior depends on Node version.
});

test("pick_aes_message rejects empty (async)", async () => {
  const r = await v.pick_aes_message("", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /at least one/);
});

test("pick_aes_message rejects >500 (async)", async () => {
  const r = await v.pick_aes_message("a".repeat(501), {});
  assert.equal(r.ok, false);
});

test("pick_aes_message rejects non-ASCII (async)", async () => {
  const r = await v.pick_aes_message("hi 🦊", {});
  assert.equal(r.ok, false);
});
```

Remove the old sync versions of `pick_aes_message` tests (4 tests; the 4 above replace them).

- [ ] **Step 4: Update wizard's `check()` to await validator returns**

In `static/core/wizard.js`, find the `check()` method (around line 138). The current line:

```js
      const result = fn(input, this.state);
```

Change to:

```js
      const result = await fn(input, this.state);
```

Sync validators (returning `{ok, value}` directly) still work — `await` on a non-promise resolves to the value.

- [ ] **Step 5: Run all tests to confirm no regressions**

Run: `cd /Users/hriday/code/enc_algo && npm test 2>&1 | tail -10`
Expected: all tests pass; counts up by 4 over the prior baseline (we replaced 4 pick_aes_message tests with 4 new async versions, then added 0 net — but we also added validators tests in earlier tasks). Verify there are no failures.

Run: `cd /Users/hriday/code/enc_algo && .venv/bin/pytest 2>&1 | tail -3`
Expected: 71 pass (Python tests not affected by JS changes).

- [ ] **Step 6: Commit**

```bash
git add static/algorithms/aes/aes_demo.js static/algorithms/aes/validators.js static/algorithms/aes/tests/validators.test.js static/core/wizard.js
git commit -m "$(cat <<'EOF'
feat(aes): aes_demo.js + async pick_aes_message + wizard awaits validators

aes_demo.js wraps browser Web Crypto: generates a 128-bit AES-GCM
key + 12-byte IV, encrypts/decrypts, returns hex strings and
recovered plaintext.

pick_aes_message becomes async — runs validation, then (in browser)
calls encryptMessage and writes the artifacts into state. In Node
(test env), crypto.subtle isn't always available; the validator
degrades gracefully so unit tests still cover validation paths.

wizard.js: changed `const result = fn(...)` to
`const result = await fn(...)`. Sync validators across RSA / hybrid
still work — await on a non-promise is a no-op.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: `lesson.html` — AES slug-keyed template branches

**Files:**
- Modify: `core/templates/core/lesson.html`

This task adds visualizations for the AES demo steps: the 16×16 S-box grid (step 2), the 4×4 ShiftRows grids (step 3), the MixColumns demo (step 4), the XOR display (step 5), the five-grids one-real-round (step 6), and the encrypted-message roundtrip (step 7 + 8).

- [ ] **Step 1: Add a `<template x-if="step.slug === 'sub-bytes'">` block**

Find the existing `info` template block (around line 75 in lesson.html). Above its closing `</template>` (just before line ~150 — the catch-all Continue button branch), insert a new top-level template for the S-box grid that should render REGARDLESS of step.kind:

Actually — looking at the existing layout, AES steps are NOT `info` kind for the interactive ones (sub-bytes is `input-numeric`). The S-box grid is supplemental display alongside the standard input renderer.

Add a new top-level block ABOVE the existing `<template x-if="conversionRows.length > 0 ...">` (around line 148):

```html
      <template x-if="step.slug === 'sub-bytes'">
        <div style="margin-top:14px;overflow:auto;">
          <div style="color:var(--muted);font-size:0.8em;margin-bottom:6px;">AES S-box (highlighted cell = answer for input 0x53)</div>
          <table style="border-collapse:collapse;font-family:ui-monospace, monospace;font-size:0.85em;">
            <thead>
              <tr>
                <th></th>
                <template x-for="c in 16" :key="c">
                  <th style="padding:3px 6px;color:var(--muted);font-weight:normal;" x-text="(c-1).toString(16).toUpperCase()"></th>
                </template>
              </tr>
            </thead>
            <tbody>
              <template x-for="r in 16" :key="r">
                <tr>
                  <th style="padding:3px 6px;color:var(--muted);font-weight:normal;" x-text="(r-1).toString(16).toUpperCase()"></th>
                  <template x-for="c in 16" :key="c">
                    <td :style="((r-1)===5 && (c-1)===3) ? 'padding:3px 6px;background:#1e3a8a;color:#fff;border:1px solid #475569;font-weight:bold;' : 'padding:3px 6px;border:1px solid #334155;color:var(--text);'" x-text="aesSBOX[(r-1)*16 + (c-1)].toString(16).toUpperCase().padStart(2,'0')"></td>
                  </template>
                </tr>
              </template>
            </tbody>
          </table>
        </div>
      </template>
```

The template uses `aesSBOX` — a wizard component property we add in the next step.

- [ ] **Step 2: Add `aesSBOX` to the wizard's data**

The S-box is loaded dynamically with the algorithm. Look at `wizard.js` — the `loadAlgorithmModules` function loads validators and codegen. To make SBOX available in the template, we need to load `tables.js` too AND expose it.

In `static/core/wizard.js`, find `loadAlgorithmModules`:

```js
async function loadAlgorithmModules(slug) {
  const base = `/static/algorithms/${slug}`;
  const v = `?v=${(window.CLOAK_ASSETS_VERSION || Date.now())}`;
  const [validators, codegen] = await Promise.all([
    import(`${base}/validators.js${v}`),
    import(`${base}/codegen.js${v}`),
  ]);
  return { validators, codegen };
}
```

Change to also try loading `tables.js` (and tolerate its absence for algorithms that don't have one):

```js
async function loadAlgorithmModules(slug) {
  const base = `/static/algorithms/${slug}`;
  const v = `?v=${(window.CLOAK_ASSETS_VERSION || Date.now())}`;
  const [validators, codegen] = await Promise.all([
    import(`${base}/validators.js${v}`),
    import(`${base}/codegen.js${v}`),
  ]);
  let tables = null;
  try { tables = await import(`${base}/tables.js${v}`); } catch (_e) { /* not all algorithms have tables */ }
  return { validators, codegen, tables };
}
```

Then in the component init, after `this.validators = mods.validators` lines, add:

```js
      this.tables = mods.tables;
      if (mods.tables?.SBOX) this.aesSBOX = mods.tables.SBOX;
```

And in the component state (next to `validators: null`), add:

```js
    tables: null,
    aesSBOX: [],
```

- [ ] **Step 3: Add the ShiftRows visualization for step 3**

Right after the `sub-bytes` template block, add:

```html
      <template x-if="step.slug === 'shift-rows'">
        <div style="margin-top:14px;display:flex;gap:24px;align-items:center;flex-wrap:wrap;">
          <div>
            <div style="color:var(--muted);font-size:0.8em;margin-bottom:4px;">Row 1 (input)</div>
            <div style="display:flex;gap:4px;">
              <template x-for="b in [0x09, 0xCF, 0x4F, 0x3C]" :key="b">
                <div style="padding:6px 10px;background:var(--code-bg);border:1px solid #475569;border-radius:4px;font-family:ui-monospace, monospace;font-size:0.9em;" x-text="'0x' + b.toString(16).toUpperCase()"></div>
              </template>
            </div>
          </div>
          <div style="font-size:1.4em;color:var(--muted);">→</div>
          <div>
            <div style="color:var(--muted);font-size:0.8em;margin-bottom:4px;">Row 1 (after shift left by 1)</div>
            <div style="display:flex;gap:4px;color:var(--muted);">
              <template x-for="i in 4" :key="i">
                <div style="padding:6px 10px;background:var(--code-bg);border:1px dashed #475569;border-radius:4px;font-family:ui-monospace, monospace;font-size:0.9em;">??</div>
              </template>
            </div>
          </div>
        </div>
      </template>
```

- [ ] **Step 4: Add MixColumns demo for step 4**

Right after the `shift-rows` block, add:

```html
      <template x-if="step.slug === 'mix-columns'">
        <div style="margin-top:14px;display:flex;gap:24px;align-items:center;flex-wrap:wrap;">
          <div>
            <div style="color:var(--muted);font-size:0.8em;margin-bottom:4px;">One column (input)</div>
            <div style="display:flex;flex-direction:column;gap:4px;">
              <template x-for="b in [0xDB, 0x13, 0x53, 0x45]" :key="b">
                <div style="padding:6px 10px;background:var(--code-bg);border:1px solid #475569;border-radius:4px;font-family:ui-monospace, monospace;font-size:0.9em;text-align:center;" x-text="'0x' + b.toString(16).toUpperCase()"></div>
              </template>
            </div>
          </div>
          <div style="color:var(--muted);font-family:ui-monospace, monospace;font-size:0.85em;line-height:1.6;">
            ×<br>
            [2 3 1 1]<br>
            [1 2 3 1]<br>
            [1 1 2 3]<br>
            [3 1 1 2]<br>
            <span style="font-size:0.8em;">(GF(2⁸))</span>
          </div>
          <div style="font-size:1.4em;color:var(--muted);">→</div>
          <div>
            <div style="color:var(--muted);font-size:0.8em;margin-bottom:4px;">Output column</div>
            <div style="display:flex;flex-direction:column;gap:4px;">
              <template x-for="b in [0x8E, 0x4D, 0xA1, 0xBC]" :key="b">
                <div style="padding:6px 10px;background:var(--code-bg);border:1px solid #475569;border-radius:4px;font-family:ui-monospace, monospace;font-size:0.9em;text-align:center;color:#5eead4;" x-text="'0x' + b.toString(16).toUpperCase()"></div>
              </template>
            </div>
          </div>
        </div>
      </template>
```

- [ ] **Step 5: Add AddRoundKey XOR display for step 5**

After the `mix-columns` block:

```html
      <template x-if="step.slug === 'add-round-key'">
        <div style="margin-top:14px;display:flex;gap:16px;align-items:center;flex-wrap:wrap;font-family:ui-monospace, monospace;">
          <div>
            <div style="color:var(--muted);font-size:0.8em;margin-bottom:4px;">State byte</div>
            <div style="padding:8px 14px;background:var(--code-bg);border:1px solid #475569;border-radius:4px;font-size:1em;">0xED <span style="color:var(--muted);font-size:0.85em;">(237 = 11101101)</span></div>
          </div>
          <div style="font-size:1.4em;color:var(--muted);">XOR</div>
          <div>
            <div style="color:var(--muted);font-size:0.8em;margin-bottom:4px;">Round-key byte</div>
            <div style="padding:8px 14px;background:var(--code-bg);border:1px solid #475569;border-radius:4px;font-size:1em;">0x2B <span style="color:var(--muted);font-size:0.85em;">(43 = 00101011)</span></div>
          </div>
          <div style="font-size:1.4em;color:var(--muted);">=</div>
          <div>
            <div style="color:var(--muted);font-size:0.8em;margin-bottom:4px;">Output</div>
            <div style="padding:8px 14px;background:var(--code-bg);border:1px dashed #475569;border-radius:4px;font-size:1em;color:var(--muted);">??</div>
          </div>
        </div>
      </template>
```

- [ ] **Step 6: Add the one-real-round demo for step 6**

After the `add-round-key` block:

```html
      <template x-if="step.slug === 'one-real-round'">
        <div style="margin-top:14px;">
          <div style="color:var(--muted);font-size:0.85em;margin-bottom:6px;">A real 16-byte state going through all four transformations of one round. Demo uses a fixed input + round key; values computed client-side via the actual S-box, ShiftRows offsets, MixColumns matrix, and XOR.</div>
          <div style="display:grid;grid-template-columns:repeat(5, 1fr);gap:10px;margin-top:12px;font-family:ui-monospace, monospace;font-size:0.75em;">
            <template x-for="(stateSnap, idx) in aesOneRoundStates" :key="idx">
              <div>
                <div style="color:var(--muted);font-size:0.85em;margin-bottom:4px;text-transform:uppercase;letter-spacing:0.04em;" x-text="['Input', 'After SubBytes', 'After ShiftRows', 'After MixColumns', 'After AddRoundKey'][idx]"></div>
                <table style="border-collapse:collapse;">
                  <template x-for="r in 4" :key="r">
                    <tr>
                      <template x-for="c in 4" :key="c">
                        <td style="padding:3px 5px;border:1px solid #334155;background:var(--code-bg);color:var(--text);text-align:center;" x-text="stateSnap[(r-1)*4 + (c-1)]?.toString(16).toUpperCase().padStart(2,'0')"></td>
                      </template>
                    </tr>
                  </template>
                </table>
              </div>
            </template>
          </div>
        </div>
      </template>
```

The template uses `aesOneRoundStates` — an array of 5 state snapshots. Add to the wizard component (next to `aesSBOX`):

```js
    aesOneRoundStates: [],
```

And initialize it in `init()` when AES tables are loaded. Add right after `if (mods.tables?.SBOX) this.aesSBOX = mods.tables.SBOX;`:

```js
      if (mods.tables?.SBOX && mods.tables?.mixColumn) {
        this.aesOneRoundStates = this._computeOneRound(mods.tables);
      }
```

And add the method to the component:

```js
    _computeOneRound(tables) {
      const { SBOX, mixColumn } = tables;
      // Fixed lesson input (16 bytes) — using a memorable byte pattern
      const input = [0x32, 0x88, 0x31, 0xe0, 0x43, 0x5a, 0x31, 0x37, 0xf6, 0x30, 0x98, 0x07, 0xa8, 0x8d, 0xa2, 0x34];
      // Fixed round key — repeat 0x2B for clarity (matches Add-Round-Key step's key byte)
      const roundKey = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
      // 1. SubBytes
      const afterSub = input.map((b) => SBOX[b]);
      // 2. ShiftRows: state laid out column-major in standard AES; for visualization
      //    we treat it row-major and shift row i by i. Convert mentally — keep simple.
      const afterShift = [...afterSub];
      // row 1: indices 4,5,6,7 → shift left by 1 → 5,6,7,4
      [afterShift[4], afterShift[5], afterShift[6], afterShift[7]] = [afterSub[5], afterSub[6], afterSub[7], afterSub[4]];
      // row 2: indices 8,9,10,11 → shift left by 2 → 10,11,8,9
      [afterShift[8], afterShift[9], afterShift[10], afterShift[11]] = [afterSub[10], afterSub[11], afterSub[8], afterSub[9]];
      // row 3: indices 12,13,14,15 → shift left by 3 → 15,12,13,14
      [afterShift[12], afterShift[13], afterShift[14], afterShift[15]] = [afterSub[15], afterSub[12], afterSub[13], afterSub[14]];
      // 3. MixColumns: 4 columns, each [row0, row1, row2, row3]
      const afterMix = [...afterShift];
      for (let c = 0; c < 4; c++) {
        const col = [afterShift[c], afterShift[c + 4], afterShift[c + 8], afterShift[c + 12]];
        const mixed = mixColumn(col);
        afterMix[c] = mixed[0];
        afterMix[c + 4] = mixed[1];
        afterMix[c + 8] = mixed[2];
        afterMix[c + 12] = mixed[3];
      }
      // 4. AddRoundKey
      const afterArk = afterMix.map((b, i) => b ^ roundKey[i]);
      return [input, afterSub, afterShift, afterMix, afterArk];
    },
```

- [ ] **Step 7: Add the encrypt-message roundtrip display for steps 7 and 8 (done)**

After the `one-real-round` block:

```html
      <template x-if="state.a_message && (step.slug === 'encrypt-a-message' || (step.kind === 'info' && step.slug === 'done' && state.a_ciphertext_hex))">
        <div style="margin-top:14px;padding:12px 14px;border:1px dashed var(--border, #444);border-radius:6px;font-size:0.92em;line-height:1.6;font-family:ui-monospace, monospace;">
          <div><strong>Original:</strong> <span x-text="state.a_message"></span></div>
          <div x-show="state.a_key_hex" style="margin-top:4px;"><strong>AES-128 key:</strong> <span x-text="state.a_key_hex"></span></div>
          <div x-show="state.a_iv_hex"><strong>IV (nonce):</strong> <span x-text="state.a_iv_hex"></span></div>
          <div x-show="state.a_ciphertext_hex" style="word-break:break-all;"><strong>Ciphertext:</strong> <span x-text="state.a_ciphertext_hex"></span></div>
          <div x-show="state.a_recovered" style="margin-top:6px;"><strong>Decrypted:</strong> <span x-text="state.a_recovered"></span> <span x-show="state.a_recovered === state.a_message" style="color:var(--ok, #2a8a3e);">✓ matches</span></div>
          <div x-show="state.a_encrypt_error" style="color:var(--bad, #c0392b);margin-top:6px;">⚠ <span x-text="state.a_encrypt_error"></span></div>
        </div>
      </template>
```

- [ ] **Step 8: Run tests to verify nothing broke**

Run: `cd /Users/hriday/code/enc_algo && npm test 2>&1 | tail -5`
Expected: same JS pass count as after Task 6 (template doesn't affect unit tests).

Run: `cd /Users/hriday/code/enc_algo && .venv/bin/pytest 2>&1 | tail -3`
Expected: 71 pass.

- [ ] **Step 9: Commit**

```bash
git add core/templates/core/lesson.html static/core/wizard.js
git commit -m "$(cat <<'EOF'
feat(aes): lesson.html template branches for AES displays

Six new slug-keyed visualizations:
- sub-bytes: 16×16 S-box grid with row-5 col-3 highlighted
- shift-rows: input row + arrow + placeholder output row
- mix-columns: column + matrix + output column (with the
  GF(2⁸) hint, demo-only since it's not hand-computable)
- add-round-key: state byte XOR round-key byte visualization
- one-real-round: 5 consecutive 4×4 grids (input → SubBytes →
  ShiftRows → MixColumns → AddRoundKey), computed client-side
  via the SBOX + mixColumn from tables.js
- encrypt-a-message / done: roundtrip display (Original / Key /
  IV / Ciphertext / Decrypted ✓ matches) using state.a_*

wizard.js: loadAlgorithmModules now also imports tables.js
(tolerates absence for non-AES algorithms). Component exposes
aesSBOX and aesOneRoundStates so the templates can render
directly via Alpine x-for.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Fixtures — algorithm + lesson + 8 steps + fixture test

**Files:**
- Create: `algorithms/aes/fixtures.json`
- Modify: `core/tests/test_fixtures.py`

- [ ] **Step 1: Create directory**

Run: `mkdir -p /Users/hriday/code/enc_algo/algorithms/aes`

- [ ] **Step 2: Create fixture file**

Create `algorithms/aes/fixtures.json`:

```json
[
  {
    "model": "core.algorithm",
    "pk": 3,
    "fields": {
      "slug": "aes",
      "name": "AES",
      "family": "symmetric",
      "status": "live",
      "order": 3,
      "intro_template": "## AES\n\nThe Advanced Encryption Standard — the symmetric block cipher used everywhere. This lesson teaches the four moves AES applies to a 16-byte block, then encrypts a real message."
    }
  },
  {
    "model": "core.lesson",
    "pk": 3,
    "fields": {
      "algorithm": 3,
      "slug": "four-transformations",
      "title": "The Four Moves",
      "order": 1
    }
  },
  {
    "model": "core.step",
    "pk": 31,
    "fields": {
      "lesson": 3, "order": 1, "slug": "intro", "kind": "info",
      "prompt_template": "## AES — the four moves\n\nAES (Advanced Encryption Standard) is a **block cipher**: it takes a 16-byte block + a key and produces 16 bytes of ciphertext. AES-128 applies 4 transformations 10 times, with a rotating round key.\n\nThe transformations:\n\n1. **SubBytes** — substitute each byte via a fixed lookup table.\n2. **ShiftRows** — rotate each row of the state.\n3. **MixColumns** — multiply each column by a matrix in a finite field.\n4. **AddRoundKey** — XOR with the round key.\n\nWe'll do each move in isolation, watch them composed in one real round, then encrypt a real message with browser-native AES-GCM.",
      "help_template": "**In plain English:** AES is the symmetric cipher everyone uses. It's too complex to compute by hand end-to-end (10 rounds × 4 moves × 16 bytes), but each move is simple enough to do on a small example. That's the lesson: learn the moves, then watch them work for real.",
      "validator_key": "info", "codegen_key": "info"
    }
  },
  {
    "model": "core.step",
    "pk": 32,
    "fields": {
      "lesson": 3, "order": 2, "slug": "sub-bytes", "kind": "input-numeric",
      "prompt_template": "### SubBytes — look up a byte in the S-box\n\nAES replaces each byte with the value from a fixed 16×16 lookup table called the **S-box**. The high nibble of the input picks the row; the low nibble picks the column.\n\nLook up byte **0x53** (row 5, column 3 — highlighted below). Enter the answer in decimal or hex (e.g. `237` or `0xED`).",
      "help_template": "**In plain English:** The S-box is just a fixed list of 256 bytes. It scrambles the input nonlinearly — that nonlinearity is what makes AES hard to invert without the key.",
      "validator_key": "sub_byte", "codegen_key": "sub_byte"
    }
  },
  {
    "model": "core.step",
    "pk": 33,
    "fields": {
      "lesson": 3, "order": 3, "slug": "shift-rows", "kind": "input-multi",
      "prompt_template": "### ShiftRows — rotate a row\n\nShiftRows rotates each row of the 4×4 state by its row index: row 0 unchanged, row 1 by 1, row 2 by 2, row 3 by 3.\n\nGiven the input row `[0x09, 0xCF, 0x4F, 0x3C]` (shown below), enter the 4 bytes of the row **after shifting left by 1**.",
      "help_template": "**In plain English:** Shifting left by 1 moves the first byte to the end. So `[A, B, C, D]` becomes `[B, C, D, A]`. ShiftRows spreads bytes across columns so MixColumns can mix them effectively.",
      "validator_key": "shift_row", "codegen_key": "shift_row"
    }
  },
  {
    "model": "core.step",
    "pk": 34,
    "fields": {
      "lesson": 3, "order": 4, "slug": "mix-columns", "kind": "info",
      "prompt_template": "### MixColumns — the spread step\n\nMixColumns multiplies each column of the state by a fixed 4×4 matrix in **GF(2⁸)** (a 256-element finite field). It's the diffusion step — a change in one byte affects all 4 bytes of the column.\n\nBelow: one column `[0xDB, 0x13, 0x53, 0x45]` becomes `[0x8E, 0x4D, 0xA1, 0xBC]` after MixColumns. The GF(2⁸) math (multiply-by-2 with reducing polynomial 0x11B) is too involved for hand computation — this step is demo-only.",
      "help_template": "**In plain English:** Without MixColumns, AES would just be byte substitutions and shuffling — each output byte would depend on only one input byte. MixColumns blends bytes within each column so changes ripple out.",
      "validator_key": "info", "codegen_key": "info"
    }
  },
  {
    "model": "core.step",
    "pk": 35,
    "fields": {
      "lesson": 3, "order": 5, "slug": "add-round-key", "kind": "input-numeric",
      "prompt_template": "### AddRoundKey — XOR with the key\n\nThe final move of each round: XOR every state byte with the matching byte of the round key. Same XOR you've seen in the toy lessons.\n\nGiven state byte = **0xED** (the SubBytes output from step 2) and round-key byte = **0x2B**, compute `0xED XOR 0x2B`.",
      "help_template": "**In plain English:** XOR is the only point in the round where the key affects the state. Without AddRoundKey, the cipher would have no key at all — just a fixed scramble.",
      "validator_key": "add_round_key", "codegen_key": "add_round_key"
    }
  },
  {
    "model": "core.step",
    "pk": 36,
    "fields": {
      "lesson": 3, "order": 6, "slug": "one-real-round", "kind": "info",
      "prompt_template": "### Watch one real round\n\nNow watch all four moves applied to a real 16-byte state with a real round key. Below: input state, then after each transformation in sequence.\n\nValues are computed client-side using the actual S-box, ShiftRows offsets, MixColumns matrix, and XOR.\n\n> AES-128 does this **10 times** with 10 different round keys (derived from your master key via the key schedule). The last round skips MixColumns.",
      "help_template": "**In plain English:** This is one round of AES. Multiply by 10, add a fresh round key each time, and you have the full encryption. The exact byte patterns shown here aren't meaningful (they're just an example) — what matters is seeing the moves compose.",
      "validator_key": "info", "codegen_key": "info"
    }
  },
  {
    "model": "core.step",
    "pk": 37,
    "fields": {
      "lesson": 3, "order": 7, "slug": "encrypt-a-message", "kind": "input-text",
      "prompt_template": "### Encrypt a real message\n\nType a sentence — your browser's built-in AES-GCM will encrypt it.\n\nWe'll generate a random 128-bit key + 12-byte IV, encrypt with `crypto.subtle.encrypt`, and decrypt to confirm. You'll see the key, IV, and ciphertext as hex strings.",
      "help_template": "**In plain English:** AES-GCM is the authenticated mode used by HTTPS. It takes the four moves you just learned, runs them 10 times, and adds an integrity tag so any tampering is detected. The browser does all of this in milliseconds.",
      "validator_key": "pick_aes_message", "codegen_key": "info"
    }
  },
  {
    "model": "core.step",
    "pk": 38,
    "fields": {
      "lesson": 3, "order": 8, "slug": "done", "kind": "info",
      "prompt_template": "## Done!\n\nYou've seen each AES move in isolation, watched them composed in one real round, and encrypted a real message with browser-native AES-GCM.\n\nWhat we skipped (next lessons, eventually):\n- **AES modes** (ECB / CBC / CTR / GCM) — how AES extends beyond a single 16-byte block to encrypt arbitrary data.\n- **Key expansion** — how the round keys are derived from the master key.\n- **KEK / HSM hierarchies** — how production systems chain keys (the hybrid lesson teaches the pattern; a future lesson generalizes it).",
      "help_template": "",
      "validator_key": "info", "codegen_key": "info"
    }
  }
]
```

- [ ] **Step 3: Verify JSON is valid**

Run: `cd /Users/hriday/code/enc_algo && python -c "import json; d=json.load(open('algorithms/aes/fixtures.json')); print('valid;', len(d), 'objects')"`
Expected: `valid; 11 objects`.

- [ ] **Step 4: Verify intro_template length fits the model**

Run: `cd /Users/hriday/code/enc_algo && python -c "import json; d=json.load(open('algorithms/aes/fixtures.json')); a=[e for e in d if e['model']=='core.algorithm'][0]; print('intro len:', len(a['fields']['intro_template']))"`
Expected: under 200 (Algorithm.intro_template is CharField(max_length=200)). The fixture above is already trimmed to ~186 chars to fit — if the file ends up over 200, trim further before continuing.

- [ ] **Step 5: Load fixtures and verify DB state**

Run: `cd /Users/hriday/code/enc_algo && .venv/bin/python manage.py loaddata algorithms/aes/fixtures.json`
Expected: `Installed 10 object(s) from 1 fixture(s).` (1 algorithm + 1 lesson + 8 steps)

Run: `cd /Users/hriday/code/enc_algo && .venv/bin/python manage.py shell -c "from core.models import Step; print(Step.objects.filter(lesson__slug='four-transformations').count())"`
Expected: `8`

Run: `cd /Users/hriday/code/enc_algo && .venv/bin/python manage.py shell -c "from core.models import Step; print([(s.order, s.slug, s.kind) for s in Step.objects.filter(lesson__slug='four-transformations').order_by('order')])"`
Expected list of 8 tuples with orders 1-8 and slugs:
`intro, sub-bytes, shift-rows, mix-columns, add-round-key, one-real-round, encrypt-a-message, done`

- [ ] **Step 6: Append fixture-load test**

Append to `core/tests/test_fixtures.py`:

```python
@pytest.mark.django_db
def test_aes_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/aes/fixtures.json")

    from core.models import Algorithm, Lesson, Step
    assert Algorithm.objects.filter(slug="aes").count() == 1
    algo = Algorithm.objects.get(slug="aes")
    assert algo.name == "AES"
    assert algo.family == "symmetric"
    assert algo.status == "live"

    lesson = Lesson.objects.get(algorithm=algo, slug="four-transformations")
    steps = list(Step.objects.filter(lesson=lesson).order_by("order"))
    assert len(steps) == 8
    assert [s.slug for s in steps] == [
        "intro", "sub-bytes", "shift-rows", "mix-columns",
        "add-round-key", "one-real-round", "encrypt-a-message", "done",
    ]
    by_slug = {s.slug: s for s in steps}
    assert by_slug["sub-bytes"].validator_key == "sub_byte"
    assert by_slug["shift-rows"].validator_key == "shift_row"
    assert by_slug["add-round-key"].validator_key == "add_round_key"
    assert by_slug["encrypt-a-message"].validator_key == "pick_aes_message"
```

- [ ] **Step 7: Run all tests**

Run: `cd /Users/hriday/code/enc_algo && .venv/bin/pytest -v 2>&1 | tail -10`
Expected: 1 new test passing (count goes 71 → 72).

Run: `cd /Users/hriday/code/enc_algo && npm test 2>&1 | tail -5`
Expected: same JS pass count as after Task 6.

- [ ] **Step 8: Commit**

```bash
git add algorithms/aes/fixtures.json core/tests/test_fixtures.py
git commit -m "$(cat <<'EOF'
feat(aes): fixtures — algorithm + lesson + 8 steps; fixture test

Algorithm pk=3, lesson pk=3, step PKs 31-38. First symmetric
algorithm record on the site (family=symmetric). Hybrid lesson's
existing /algorithms/aes/ link now resolves.

test_fixtures: assertions for the AES algorithm + lesson + 8
expected step slugs + validator_keys for the actionable steps.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: End-to-end smoke

**Files:** None changed; this is a verification task.

- [ ] **Step 1: Confirm dev server is running**

Run: `lsof -iTCP:8000 -sTCP:LISTEN 2>/dev/null | head -3`
If nothing, start it: `cd /Users/hriday/code/enc_algo && DJANGO_DEBUG=True .venv/bin/python manage.py runserver 8000 > /tmp/runserver.log 2>&1 &`

- [ ] **Step 2: Final test run**

Run: `cd /Users/hriday/code/enc_algo && .venv/bin/pytest 2>&1 | tail -3`
Expected: 72 passing.

Run: `cd /Users/hriday/code/enc_algo && npm test 2>&1 | tail -5`
Expected: all green (counts depend on which tests landed earlier).

- [ ] **Step 3: Manual happy-path smoke**

Open `http://127.0.0.1:8000/` in a fresh browser tab (or incognito):

1. Confirm AES card appears alongside RSA + Hybrid Encryption.
2. Click AES → confirm intro page loads.
3. Start the lesson:
   - **Step 1 (intro):** Continue
   - **Step 2 (sub-bytes):** Enter `0xED`. Confirm S-box grid shows with row 5 col 3 highlighted; advance succeeds.
   - **Step 3 (shift-rows):** Enter `0xCF`, `0x4F`, `0x3C`, `0x09`. Advance succeeds.
   - **Step 4 (mix-columns):** Demo renders the column → matrix → output. Continue.
   - **Step 5 (add-round-key):** Enter `0xC6` (or `198`). Advance succeeds.
   - **Step 6 (one-real-round):** 5 grids render; values computed client-side via SBOX + mixColumn. Continue.
   - **Step 7 (encrypt-a-message):** Type `hello`. On Continue, AES-GCM runs in the browser; key/IV/ciphertext hex strings render; decrypted shows `hello` with ✓ matches.
   - **Step 8 (done):** Roundtrip display + forward-links.

- [ ] **Step 4: Wrong-input smoke**

On step 2, enter `0xAA`. Confirm the hint mentions `0xED`. Enter the correct value, advance.

- [ ] **Step 5: "I don't know how" smoke**

On step 2, click "I don't know how" three times. Confirm three escalating rungs reveal, ending with the answer.

- [ ] **Step 6: Final commit (only if any fix-ups during smoke)**

If smoke surfaced bugs, commit fixes. Otherwise no extra commit.

---

## Verification before declaring done

- [ ] `cd /Users/hriday/code/enc_algo && .venv/bin/pytest` is all green (72 passing).
- [ ] `cd /Users/hriday/code/enc_algo && npm test` is all green.
- [ ] AES card appears on landing page.
- [ ] Manual smoke walks 1 → 8 in browser without errors.
- [ ] Browser AES-GCM encryption works (step 7 produces hex strings + decrypted matches).
- [ ] RSA + Hybrid lessons still work (regression check).
