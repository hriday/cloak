# Hybrid Encryption Lesson Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a 9-step "Hybrid Encryption" lesson as a second algorithm — teaches the KEK / envelope pattern (random key + RSA wraps it + symmetric cipher encrypts the data) by composing the existing RSA module with a hand-computable XOR cipher that stands in for AES.

**Architecture:** New algorithm record with its own `static/algorithms/hybrid/` module directory. Reuses RSA's `modPow / modInv / isPrime / gcd` via re-export from `rsa/math.js`. No changes needed to `wizard.js`, `lesson.html`, or any Django model — the infrastructure is already algorithm-generic. Canonical RSA keys (p=11, q=13, n=143, e=7, d=103) are baked into prompts so the user can RSA-wrap a one-byte symmetric key (0–127) without first deriving a keypair. Spec: `docs/superpowers/specs/2026-05-23-hybrid-encryption-lesson-design.md`.

**Tech Stack:** Django 5 + Alpine.js wizard, `node --test` for JS, ESM modules. SQLite locally, Postgres in prod. Fixtures loaded via `loaddata`.

---

## File Structure

**Created:**
- `static/algorithms/hybrid/math.js` — `xorBytes` helper + re-exports from `../rsa/math.js`
- `static/algorithms/hybrid/validators.js` — 6 step validators + `walkthroughs` object
- `static/algorithms/hybrid/codegen.js` — `full_script` returning a runnable hybrid-encryption Python script
- `static/algorithms/hybrid/tests/math.test.js` — node tests for `xorBytes`
- `static/algorithms/hybrid/tests/validators.test.js` — node tests for each validator
- `static/algorithms/hybrid/tests/codegen.test.js` — node tests for `full_script`
- `algorithms/hybrid/fixtures.json` — algorithm record + lesson record + 9 step records

**Modified:**
- `core/tests/test_fixtures.py` — extend with hybrid-lesson assertions

No changes to: `static/core/wizard.js`, `core/templates/core/lesson.html`, `core/models.py`, `core/views.py`, `algorithms/rsa/*`.

**Numerology baked into the plan** (all verified):
- `p=11, q=13, n=143, φ=120, e=7, d=103`
- `gcd(7, 120) = 1` ✓
- `7 × 103 = 721 = 6 × 120 + 1`, so `7d ≡ 1 (mod 120)` ✓
- Max sym key 127 < n 143 ✓
- For "hi" with sym_key=42: ciphertext = `[104^42, 105^42] = [66, 67]`
- `pow(42, 7, 143) = 81` (wrapped key)
- `pow(81, 103, 143) = 42` (unwrapped key, roundtrip)

---

## Task 1: `math.js` — `xorBytes` helper + re-exports

**Files:**
- Create: `static/algorithms/hybrid/math.js`
- Test: `static/algorithms/hybrid/tests/math.test.js`

- [ ] **Step 1: Create the directory structure**

Run:

```bash
mkdir -p /Users/hriday/code/enc_algo/static/algorithms/hybrid/tests
```

- [ ] **Step 2: Write the failing test**

Create `static/algorithms/hybrid/tests/math.test.js` with:

```js
import { test } from "node:test";
import assert from "node:assert/strict";
import * as m from "../math.js";

test("xorBytes encrypts a string with a key", () => {
  // "hi" with key 42: 'h'=104 XOR 42 = 66; 'i'=105 XOR 42 = 67
  assert.deepEqual(m.xorBytes("hi", 42), [66, 67]);
});

test("xorBytes is self-inverse — applying twice returns original codes", () => {
  const original = "hello";
  const encryptedBytes = m.xorBytes(original, 42);
  // Reassemble bytes into a string, then xor again with same key
  const encStr = encryptedBytes.map((c) => String.fromCharCode(c)).join("");
  const decBytes = m.xorBytes(encStr, 42);
  const recovered = decBytes.map((c) => String.fromCharCode(c)).join("");
  assert.equal(recovered, original);
});

test("xorBytes handles key=0 as identity", () => {
  assert.deepEqual(m.xorBytes("Hi", 0), [72, 105]);
});

test("modPow is re-exported from rsa/math.js", () => {
  // Sanity: re-export works and produces the same value as a direct rsa import
  assert.equal(m.modPow(42n, 7n, 143n), 81n);
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd /Users/hriday/code/enc_algo && npm test 2>&1 | grep -E "xorBytes|fail|cannot"`
Expected: failures referencing `xorBytes is not a function` or module-not-found.

- [ ] **Step 4: Create `math.js` with the helper + re-exports**

Create `static/algorithms/hybrid/math.js`:

```js
// Re-export RSA's number-theory helpers so hybrid lesson code can pull
// everything from one place without reaching across algorithm directories.
export { modPow, modInv, gcd, isPrime, phi } from "../rsa/math.js";

// Byte-wise XOR of an ASCII string with a single-byte key.
// Self-inverse: xorBytes(xorBytes(s, k).map(String.fromCharCode).join(""), k)
// recovers the original byte sequence.
export function xorBytes(text, key) {
  const k = Number(key);
  const out = [];
  for (let i = 0; i < text.length; i++) {
    out.push(text.charCodeAt(i) ^ k);
  }
  return out;
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd /Users/hriday/code/enc_algo && npm test 2>&1 | tail -8`
Expected: pass count up by 4, no failures.

- [ ] **Step 6: Commit**

```bash
git add static/algorithms/hybrid/math.js static/algorithms/hybrid/tests/math.test.js
git commit -m "feat(hybrid): math.js — xorBytes helper + re-exports from rsa/math.js"
```

(Include the standard `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>` trailer on the last line of every commit message in this plan.)

---

## Task 2: Validators — `pick_sym_key` + `wrap_key`

**Files:**
- Create: `static/algorithms/hybrid/validators.js`
- Test: `static/algorithms/hybrid/tests/validators.test.js`

- [ ] **Step 1: Write failing tests**

Create `static/algorithms/hybrid/tests/validators.test.js`:

```js
import { test } from "node:test";
import assert from "node:assert/strict";
import * as v from "../validators.js";

test("pick_sym_key happy", () => {
  assert.deepEqual(v.pick_sym_key("42", {}), { ok: true, value: { h_sym_key: 42 } });
});

test("pick_sym_key rejects non-integer", () => {
  const r = v.pick_sym_key("abc", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /whole number/i);
});

test("pick_sym_key rejects negative", () => {
  const r = v.pick_sym_key("-1", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /0 to 127/);
});

test("pick_sym_key rejects > 127", () => {
  const r = v.pick_sym_key("128", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /0 to 127/);
});

test("wrap_key happy — 42^7 mod 143 = 81", () => {
  const r = v.wrap_key("81", { h_sym_key: 42 });
  assert.equal(r.ok, true);
  assert.equal(r.value.h_wrapped_key, 81);
});

test("wrap_key wrong value mentions m/e/n", () => {
  const r = v.wrap_key("999", { h_sym_key: 42 });
  assert.equal(r.ok, false);
  assert.match(r.hint, /42/);   // m
  assert.match(r.hint, /\b7\b/); // e
  assert.match(r.hint, /143/);  // n
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/hriday/code/enc_algo && npm test 2>&1 | grep -E "pick_sym_key|wrap_key|cannot"`
Expected: 6 failures (module not found, or function undefined).

- [ ] **Step 3: Create `validators.js` with both validators**

Create `static/algorithms/hybrid/validators.js`:

```js
import { modPow, xorBytes } from "./math.js";

// Canonical RSA keypair baked into hybrid lesson prompts.
// p=11, q=13 → n=143, φ=120, e=7, d=103. Verified: 7×103 ≡ 1 (mod 120).
const HYBRID_E = 7n;
const HYBRID_D = 103n;
const HYBRID_N = 143n;

function _parseInt(s) {
  if (s === null || s === undefined) return null;
  const t = String(s).trim();
  if (!/^-?\d+$/.test(t)) return null;
  return BigInt(t);
}

function _ok(value) {
  const out = {};
  for (const [k, val] of Object.entries(value)) {
    out[k] = typeof val === "bigint" ? Number(val) : val;
  }
  return { ok: true, value: out };
}

export function pick_sym_key(input, _state) {
  const got = _parseInt(input);
  if (got === null) return { ok: false, hint: "Enter a whole number." };
  if (got < 0n || got > 127n) {
    return { ok: false, hint: "Pick a number from 0 to 127 (so it fits in our RSA key, n=143)." };
  }
  return _ok({ h_sym_key: got });
}

export function wrap_key(input, state) {
  const got = _parseInt(input);
  if (got === null) return { ok: false, hint: "Enter a whole number." };
  const symKey = BigInt(state.h_sym_key);
  const expected = modPow(symKey, HYBRID_E, HYBRID_N);
  if (got !== expected) {
    return { ok: false, hint: `c = m^e mod n. With m=${symKey}, e=7, n=143.` };
  }
  return _ok({ h_wrapped_key: got });
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/hriday/code/enc_algo && npm test 2>&1 | tail -8`
Expected: pass count up by 6 (was 4 after Task 1; now 10).

- [ ] **Step 5: Commit**

```bash
git add static/algorithms/hybrid/validators.js static/algorithms/hybrid/tests/validators.test.js
git commit -m "feat(hybrid): pick_sym_key + wrap_key validators (canonical keypair p=11,q=13)"
```

---

## Task 3: Validators — `type_message` + `xor_encrypt_head`

**Files:**
- Modify: `static/algorithms/hybrid/validators.js`
- Modify: `static/algorithms/hybrid/tests/validators.test.js`

- [ ] **Step 1: Write failing tests**

Append to `static/algorithms/hybrid/tests/validators.test.js`:

```js
test("type_message happy", () => {
  const r = v.type_message("hi", {});
  assert.equal(r.ok, true);
  assert.equal(r.value.h_message, "hi");
  assert.equal(r.value.h_first_char, "h");
  assert.equal(r.value.h_first_code, 104);
});

test("type_message rejects empty", () => {
  const r = v.type_message("", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /at least one/);
});

test("type_message rejects > 500 chars", () => {
  const r = v.type_message("a".repeat(501), {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /500/);
});

test("type_message rejects non-ASCII", () => {
  const r = v.type_message("Hi 🦊", {});
  assert.equal(r.ok, false);
  assert.match(r.hint, /ASCII/i);
});

test("xor_encrypt_head happy — first byte of 'hi' XOR 42 = 66", () => {
  const r = v.xor_encrypt_head("66", { h_message: "hi", h_sym_key: 42 });
  assert.equal(r.ok, true);
  assert.deepEqual(r.value.h_ciphertext, [66, 67]);
});

test("xor_encrypt_head wrong value mentions both operands", () => {
  const r = v.xor_encrypt_head("999", { h_message: "hi", h_sym_key: 42 });
  assert.equal(r.ok, false);
  assert.match(r.hint, /104/); // first_code
  assert.match(r.hint, /42/);  // sym_key
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/hriday/code/enc_algo && npm test 2>&1 | grep -E "type_message|xor_encrypt|fail"`
Expected: 6 new failures.

- [ ] **Step 3: Implement the validators**

Append to `static/algorithms/hybrid/validators.js`:

```js
export function type_message(input, _state) {
  const s = input == null ? "" : String(input);
  if (s.length === 0) return { ok: false, hint: "Type at least one character." };
  if (s.length > 500) return { ok: false, hint: "Keep it under 500 characters." };
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code < 32 || code > 126) {
      return { ok: false, hint: `Only printable ASCII for now — no emoji, accents, tabs, or newlines. Found: '${s[i]}'.` };
    }
  }
  return { ok: true, value: { h_message: s, h_first_char: s[0], h_first_code: s.charCodeAt(0) } };
}

export function xor_encrypt_head(input, state) {
  const got = _parseInt(input);
  if (got === null) return { ok: false, hint: "Enter a whole number." };
  const msg = state?.h_message || "";
  if (!msg) return { ok: false, hint: "No message in state — go back and type one first." };
  const symKey = Number(state.h_sym_key);
  const firstCode = msg.charCodeAt(0);
  const expectedFirst = firstCode ^ symKey;
  if (Number(got) !== expectedFirst) {
    return { ok: false, hint: `Compute first_char XOR sym_key. With first_char = ${firstCode} (ASCII of '${msg[0]}') and sym_key = ${symKey}.` };
  }
  return { ok: true, value: { h_ciphertext: xorBytes(msg, symKey) } };
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/hriday/code/enc_algo && npm test 2>&1 | tail -8`
Expected: pass count up by 6 (now 16).

- [ ] **Step 5: Commit**

```bash
git add static/algorithms/hybrid/validators.js static/algorithms/hybrid/tests/validators.test.js
git commit -m "feat(hybrid): type_message + xor_encrypt_head validators"
```

---

## Task 4: Validators — `unwrap_key` + `xor_decrypt_head` + `info`

**Files:**
- Modify: `static/algorithms/hybrid/validators.js`
- Modify: `static/algorithms/hybrid/tests/validators.test.js`

- [ ] **Step 1: Write failing tests**

Append to `static/algorithms/hybrid/tests/validators.test.js`:

```js
test("unwrap_key happy — 81^103 mod 143 = 42", () => {
  const r = v.unwrap_key("42", { h_wrapped_key: 81 });
  assert.equal(r.ok, true);
  assert.equal(r.value.h_recovered_key, 42);
});

test("unwrap_key wrong value mentions c/d/n", () => {
  const r = v.unwrap_key("999", { h_wrapped_key: 81 });
  assert.equal(r.ok, false);
  assert.match(r.hint, /81/);   // c
  assert.match(r.hint, /103/);  // d
  assert.match(r.hint, /143/);  // n
});

test("xor_decrypt_head happy — first byte 66 XOR recovered_key 42 = 104", () => {
  const r = v.xor_decrypt_head("104", { h_ciphertext: [66, 67], h_recovered_key: 42 });
  assert.equal(r.ok, true);
  assert.equal(r.value.h_recovered_message, "hi");
});

test("xor_decrypt_head wrong value mentions both operands", () => {
  const r = v.xor_decrypt_head("999", { h_ciphertext: [66, 67], h_recovered_key: 42 });
  assert.equal(r.ok, false);
  assert.match(r.hint, /66/);  // ciphertext[0]
  assert.match(r.hint, /42/);  // recovered_key
});

test("info always returns ok", () => {
  assert.deepEqual(v.info("anything", {}), { ok: true, value: {} });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/hriday/code/enc_algo && npm test 2>&1 | grep -E "unwrap_key|xor_decrypt|info always|fail "`
Expected: 5 new failures.

- [ ] **Step 3: Implement the validators**

Append to `static/algorithms/hybrid/validators.js`:

```js
export function unwrap_key(input, state) {
  const got = _parseInt(input);
  if (got === null) return { ok: false, hint: "Enter a whole number." };
  const wrapped = BigInt(state.h_wrapped_key);
  const expected = modPow(wrapped, HYBRID_D, HYBRID_N);
  if (got !== expected) {
    return { ok: false, hint: `m = c^d mod n. With c=${wrapped}, d=103, n=143.` };
  }
  return _ok({ h_recovered_key: got });
}

export function xor_decrypt_head(input, state) {
  const got = _parseInt(input);
  if (got === null) return { ok: false, hint: "Enter a whole number." };
  const cipher = state?.h_ciphertext;
  if (!Array.isArray(cipher) || cipher.length === 0) {
    return { ok: false, hint: "No ciphertext in state — go back and encrypt first." };
  }
  const recoveredKey = Number(state.h_recovered_key);
  const firstByte = cipher[0];
  const expectedFirst = firstByte ^ recoveredKey;
  if (Number(got) !== expectedFirst) {
    return { ok: false, hint: `Compute first_ciphertext_byte XOR recovered_key. With c[0] = ${firstByte} and recovered_key = ${recoveredKey}.` };
  }
  const decoded = cipher.map((c) => c ^ recoveredKey);
  const recovered = decoded.map((code) => String.fromCharCode(code)).join("");
  return { ok: true, value: { h_recovered_message: recovered } };
}

export function info(_input, _state) {
  return { ok: true, value: {} };
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/hriday/code/enc_algo && npm test 2>&1 | tail -8`
Expected: pass count up by 5 (now 21).

- [ ] **Step 5: Commit**

```bash
git add static/algorithms/hybrid/validators.js static/algorithms/hybrid/tests/validators.test.js
git commit -m "feat(hybrid): unwrap_key + xor_decrypt_head + info validators"
```

---

## Task 5: Walkthroughs for actionable steps

**Files:**
- Modify: `static/algorithms/hybrid/validators.js`
- Modify: `static/algorithms/hybrid/tests/validators.test.js`

- [ ] **Step 1: Write failing tests**

Append to `static/algorithms/hybrid/tests/validators.test.js`:

```js
test("walkthroughs exports has the 4 actionable keys", () => {
  assert.equal(typeof v.walkthroughs.wrap_key, "function");
  assert.equal(typeof v.walkthroughs.xor_encrypt_head, "function");
  assert.equal(typeof v.walkthroughs.unwrap_key, "function");
  assert.equal(typeof v.walkthroughs.xor_decrypt_head, "function");
});

test("wrap_key walkthrough computes the answer", () => {
  const rungs = v.walkthroughs.wrap_key({ h_sym_key: 42 });
  assert.equal(rungs.length, 3);
  rungs.forEach((r) => assert.equal(typeof r, "string"));
  assert.match(rungs[2], /\b81\b/); // 42^7 mod 143 = 81
});

test("xor_encrypt_head walkthrough computes the answer", () => {
  const rungs = v.walkthroughs.xor_encrypt_head({ h_message: "hi", h_sym_key: 42 });
  assert.equal(rungs.length, 3);
  assert.match(rungs[2], /\b66\b/); // 'h'(104) XOR 42 = 66
});

test("unwrap_key walkthrough computes the answer", () => {
  const rungs = v.walkthroughs.unwrap_key({ h_wrapped_key: 81 });
  assert.equal(rungs.length, 3);
  assert.match(rungs[2], /\b42\b/); // 81^103 mod 143 = 42
});

test("xor_decrypt_head walkthrough computes the answer", () => {
  const rungs = v.walkthroughs.xor_decrypt_head({ h_ciphertext: [66, 67], h_recovered_key: 42 });
  assert.equal(rungs.length, 3);
  assert.match(rungs[2], /\b104\b/); // 66 XOR 42 = 104
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/hriday/code/enc_algo && npm test 2>&1 | grep -E "walkthrough"`
Expected: 5 failures.

- [ ] **Step 3: Add the `walkthroughs` export**

Append to `static/algorithms/hybrid/validators.js`:

```js
// ---- Walkthroughs (powering the "I don't know how" button) ----
// Each returns an array of 3 escalating string rungs: method → worked
// example → answer. Same pattern as the RSA lesson's walkthroughs.

export const walkthroughs = {
  wrap_key: (state) => {
    const m = BigInt(state?.h_sym_key ?? 0);
    const result = modPow(m, HYBRID_E, HYBRID_N);
    return [
      `**The method:** c = m^e mod n. Here m is the symmetric key you picked, e and n are the public RSA key.`,
      `m = ${m}, e = 7, n = 143. So compute ${m}^7 mod 143.`,
      `**Answer: ${result}.** (In Python: \`pow(${m}, 7, 143)\`.)`,
    ];
  },

  xor_encrypt_head: (state) => {
    const msg = state?.h_message || "";
    const ch = msg[0] || "?";
    const code = msg.charCodeAt(0) || 0;
    const k = Number(state?.h_sym_key ?? 0);
    const result = code ^ k;
    return [
      `**The method:** XOR the ASCII code of the first character with your symmetric key. XOR is bit-wise; the answer is a byte value (0–255).`,
      `For '${ch}', ASCII = ${code}. sym_key = ${k}. Compute ${code} XOR ${k}.`,
      `**Answer: ${result}.** (In Python: \`${code} ^ ${k}\`.)`,
    ];
  },

  unwrap_key: (state) => {
    const c = BigInt(state?.h_wrapped_key ?? 0);
    const result = modPow(c, HYBRID_D, HYBRID_N);
    return [
      `**The method:** m = c^d mod n. Same shape as the toy RSA decrypt — d is the private exponent that undoes the wrap.`,
      `c = ${c}, d = 103, n = 143. Compute ${c}^103 mod 143.`,
      `**Answer: ${result}.** (In Python: \`pow(${c}, 103, 143)\`.)`,
    ];
  },

  xor_decrypt_head: (state) => {
    const cipher = Array.isArray(state?.h_ciphertext) ? state.h_ciphertext : [0];
    const c = cipher[0];
    const k = Number(state?.h_recovered_key ?? 0);
    const result = c ^ k;
    return [
      `**The method:** XOR is self-inverse — the same operation that encrypted decrypts. Take the first ciphertext byte and XOR with the recovered key.`,
      `c[0] = ${c}, recovered_key = ${k}. Compute ${c} XOR ${k}.`,
      `**Answer: ${result}.** That's the ASCII code for '${String.fromCharCode(result)}'. (In Python: \`${c} ^ ${k}\`.)`,
    ];
  },
};
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/hriday/code/enc_algo && npm test 2>&1 | tail -8`
Expected: pass count up by 5 (now 26).

- [ ] **Step 5: Commit**

```bash
git add static/algorithms/hybrid/validators.js static/algorithms/hybrid/tests/validators.test.js
git commit -m "feat(hybrid): walkthroughs for wrap_key, xor_encrypt_head, unwrap_key, xor_decrypt_head"
```

---

## Task 6: `codegen.js` — `full_script`

**Files:**
- Create: `static/algorithms/hybrid/codegen.js`
- Test: `static/algorithms/hybrid/tests/codegen.test.js`

- [ ] **Step 1: Write failing tests**

Create `static/algorithms/hybrid/tests/codegen.test.js`:

```js
import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../codegen.js";

const FULL_STATE = {
  h_sym_key: 42,
  h_wrapped_key: 81,
  h_message: "hi",
  h_ciphertext: [66, 67],
  h_recovered_key: 42,
  h_recovered_message: "hi",
};

test("full_script includes canonical RSA keys", () => {
  const out = c.full_script(FULL_STATE);
  assert.match(out, /p, q = 11, 13/);
  assert.match(out, /e = 7/);
});

test("full_script includes the sym key value and the wrap call", () => {
  const out = c.full_script(FULL_STATE);
  assert.match(out, /sym_key = 42/);
  assert.match(out, /wrapped_key = pow\(sym_key, e, n\)/);
});

test("full_script includes the message and the XOR list comprehension", () => {
  const out = c.full_script(FULL_STATE);
  assert.match(out, /message = "hi"/);
  assert.match(out, /ord\(ch\) \^ sym_key for ch in message/);
});

test("full_script includes the assert that closes the roundtrip", () => {
  const out = c.full_script(FULL_STATE);
  assert.match(out, /assert recovered == message/);
});

test("info and other per-step codegen functions return empty string", () => {
  assert.equal(c.info({}), "");
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/hriday/code/enc_algo && npm test 2>&1 | grep -E "full_script|info and|cannot"`
Expected: 5 failures.

- [ ] **Step 3: Create `codegen.js`**

Create `static/algorithms/hybrid/codegen.js`:

```js
// Generates the Python script shown on the Done step.
// Mirrors the lesson's logical sequence so the user can copy/run it.

export function full_script(state) {
  const symKey = state.h_sym_key ?? 42;
  const message = state.h_message ?? "hi";
  const messageLiteral = JSON.stringify(message);
  return [
    "# Hybrid encryption — generated by cloak.moosha.org",
    "",
    "# RSA keypair (see the RSA lesson for derivation)",
    "p, q = 11, 13",
    "n = p * q                            # 143",
    "phi = (p - 1) * (q - 1)              # 120",
    "e = 7                                # coprime to phi",
    "d = pow(e, -1, phi)                  # 103",
    "",
    "# Sender side",
    `sym_key = ${symKey}                         # in real life: 32 random bytes for AES-256`,
    "wrapped_key = pow(sym_key, e, n)     # RSA wraps the symmetric key",
    `message = ${messageLiteral}`,
    "ciphertext = [ord(ch) ^ sym_key for ch in message]   # XOR stands in for AES",
    "",
    "# Send: [wrapped_key, ciphertext]",
    "",
    "# Receiver side",
    "recovered_key = pow(wrapped_key, d, n)",
    "recovered = \"\".join(chr(c ^ recovered_key) for c in ciphertext)",
    "assert recovered == message",
  ].join("\n");
}

// Per-step inline codegen — info steps emit nothing.
export function info(_state) { return ""; }

// Stubs for the other steps; the wizard's inline code panel only renders
// when codegen_key maps to a function that returns non-empty text.
export function pick_sym_key(_state) { return ""; }
export function wrap_key(_state) { return "wrapped_key = pow(sym_key, e, n)"; }
export function type_message(_state) { return ""; }
export function xor_encrypt_head(state) {
  return `ciphertext = [ord(ch) ^ ${state.h_sym_key} for ch in message]`;
}
export function unwrap_key(_state) { return "recovered_key = pow(wrapped_key, d, n)"; }
export function xor_decrypt_head(state) {
  return `recovered = "".join(chr(c ^ ${state.h_recovered_key}) for c in ciphertext)`;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/hriday/code/enc_algo && npm test 2>&1 | tail -8`
Expected: pass count up by 5 (now 31).

- [ ] **Step 5: Commit**

```bash
git add static/algorithms/hybrid/codegen.js static/algorithms/hybrid/tests/codegen.test.js
git commit -m "feat(hybrid): codegen.js — full_script + per-step inline code"
```

---

## Task 7: Fixtures — algorithm + lesson + 9 steps

**Files:**
- Create: `algorithms/hybrid/fixtures.json`

- [ ] **Step 1: Create the directory**

Run:

```bash
mkdir -p /Users/hriday/code/enc_algo/algorithms/hybrid
```

- [ ] **Step 2: Create the fixture file**

Create `algorithms/hybrid/fixtures.json`:

```json
[
  {
    "model": "core.algorithm",
    "pk": 2,
    "fields": {
      "slug": "hybrid",
      "name": "Hybrid Encryption",
      "family": "asymmetric",
      "status": "live",
      "order": 2,
      "intro_template": "## Hybrid Encryption\n\nRSA can only encrypt small things — a 2048-bit key fits about 214 bytes of message per operation. So real systems don't RSA-encrypt your data. They generate a random symmetric key (typically for AES), use RSA to wrap that key, and use the symmetric cipher to encrypt the actual data. This lesson walks you through that pattern end-to-end using a hand-computable XOR cipher in place of AES."
    }
  },
  {
    "model": "core.lesson",
    "pk": 2,
    "fields": {
      "algorithm": 2,
      "slug": "wrap-and-send",
      "title": "Wrap a Key, Send a Message",
      "order": 1
    }
  },
  {
    "model": "core.step",
    "pk": 21,
    "fields": {
      "lesson": 2, "order": 1, "slug": "intro", "kind": "info",
      "prompt_template": "## Wrap a key, send a message\n\nRSA can only encrypt numbers smaller than n. For a 2048-bit real-world RSA key, that's about 214 bytes per block. So nobody RSA-encrypts a whole email or webpage. The pattern is:\n\n1. Generate a random **symmetric key**.\n2. **RSA-wrap** the key with the recipient's public key.\n3. **Symmetric-encrypt** the message with the key.\n4. Send both: `[wrapped_key, ciphertext]`.\n5. The recipient RSA-unwraps the key, then symmetric-decrypts the message.\n\nIn the next 7 steps you'll do every operation by hand.",
      "help_template": "**In plain English:** RSA is slow and small. Symmetric ciphers (like AES) are fast and have no size limit. So we use each for what it's good at — RSA carries the key, the symmetric cipher carries the data. This is called *hybrid encryption* (or *envelope encryption*), and it's how HTTPS, SSH, and PGP all work.",
      "validator_key": "info", "codegen_key": "info"
    }
  },
  {
    "model": "core.step",
    "pk": 22,
    "fields": {
      "lesson": 2, "order": 2, "slug": "meet-symmetric", "kind": "info",
      "prompt_template": "### Meet the symmetric cipher\n\nReal systems use **AES** for the symmetric step — a 10-round block cipher with S-boxes, state matrices, and mix columns. Nobody computes AES by hand. To keep this lesson compute-along, we'll use a tiny stand-in: byte-wise **XOR**.\n\n> XOR is dead-simple — the same operation encrypts and decrypts. It's not secure on its own (real systems wrap it in AES-GCM with a nonce), but it makes the *pattern* of hybrid encryption visible.\n\nIf you want to learn the real AES algorithm, see the [AES lesson](/algorithms/aes/) (coming soon).",
      "help_template": "**In plain English:** AES takes a key and a chunk of data and scrambles them into ciphertext. It's reversible with the same key. Our XOR cipher does the same thing using one byte instead of 128 bits — same shape, much weaker, much easier to compute.",
      "validator_key": "info", "codegen_key": "info"
    }
  },
  {
    "model": "core.step",
    "pk": 23,
    "fields": {
      "lesson": 2, "order": 3, "slug": "pick-sym-key", "kind": "input-numeric",
      "prompt_template": "### Pick a symmetric key\n\nPick any whole number from **0 to 127** — that's your symmetric key. (In a real system this would be 32 cryptographically-random bytes for AES-256. We use one small number here so you can do the XOR by hand.)",
      "help_template": "**In plain English:** Any number 0–127 works. Pick something memorable like 42; the math works the same either way. The 127 cap is so the key fits in our toy RSA modulus n=143.",
      "validator_key": "pick_sym_key", "codegen_key": "info"
    }
  },
  {
    "model": "core.step",
    "pk": 24,
    "fields": {
      "lesson": 2, "order": 4, "slug": "wrap-key", "kind": "input-numeric",
      "prompt_template": "### Wrap the key with RSA\n\nWe're using a fixed RSA keypair for this lesson: **p = 11, q = 13, n = 143, e = 7, d = 103**. *(If you want to see where these come from, that's the [RSA lesson](/algorithms/rsa/learn/encrypt-decrypt/).)*\n\nWrap your symmetric key by computing `c = m^e mod n` with **m = {{ state.h_sym_key }}**, e = 7, n = 143. The result is your *wrapped key* — what you'd actually transmit.",
      "help_template": "**In plain English:** Same `pow(m, e, n)` you did in the RSA lesson. The wrapped key is only meaningful to someone holding the matching private key (d).",
      "validator_key": "wrap_key", "codegen_key": "wrap_key"
    }
  },
  {
    "model": "core.step",
    "pk": 25,
    "fields": {
      "lesson": 2, "order": 5, "slug": "type-message", "kind": "input-text",
      "prompt_template": "### Type a message\n\nWith your symmetric key set ({{ state.h_sym_key }}) and wrapped ({{ state.h_wrapped_key }}), type the message you want to send. Up to 500 printable ASCII characters. We'll encrypt it byte-by-byte with the symmetric key on the next step.",
      "help_template": "**In plain English:** Whatever you type here will be the plaintext input to the symmetric cipher. Real systems would handle arbitrary bytes (images, files, whatever); we limit to printable ASCII so the table is readable.",
      "validator_key": "type_message", "codegen_key": "info"
    }
  },
  {
    "model": "core.step",
    "pk": 26,
    "fields": {
      "lesson": 2, "order": 6, "slug": "xor-encrypt", "kind": "input-numeric",
      "prompt_template": "### Encrypt the first byte\n\nThe first character of your message is **'{{ state.h_first_char }}'** — ASCII **{{ state.h_first_code }}**. Compute `{{ state.h_first_code }} XOR {{ state.h_sym_key }}`.\n\nOnce you get the first one, the lesson XORs the rest for you and shows the full ciphertext.",
      "help_template": "**In plain English:** XOR (exclusive OR) compares two numbers bit by bit. A 1 in each position is contributed by exactly one of the operands. You can do it in Python with the `^` operator: `{{ state.h_first_code }} ^ {{ state.h_sym_key }}`.",
      "validator_key": "xor_encrypt_head", "codegen_key": "xor_encrypt_head"
    }
  },
  {
    "model": "core.step",
    "pk": 27,
    "fields": {
      "lesson": 2, "order": 7, "slug": "unwrap-key", "kind": "input-numeric",
      "prompt_template": "### Receiver: unwrap the key\n\nNow you're the receiver. You have the wrapped key ({{ state.h_wrapped_key }}) and your private exponent d = 103. Recover the symmetric key by computing `m = c^d mod n` with **c = {{ state.h_wrapped_key }}**, d = 103, n = 143. The answer should equal **{{ state.h_sym_key }}** — the original symmetric key the sender chose.",
      "help_template": "**In plain English:** Same `pow(c, d, n)` shape as the RSA decrypt. Only someone holding d can do this — that's the whole point of RSA being asymmetric.",
      "validator_key": "unwrap_key", "codegen_key": "unwrap_key"
    }
  },
  {
    "model": "core.step",
    "pk": 28,
    "fields": {
      "lesson": 2, "order": 8, "slug": "xor-decrypt", "kind": "input-numeric",
      "prompt_template": "### Receiver: decrypt the first byte\n\nThe first ciphertext byte is **{{ state.h_first_encrypted }}** *(displayed below)* and you've recovered the key — **{{ state.h_recovered_key }}**. Compute `{{ state.h_first_encrypted }} XOR {{ state.h_recovered_key }}`. The answer should be **{{ state.h_first_code }}** — the ASCII code for **'{{ state.h_first_char }}'**.\n\nOn Check, the lesson decrypts the rest and assembles your message back.",
      "help_template": "**In plain English:** XOR is self-inverse: the same operation that encrypted decrypts. That's why a single key works for both directions in symmetric ciphers like this one.",
      "validator_key": "xor_decrypt_head", "codegen_key": "xor_decrypt_head"
    }
  },
  {
    "model": "core.step",
    "pk": 29,
    "fields": {
      "lesson": 2, "order": 9, "slug": "done", "kind": "info",
      "prompt_template": "## Done!\n\nYou just did **hybrid encryption** by hand. Your roundtrip:\n\n- **Symmetric key:** {{ state.h_sym_key }} → **RSA-wrapped as:** {{ state.h_wrapped_key }}\n- **Message:** '{{ state.h_message }}' → **ciphertext:** {{ state.h_ciphertext_str }}\n- **Receiver recovered the key** ({{ state.h_recovered_key }}) **and decrypted back to:** '{{ state.h_recovered_message }}' ✓\n\nThe pattern you used — random symmetric key + RSA wraps the key + symmetric cipher encrypts the data — is what HTTPS, SSH, and PGP all use.\n\nIn production, swap the XOR for **AES** (see the [AES lesson](/algorithms/aes/) when it ships) and the toy RSA keys for 2048-bit primes with OAEP padding.\n\n**Where this leads:** the pattern of \"a key that encrypts a key\" is called a **KEK** (Key Encryption Key). Production key-management systems — AWS KMS, GCP KMS, Azure Key Vault, hardware HSMs — build whole hierarchies of KEKs on top of this idea. There'll be a KEK/HSM lesson covering that.",
      "help_template": "",
      "validator_key": "info", "codegen_key": "info"
    }
  }
]
```

(Note: the prompt for step 28 references `state.h_first_encrypted` — that's set by `xor_encrypt_head`'s validator at success time. Verify by checking Task 3's validator returns it; it currently does not. Add a fix-up below.)

- [ ] **Step 3: Patch `xor_encrypt_head` to expose display-friendly fields**

Step 28 (xor-decrypt) interpolates `{{ state.h_first_encrypted }}`. The Done step (29) interpolates `{{ state.h_ciphertext_str }}` for the roundtrip narrative. Make `xor_encrypt_head` write both.

In `static/algorithms/hybrid/validators.js`, find:

```js
  return { ok: true, value: { h_ciphertext: xorBytes(msg, symKey) } };
}
```

Replace with:

```js
  const ciphertext = xorBytes(msg, symKey);
  return {
    ok: true,
    value: {
      h_ciphertext: ciphertext,
      h_first_encrypted: ciphertext[0],
      h_ciphertext_str: ciphertext.join(", "),
    },
  };
}
```

- [ ] **Step 4: Update the `xor_encrypt_head` happy-path test to assert the new keys**

In `static/algorithms/hybrid/tests/validators.test.js`, find:

```js
test("xor_encrypt_head happy — first byte of 'hi' XOR 42 = 66", () => {
  const r = v.xor_encrypt_head("66", { h_message: "hi", h_sym_key: 42 });
  assert.equal(r.ok, true);
  assert.deepEqual(r.value.h_ciphertext, [66, 67]);
});
```

Replace with:

```js
test("xor_encrypt_head happy — first byte of 'hi' XOR 42 = 66", () => {
  const r = v.xor_encrypt_head("66", { h_message: "hi", h_sym_key: 42 });
  assert.equal(r.ok, true);
  assert.deepEqual(r.value.h_ciphertext, [66, 67]);
  assert.equal(r.value.h_first_encrypted, 66);
  assert.equal(r.value.h_ciphertext_str, "66, 67");
});
```

- [ ] **Step 5: Run all JS tests to verify everything still passes**

Run: `cd /Users/hriday/code/enc_algo && npm test 2>&1 | tail -5`
Expected: all green.

- [ ] **Step 6: Load fixtures and verify DB state**

Run: `cd /Users/hriday/code/enc_algo && .venv/bin/python manage.py loaddata algorithms/hybrid/fixtures.json`
Expected: `Installed 11 object(s) from 1 fixture(s).` (1 algorithm + 1 lesson + 9 steps)

Run: `cd /Users/hriday/code/enc_algo && .venv/bin/python manage.py shell -c "from core.models import Step; print(Step.objects.filter(lesson__slug='wrap-and-send').count())"`
Expected: `9`

Run: `cd /Users/hriday/code/enc_algo && .venv/bin/python manage.py shell -c "from core.models import Step; print([(s.order, s.slug, s.kind) for s in Step.objects.filter(lesson__slug='wrap-and-send').order_by('order')])"`
Expected list of 9 tuples with orders 1–9 and slugs:
`intro, meet-symmetric, pick-sym-key, wrap-key, type-message, xor-encrypt, unwrap-key, xor-decrypt, done`

- [ ] **Step 7: Commit**

```bash
git add algorithms/hybrid/fixtures.json static/algorithms/hybrid/validators.js static/algorithms/hybrid/tests/validators.test.js
git commit -m "feat(hybrid): fixtures — algorithm + lesson + 9 steps; expose h_first_encrypted"
```

---

## Task 8: Fixture-load test + final smoke

**Files:**
- Modify: `core/tests/test_fixtures.py`

- [ ] **Step 1: Read the existing test to match its shape**

Run: `cat /Users/hriday/code/enc_algo/core/tests/test_fixtures.py`

Expected: an existing `test_rsa_fixture_loads` (or similar) that calls `loaddata` and asserts step shape. The new test will follow the same pattern.

- [ ] **Step 2: Append the hybrid-lesson test**

Append to `core/tests/test_fixtures.py`:

```python
@pytest.mark.django_db
def test_hybrid_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/hybrid/fixtures.json")

    from core.models import Algorithm, Lesson, Step
    assert Algorithm.objects.filter(slug="hybrid").count() == 1
    algo = Algorithm.objects.get(slug="hybrid")
    assert algo.name == "Hybrid Encryption"
    assert algo.family == "asymmetric"
    assert algo.status == "live"

    lesson = Lesson.objects.get(algorithm=algo, slug="wrap-and-send")
    steps = list(Step.objects.filter(lesson=lesson).order_by("order"))
    assert len(steps) == 9
    assert [s.slug for s in steps] == [
        "intro", "meet-symmetric", "pick-sym-key", "wrap-key",
        "type-message", "xor-encrypt", "unwrap-key", "xor-decrypt", "done",
    ]
    # Spot-check validator keys for the actionable steps
    by_slug = {s.slug: s for s in steps}
    assert by_slug["pick-sym-key"].validator_key == "pick_sym_key"
    assert by_slug["wrap-key"].validator_key == "wrap_key"
    assert by_slug["type-message"].validator_key == "type_message"
    assert by_slug["xor-encrypt"].validator_key == "xor_encrypt_head"
    assert by_slug["unwrap-key"].validator_key == "unwrap_key"
    assert by_slug["xor-decrypt"].validator_key == "xor_decrypt_head"
```

If the file doesn't already `import pytest`, add it at the top.

- [ ] **Step 3: Run all tests**

Run: `cd /Users/hriday/code/enc_algo && .venv/bin/pytest -v 2>&1 | tail -10`
Expected: 1 new test passing, no regressions (RSA tests still green).

Run: `cd /Users/hriday/code/enc_algo && npm test 2>&1 | tail -5`
Expected: same pass count as after Task 6 (the validators/codegen tests we added).

- [ ] **Step 4: Manual smoke — happy path**

If a dev server isn't running:

```bash
cd /Users/hriday/code/enc_algo && DJANGO_DEBUG=True .venv/bin/python manage.py runserver 8000 > /tmp/runserver.log 2>&1 &
```

1. Open `http://127.0.0.1:8000/` in a fresh browser tab (or incognito).
2. Confirm two algorithm cards: RSA and Hybrid Encryption.
3. Click Hybrid Encryption. Confirm intro page loads with the intro_template copy.
4. Start the lesson. Walk all 9 steps with sym_key=42, message="hi":
   - Step 4: enter 81 (= 42^7 mod 143). Should advance.
   - Step 6: enter 66 (= 104 XOR 42). Should advance + show full ciphertext [66, 67].
   - Step 7: enter 42 (= 81^103 mod 143). Should advance.
   - Step 8: enter 104 (= 66 XOR 42). Should advance to Done.
5. On Done: confirm the roundtrip display shows `Wrapped key: 81 / Ciphertext: 66, 67 / Recovered: "hi"` (or equivalent) and the full Python script appears.
6. Test the "I don't know how" button on step 4: should reveal method → example → answer (81).

- [ ] **Step 5: Manual smoke — wrong-input + walkthrough**

On step 4, enter `999`. Confirm hint says "c = m^e mod n. With m=42, e=7, n=143." Click "I don't know how", verify three rungs reveal correctly.

- [ ] **Step 6: Manual smoke — cross-lesson isolation**

In the same tab:
1. Navigate to the RSA lesson (`/algorithms/rsa/learn/encrypt-decrypt/`).
2. Confirm RSA state is unaffected by the hybrid lesson's progress (separate localStorage keys).

- [ ] **Step 7: Final commit (only if any code changes happened during smoke)**

If smoke passed first try, no extra commit. Otherwise, fix-up commits per bug:

```bash
git commit -m "fix(hybrid): <specific bug>"
```

---

## Verification before declaring done

- [ ] `cd /Users/hriday/code/enc_algo && .venv/bin/pytest -v` is all green (existing tests + 1 new hybrid fixture test).
- [ ] `cd /Users/hriday/code/enc_algo && npm test` is all green (existing RSA tests + 31 new hybrid tests).
- [ ] Manual happy path walks 1 → 9 in browser without errors.
- [ ] Hybrid algorithm card appears on landing page.
- [ ] Done page shows roundtrip + full script + forward-link to KEK lesson.
- [ ] RSA lesson still works (no regressions).
- [ ] No changes to `static/core/wizard.js`, `core/templates/core/lesson.html`, or any Django model.
