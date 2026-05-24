# Triple DES Lesson — Design

**Date:** 2026-05-24
**Project:** `cloak`
**Working directory:** /Users/hriday/code/enc_algo

## Goal

Teach Triple DES (3DES) as a 7-step lesson whose pedagogical centerpiece is **why** 3DES exists — i.e., the meet-in-the-middle attack on 2DES that explains why doubling DES doesn't double security. Real DES is too complex to compute by hand (16 Feistel rounds, S-boxes, P-boxes) and isn't in Web Crypto, so the lesson treats single-DES as a black box, walks through the MITM attack on a toy cipher in-browser, then shows the 3DES E-D-E composition and a Python codegen using `cryptography.hazmat`'s 3DES API.

## Curriculum position

Fourth algorithm in the planned arc:

1. RSA ✅
2. Hybrid Encryption ✅
3. AES ✅
4. **Triple DES** (this design)
5. Caesar / Vigenère
6. Blowfish
7. Twofish
8. KEK / HSM

## Non-goals

- Implementing real DES from scratch in JS (no Web Crypto support; full DES is ~200 LOC; not pedagogically useful at lesson scale).
- The 16 Feistel rounds of real DES (acknowledged as "behind the curtain"; not walked through).
- DES key expansion (PC-1, PC-2 — too detailed for the cipher's modern relevance).
- The complete S-box / P-box tables.
- 3DES-EEE variant (we only show E-D-E, which is the standard).
- Showing real 56-bit brute force (simulated with smaller keys for the MITM step).

## User experience

The lesson lives at `/algorithms/triple-des/learn/why-3des/`. Triple DES appears as a new card on the landing page.

### Step sequence

| # | Slug | Kind | Behavior |
|---|---|---|---|
| 1 | `intro` | `info` | What DES is (60s) — 56-bit key, 64-bit block, Feistel cipher from 1977. Why it's deprecated (key size too small for modern compute). Motivates the question: can we just chain it to make it stronger? |
| 2 | `single-des-weakness` | `info` | Demo: a 56-bit key has ~7.2 × 10¹⁶ possibilities. At 10⁹ keys/sec on a desktop, that's ~2 years. A modern GPU farm cracks it in hours. Doubling to 112 bits should make it 2⁵⁶× harder — *should*. |
| 3 | `naive-2des-intro` | `info` | "2DES": just apply DES twice with two different keys. That's a 112-bit key space — should be uncrackable. Or is it? |
| 4 | `mitm-attack` | `input-numeric` | **The lesson's centerpiece.** Uses a toy cipher with tiny keys (8-bit) so the attack is computable in-browser. Given a known plaintext-ciphertext pair, the user runs the MITM attack: encrypt with all 256 K1 candidates → decrypt ciphertext with all 256 K2 candidates → find the match. Lesson narrates: this is O(2 × 2⁸) work, not O(2¹⁶). The same math scales: real 2DES MITM is O(2 × 2⁵⁶), not O(2¹¹²). |
| 5 | `3des-ede` | `info` | Triple DES: `E(K3, D(K2, E(K1, plaintext)))`. Three keys, but MITM only reduces effective security to ~112 bits (not 168). Standard "3-key 3DES" or sometimes "2-key 3DES" with K1=K3. Lesson explains the E-D-E pattern (rather than E-E-E) so that single-key 3DES degrades gracefully to single DES. |
| 6 | `encrypt-with-3des` | `input-text` | User types a message; sees Python codegen using `cryptography.hazmat.primitives.ciphers.algorithms.TripleDES`. We don't run encryption in-browser (DES not in Web Crypto). Instead, the codegen panel shows a runnable Python script the learner can copy. |
| 7 | `done` | `info` | Recap + forward-link to AES (which is what replaced 3DES) and to the future KEK lesson. Notes that 3DES is officially deprecated by NIST as of 2023 — should not be used in new systems. |

### Canonical values

- Step 4 toy cipher: an 8-bit XOR cipher (`Cipher(key, msg) = msg XOR key`) standing in for DES. Lesson is upfront: "DES isn't this simple, but the attack pattern is the same."
- Step 4 example: known plaintext `0x42`, ciphertext after 2-round XOR with K1 and K2 = `0x7E`. User finds (K1, K2) via MITM.
- Step 6 message: user-supplied; defaults to "hello world" if empty.

## Architecture

### New algorithm record

`algorithms/triple-des/fixtures.json` follows the existing pattern. Slug `triple-des`, name "Triple DES", family `symmetric`. PKs:
- Algorithm pk=4 (RSA 1, Hybrid 2, AES 3)
- Lesson pk=4
- Steps pk=41–47

### New algorithm module directory

`static/algorithms/triple-des/`:

| File | Responsibility |
|---|---|
| `validators.js` | `mitm_attack` validator + `pick_3des_message` + `info` + `walkthroughs`. |
| `codegen.js` | `full_script` for the Python 3DES encrypt/decrypt demo. |
| `mitm.js` | The toy cipher + the MITM search (used by validator + the display panel). |
| `tests/*.test.js` | Node tests for validators, mitm, codegen. |

### MITM search (`mitm.js`)

```js
// Toy cipher: 2-round XOR, 8-bit keys
export function toyEncrypt(plaintext, k1, k2) {
  return ((plaintext ^ k1) ^ k2) & 0xFF;
}

export function mitmFind(plaintext, ciphertext) {
  // Build lookup of E(K1, plaintext) -> K1 for all K1 in 0..255
  const fwd = new Map();
  for (let k1 = 0; k1 < 256; k1++) {
    fwd.set(plaintext ^ k1, k1);
  }
  // Try every K2: compute D(K2, ciphertext) and look it up
  const matches = [];
  for (let k2 = 0; k2 < 256; k2++) {
    const dec = ciphertext ^ k2;
    if (fwd.has(dec)) matches.push([fwd.get(dec), k2]);
  }
  return matches;
}
```

The validator checks the user found (or one of) the valid (K1, K2) pairs.

### Validators

| Key | Validates | Writes |
|---|---|---|
| `mitm_attack` | User entered a valid (K1, K2) pair (multi-input, decimal or hex) | `{td_k1, td_k2}` |
| `pick_3des_message` | non-empty, ≤500 chars, printable ASCII | `{td_message}` |
| `info` | always ok | `{}` |

### Codegen (Python output)

```python
# Triple DES — generated by cloak.moosha.org
# Requires: pip install cryptography

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# 3DES needs a 24-byte key (three 8-byte DES keys concatenated)
key = os.urandom(24)
iv = os.urandom(8)  # 64-bit block size

cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
encryptor = cipher.encryptor()
decryptor = cipher.decryptor()

message = b"hello world"
# 3DES requires PKCS#7 padding to 8-byte block
from cryptography.hazmat.primitives.padding import PKCS7
padder = PKCS7(64).padder()
padded = padder.update(message) + padder.finalize()
ciphertext = encryptor.update(padded) + encryptor.finalize()

print("key:", key.hex())
print("iv :", iv.hex())
print("ct :", ciphertext.hex())

# Decrypt to confirm
unpadder = PKCS7(64).unpadder()
decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
plaintext = unpadder.update(decrypted_padded) + unpadder.finalize()
assert plaintext == message
```

Wrapped in `full_script(state)` so the user's message is interpolated.

### State namespace

All keys prefixed `td_` (e.g., `td_k1`, `td_k2`, `td_message`).

### What does NOT change

- `static/core/wizard.js` — generic.
- `core/templates/core/lesson.html` — generic. May add a slug-keyed panel for the MITM search result display (a small table of "K1=X, K2=Y" matches) if user input alone isn't visual enough.
- `core/models.py` — no schema changes.

## Data flow

```
Step 1-3 (info)         no input. state grows on advance with nothing.
Step 4 (mitm-attack)    input: K1, K2 (multi-input)
  ↓ mitm_attack validator (also exposes mitmFind for the display)
state += { td_k1, td_k2 }

Step 5 (3des-ede)       info, no input.

Step 6 (encrypt)        input: message text
  ↓ pick_3des_message
state += { td_message }
  ↓ codegen.full_script renders Python that uses TripleDES.

Step 7 (done)           info. Recap + forward links.
```

## Error handling

### Step 4 — `mitm_attack`
- Not numbers → `"Enter two whole numbers (0–255 each, decimal or 0xNN)."`
- Out of [0, 255] → `"Each key is 8 bits — 0–255."`
- Wrong pair → `"Find (K1, K2) such that toyEncrypt(plaintext, K1, K2) = ciphertext. Try the matches the lookup found: [list of valid pairs]."`

### Step 6 — `pick_3des_message`
- Same as RSA's `pick_sentence`: empty / >500 / non-ASCII rejection.

### Cross-step
- All sync (no async). Standard wizard handling applies.

## Testing

### JS validator tests
- `mitm_attack` happy (a known-valid (K1, K2) pair for the canonical example).
- `mitm_attack` rejects wrong pair, non-integer, out of range.
- `pick_3des_message` happy + standard ASCII rejections.

### JS mitm tests
- `toyEncrypt(0x42, 0x10, 0x20)` returns expected value (verifiable by hand).
- `mitmFind(0x42, expected_ciphertext)` returns at least one match including the canonical (K1, K2).
- All matches are valid (each pair encrypts plaintext to ciphertext).

### JS codegen tests
- `full_script` with state.td_message="hi" produces Python containing `algorithms.TripleDES`, `PKCS7(64)`, and `assert plaintext == message`.

### Fixture-load test
- Extend `core/tests/test_fixtures.py` with assertions for the 7-step 3DES lesson.

### Manual smoke
- Walk all 7 steps; verify MITM finds matches; verify codegen renders.

## Files touched

| File | Change |
|---|---|
| `algorithms/triple-des/fixtures.json` | CREATE |
| `static/algorithms/triple-des/validators.js` | CREATE |
| `static/algorithms/triple-des/codegen.js` | CREATE |
| `static/algorithms/triple-des/mitm.js` | CREATE |
| `static/algorithms/triple-des/tests/*.test.js` | CREATE (validators, mitm, codegen) |
| `core/tests/test_fixtures.py` | MODIFY (extend) |

## Open questions / deferred

- **MITM display panel:** the validator confirms a correct (K1, K2) pair, but the *interesting* output is the LIST of matches the brute-force finds. A new slug-keyed template branch could show "found 3 valid pairs: (10, 20), (53, 99), (200, 87) — pick any one." Adds template work; reasonable for v1.
- **Real DES via JS:** could implement single-DES in JS (~200 LOC) and use it for the MITM demo instead of XOR. Higher fidelity, much more code. Deferred.
- **NIST deprecation note:** the Done page says 3DES is deprecated. Could link to NIST SP 800-131A for credibility. Cosmetic.
