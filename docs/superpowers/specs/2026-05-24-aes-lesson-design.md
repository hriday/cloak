# AES Lesson — Design

**Date:** 2026-05-24
**Project:** `cloak`
**Working directory:** /Users/hriday/code/enc_algo

## Goal

Add a third algorithm to the site — **AES** — taught as an 8-step lesson that walks the learner through the four AES "moves" (SubBytes, ShiftRows, MixColumns, AddRoundKey) in isolation, then composes them in one demo round, then has the user encrypt a real message via the browser's Web Crypto API.

Because AES (10 rounds of 4 transformations × 16-byte state × GF(2⁸) arithmetic) is intractable to compute end-to-end by hand, this lesson takes a different shape from the existing RSA / Hybrid lessons. Rather than chaining state from step to step, each transformation is taught as an isolated demo — the user does a small interactive operation (S-box lookup, row shift, one XOR) and sees the move illustrated on a small fixed example. MixColumns is demo-only because the GF(2⁸) matrix multiplication is too involved for hand computation. The lesson closes with a real AES-GCM encryption via Web Crypto, which gives the learner a concrete artifact ("here's the ciphertext your message becomes") to anchor the conceptual moves.

## Curriculum position

This is the second symmetric cipher introduced (after the toy XOR in the Hybrid lesson), and the third algorithm overall:

1. **RSA** (shipped) — asymmetric, full compute-along.
2. **Hybrid Encryption** (shipped) — RSA wraps a key for a tiny XOR-as-AES stand-in. Includes a forward link to this AES lesson.
3. **AES** (this design) — symmetric block cipher, "watch the moves + encrypt for real."
4. **3DES** (planned) — pedagogically demonstrates meet-in-the-middle attack.
5. **Caesar / Vigenère / Blowfish / KEK-HSM** — future.

Once shipped, the hybrid lesson's `/algorithms/aes/` link will resolve correctly.

## Non-goals

- All 10 rounds of AES-128 (only one round is demonstrated).
- AES key expansion / round-key derivation (round key in step 5 is hardcoded).
- AES-192 / AES-256 (only AES-128 in step 7).
- Modes of operation (ECB/CBC/CTR/GCM) explained as concepts — step 7 uses GCM under the hood without unpacking it. A future "AES modes" lesson can do that.
- Inverse operations (InvSubBytes / InvShiftRows / InvMixColumns) — decryption is shown but not deconstructed.
- Side-channel discussion (timing attacks, etc.).
- Python `cryptography` library tutorial — codegen produces a runnable demo, not a how-to.

## User experience

The lesson lives at `/algorithms/aes/learn/four-transformations/`. AES appears as a new card on the landing page next to RSA and Hybrid Encryption.

### Step sequence

| # | Slug | Kind | Behavior |
|---|---|---|---|
| 1 | `intro` | `info` | Motivates AES: block cipher, 16-byte state, 10 rounds of 4 moves with rotating round keys. "Real AES is too much to compute by hand. We'll learn each move in isolation, then watch them work together on a real input." |
| 2 | `sub-bytes` | `input-numeric` | Renders the full 16×16 AES S-box as a grid (256 hex bytes). Highlights row 5 column 3. Prompt: "Look up byte 0x53 in the S-box — find the byte at row 5, column 3." Validator accepts decimal (`237`) or hex (`0xED`/`ED`). Answer: `0xED`. |
| 3 | `shift-rows` | `input-multi` | Displays a 4×4 state grid. Asks the user to enter the 4 bytes of row 1 after shifting left by 1. Input: `[0x09, 0xCF, 0x4F, 0x3C]`. Expected output: `[0xCF, 0x4F, 0x3C, 0x09]`. |
| 4 | `mix-columns` | `info` | Pure demo. Shows one column being multiplied by the MixColumns matrix in GF(2⁸). Explains: "This is the 'spread' step — a change in one byte affects the whole column. The GF(2⁸) math is too much by hand; here it is computed for you." Source: `[0xDB, 0x13, 0x53, 0x45]` → `[0x8E, 0x4D, 0xA1, 0xBC]` (Wikipedia's canonical test vector). |
| 5 | `add-round-key` | `input-numeric` | User XORs one state byte with the corresponding round key byte. With state byte = `0xED` (from step 2's output) and round-key byte = `0x2B`, answer is `0xC6`. Same XOR shape as the Hybrid lesson. |
| 6 | `one-real-round` | `info` | Demo. Displays a fixed 16-byte input block + 16-byte round key, then renders the state after each transformation in sequence (input → SubBytes → ShiftRows → MixColumns → AddRoundKey). Real values from `SBOX` + `mixColumn`. Caption: "These four moves are one round. AES-128 does this 10 times." |
| 7 | `encrypt-a-message` | `input-text` | User types a sentence (≤500 ASCII chars). On Continue, browser's Web Crypto API encrypts it: AES-GCM, 128-bit random key, 12-byte random IV. Displays the key (hex), IV (hex), and ciphertext (hex). Decrypts immediately and shows recovered text to close the loop. |
| 8 | `done` | `info` | Roundtrip display (Original / Key / IV / Ciphertext / Decrypted ✓ matches) + back-links + forward-link to a future "AES modes" lesson and to KEK/HSM. |

### Canonical values

All values used in prompts are baked into the lesson so the answer is reproducible:

- **SubBytes:** S-box lookup of 0x53. Standard AES S-box gives `0xED`.
- **ShiftRows:** input row `[0x09, 0xCF, 0x4F, 0x3C]` → output `[0xCF, 0x4F, 0x3C, 0x09]`.
- **MixColumns:** column `[0xDB, 0x13, 0x53, 0x45]` → `[0x8E, 0x4D, 0xA1, 0xBC]` (Wikipedia's standard test vector).
- **AddRoundKey:** state byte `0xED` XOR round key byte `0x2B` = `0xC6`.
- **One real round (step 6):** a hardcoded 16-byte input + 16-byte round key; intermediate states computed client-side from `SBOX`, `SHIFT_OFFSETS`, and `mixColumn`.

## Architecture

### New algorithm record

`algorithms/aes/fixtures.json` follows the same shape as RSA's and hybrid's:

```json
{ "model": "core.algorithm", "pk": 3, "fields": {
    "slug": "aes", "name": "AES", "family": "symmetric",
    "status": "live", "order": 3, "intro_template": "..."
}}
```

`family: symmetric` — the first symmetric algorithm on the site. The hybrid lesson's `/algorithms/aes/` link starts resolving.

### New lesson + 8 steps

Same fixture file. Lesson `four-transformations`, PK 3. Step PKs **31–38** (RSA uses 1–15, hybrid 21–29, gap at 16–20 and 30 for future RSA/hybrid extensions).

### New algorithm module directory `static/algorithms/aes/`

| File | Responsibility |
|---|---|
| `tables.js` | Exports `SBOX` (256-byte array), `SHIFT_OFFSETS = [0, 1, 2, 3]`, `mixColumn(col) → newCol` (GF(2⁸) matrix multiply for one 4-byte column). |
| `validators.js` | Three actionable validators (`sub_byte`, `shift_row`, `add_round_key`) + `pick_aes_message` + `info` + `walkthroughs` object. |
| `codegen.js` | `full_script(state)` emits a runnable Python AES-GCM demo using the `cryptography` library. Per-step inline snippets are mostly empty (info steps emit nothing). |
| `aes_demo.js` | Thin async wrapper around browser-native `crypto.subtle` for step 7. Exports `encryptMessage(plaintext) → Promise<{keyHex, ivHex, ciphertextHex, recovered}>`. |
| `tests/validators.test.js` | Node tests for the 4 validators. |
| `tests/tables.test.js` | Node tests for SBOX entries + mixColumn test vector. |
| `tests/codegen.test.js` | Node test for `full_script` output. |

`aes_demo.js` isn't unit-tested (Node's `node:test` doesn't have Web Crypto). Verified manually via Playwright in the smoke check.

### Validators

| Key | Validates | On success, writes |
|---|---|---|
| `sub_byte` | accepts decimal or `0xNN` hex; integer in [0, 255]; equals `SBOX[input_byte]` | `{a_sub_input, a_sub_output}` |
| `shift_row` | 4 bytes, each in [0, 255]; order matches `[r1[1], r1[2], r1[3], r1[0]]` for the lesson's input row | `{a_shifted_row}` |
| `add_round_key` | integer in [0, 255]; equals `state_byte XOR round_key_byte` (specific values in prompt) | `{a_ark_input, a_ark_key, a_ark_output}` |
| `pick_aes_message` | non-empty, ≤500 chars, all printable ASCII (32–126) | `{a_message}` |
| `info` | always ok | `{}` |

### Web Crypto integration (step 7)

The wizard, on step 7 success, calls `aes_demo.encryptMessage(state.a_message)`:

```js
async function encryptMessage(plaintext) {
  const key = await crypto.subtle.generateKey({name: "AES-GCM", length: 128}, true, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ptBytes = new TextEncoder().encode(plaintext);
  const ctBuffer = await crypto.subtle.encrypt({name: "AES-GCM", iv}, key, ptBytes);
  const recoveredBuffer = await crypto.subtle.decrypt({name: "AES-GCM", iv}, key, ctBuffer);
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

Results are written to state: `a_key_hex`, `a_iv_hex`, `a_ciphertext_hex`, `a_recovered`.

### Walkthroughs ("I don't know how")

For the 3 actionable steps (`sub_byte`, `shift_row`, `add_round_key`) — three escalating rungs each:
- Method (what the operation does conceptually)
- Worked example (point at where to look in the displayed table/grid)
- Answer (the literal value)

Mirrors the walkthrough pattern from RSA / Hybrid.

### Template changes

`core/templates/core/lesson.html` gets new slug-keyed branches under the `info` template for the demo steps (`mix-columns`, `one-real-round`, `done`) and additional render blocks for the interactive grids in steps 2, 3, 5. Pattern mirrors the existing RSA `toy-complete` / `done` branches.

### State namespace

All keys prefixed `a_` (e.g., `a_sub_input`, `a_shifted_row`, `a_ark_output`, `a_message`, `a_key_hex`, `a_iv_hex`, `a_ciphertext_hex`, `a_recovered`) to keep this lesson's state visually distinct from RSA's and hybrid's.

### What does NOT change

- `static/core/wizard.js` — the wizard is generic; loads algorithm modules dynamically.
- `core/models.py` — no schema changes (all step kinds already exist).
- `core/views.py` — URL pattern already supports any algorithm/lesson slug pair.
- `algorithms/rsa/*` and `algorithms/hybrid/*` — untouched.

## Data flow

```
Step 1 (intro)         no input. state = {}
Step 2 (sub-bytes)     input: "0xED" (or "237")
  ↓ sub_byte validator
state += { a_sub_input: 0x53, a_sub_output: 0xED }

Step 3 (shift-rows)    input: 4 bytes
  ↓ shift_row validator
state += { a_shifted_row: [0xCF, 0x4F, 0x3C, 0x09] }

Step 4 (mix-columns)   info — no input. Demo column displayed.

Step 5 (add-round-key) input: "0xC6" (or "198")
  ↓ add_round_key validator
state += { a_ark_input: 0xED, a_ark_key: 0x2B, a_ark_output: 0xC6 }

Step 6 (one-real-round) info — no input. 5 grids rendered client-side.

Step 7 (encrypt-msg)   input: "hello world"
  ↓ pick_aes_message → state += { a_message: "hello world" }
  ↓ async aes_demo.encryptMessage
state += { a_key_hex, a_iv_hex, a_ciphertext_hex, a_recovered }

Step 8 (done)          info. Roundtrip display + forward-link.
```

**Key property:** steps 2, 3, 4, 5 are independent. State written in each doesn't feed the next. The lesson is resilient — if a user gets stuck on MixColumns, the encrypt step still works.

## Error handling

### Step 2 — `sub_byte`
- Not parseable → `"Enter a byte value (0–255 in decimal, or 0xNN in hex)."`
- Out of [0, 255] → `"S-box outputs a byte. Enter 0–255 (or 0xNN)."`
- Wrong value → `"The S-box at row 5, column 3 (input 0x53) is 0xED (decimal 237). Look at the highlighted cell above."`

Validator accepts: decimal (`237`), uppercase hex (`ED`, `0xED`), lowercase hex (`ed`, `0xed`).

### Step 3 — `shift_row`
- Not 4 numbers → `"Enter 4 bytes (one per column)."`
- Any out of [0, 255] → `"Each value must be 0–255."`
- Wrong order → `"Row 1 shifts left by 1, so input [0x09, 0xCF, 0x4F, 0x3C] becomes [0xCF, 0x4F, 0x3C, 0x09] — the first byte wraps to the end."`

### Step 5 — `add_round_key`
- Not parseable / out of range → same byte hints as step 2
- Wrong value → `"AddRoundKey is byte-wise XOR. With state byte = 0xED (237) and round-key byte = 0x2B (43), compute 237 XOR 43 = 198 (0xC6)."`

### Step 7 — `pick_aes_message` + Web Crypto
- Validator-level errors mirror `pick_sentence` (empty, >500, non-ASCII).
- Web Crypto rejection (browser doesn't support AES-GCM, extremely rare): caught, sets `state.a_encrypt_error`. Step 7 panel renders the error message instead of the roundtrip.
- Web Crypto succeeds but `a_recovered !== a_message`: shouldn't happen; render a loud "key derivation bug — please reload" message.

### Cross-step
- Steps 2–5 are independent. A failure on one doesn't break others.
- `currentStepOrder` clamps to `steps.length` on load (same as RSA / hybrid).

## Testing

### JS validator tests (`static/algorithms/aes/tests/validators.test.js`)
- `sub_byte`: happy (`"0xED"` and `"237"` both succeed for input 0x53), wrong value, out of range, unparseable.
- `shift_row`: happy (`["0x09", "0xCF", "0x4F", "0x3C"]` → `[0xCF, 0x4F, 0x3C, 0x09]`), wrong order, missing values.
- `add_round_key`: happy (state=0xED, key=0x2B → 0xC6), wrong value.
- `pick_aes_message`: happy, empty, >500, non-ASCII.

### JS tables tests (`static/algorithms/aes/tests/tables.test.js`)
- `SBOX[0x00] === 0x63` (canonical first byte)
- `SBOX[0xFF] === 0x16`
- `SBOX.length === 256`
- `SHIFT_OFFSETS` deep-equals `[0, 1, 2, 3]`
- `mixColumn([0xDB, 0x13, 0x53, 0x45])` deep-equals `[0x8E, 0x4D, 0xA1, 0xBC]`

### JS codegen test (`static/algorithms/aes/tests/codegen.test.js`)
- `full_script({a_message: "hi"})` contains:
  - `from cryptography.hazmat.primitives.ciphers.aead import AESGCM`
  - `key = AESGCM.generate_key(bit_length=128)`
  - `aesgcm = AESGCM(key)`
  - `ciphertext = aesgcm.encrypt(iv, message, None)`
  - `assert plaintext == message`

### Fixture-load test (`core/tests/test_fixtures.py` — extend)
- After loading `algorithms/aes/fixtures.json`:
  - `Algorithm.objects.filter(slug="aes").count() == 1`
  - `Lesson.objects.filter(slug="four-transformations").count() == 1`
  - 8 steps in expected order with expected slugs

### Manual smoke (post-implementation)
- Walk all 8 steps with canonical answers (`0xED`, `[0xCF, 0x4F, 0x3C, 0x09]`, `0xC6`, message `"hello"`).
- Verify step 7's Web Crypto path: hex strings render, decrypted matches.
- Cross-browser sanity: at minimum confirm in the browser you're using.

No Python tests — same rationale as Hybrid: JS validators are load-bearing; fixture loading is covered by the test_fixtures extension.

## Files touched

| File | Change |
|---|---|
| `algorithms/aes/fixtures.json` | **CREATE** — algorithm + lesson + 8 steps |
| `static/algorithms/aes/tables.js` | **CREATE** — SBOX, SHIFT_OFFSETS, mixColumn |
| `static/algorithms/aes/validators.js` | **CREATE** — 4 validators + walkthroughs |
| `static/algorithms/aes/codegen.js` | **CREATE** — full_script + per-step stubs |
| `static/algorithms/aes/aes_demo.js` | **CREATE** — Web Crypto wrapper |
| `static/algorithms/aes/tests/validators.test.js` | **CREATE** |
| `static/algorithms/aes/tests/tables.test.js` | **CREATE** |
| `static/algorithms/aes/tests/codegen.test.js` | **CREATE** |
| `core/templates/core/lesson.html` | **MODIFY** — add slug-keyed branches for AES demo + grid steps |
| `core/tests/test_fixtures.py` | **MODIFY** — extend with AES fixture assertions |

No changes to: `static/core/wizard.js`, `core/models.py`, `core/views.py`, `algorithms/rsa/*`, `algorithms/hybrid/*`.

## Open questions / deferred

- **AES modes lesson**: step 8's done page links to a future `/algorithms/aes-modes/` lesson. Acceptable to 404 until that ships.
- **MixColumns interactivity**: step 4 is demo-only. If learners ask for more, a future iteration could add a stepped walkthrough of the GF(2⁸) multiplication — but it'd be a heavy lift relative to the pedagogical payoff.
- **S-box presentation**: the 16×16 grid will be ~256 cells. Worth confirming visually that it fits on standard mobile widths without horizontal scroll. If not, we use compact 2-digit hex with tight spacing.
