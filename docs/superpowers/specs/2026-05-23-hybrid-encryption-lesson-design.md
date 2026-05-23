# Hybrid Encryption Lesson — Design

**Date:** 2026-05-23
**Project:** `cloak`
**Working directory:** /Users/hriday/code/enc_algo

## Goal

Add a second algorithm to the site — "Hybrid Encryption" — taught as a 9-step compute-along lesson. The learner experiences the standard real-world pattern (random symmetric key + RSA wraps the key + symmetric cipher encrypts the message) end-to-end, doing every step by hand.

Because no learner can compute AES by hand, the lesson uses a tiny XOR cipher in place of AES with explicit framing: *"Real systems use AES — see the AES lesson for the algorithm itself. Here we use XOR so you can compute it."* The pattern being taught (KEK / hybrid envelope) is identical regardless of the symmetric cipher underneath.

## Curriculum context

This is the third lesson in a planned arc:

1. **RSA** (shipped) — math, encrypt/decrypt single number, then encrypt a sentence char-by-char.
2. **AES** — TBD; standalone algorithm lesson.
3. **Hybrid encryption** (this design) — composes RSA + symmetric cipher.
4. **2DES** — meet-in-the-middle attack pedagogy.
5. **Caesar**, **Vigenère** — classical pair.
6. **Blowfish** — alternative symmetric.
7. **KEK / HSM** — generalizes hybrid into multi-layer key hierarchies, HSM-bound keys, KMS patterns.

The Done page of this lesson includes a one-line forward-link to the future KEK/HSM lesson so learners see this pattern is the foundation of production key management.

## Non-goals

- Real AES (deferred to its own lesson).
- Cryptographically random key generation (the learner picks a number; lesson narration covers what real systems do).
- Multi-block RSA, RSA padding (OAEP), or signatures.
- Key exchange algorithms (Diffie-Hellman, ECDHE).
- Cross-lesson state import (the hybrid lesson doesn't read RSA lesson 1's state; it uses its own canonical keys).

## User experience

The lesson lives at `/algorithms/hybrid/learn/wrap-and-send/`. The algorithm appears as a new card on the landing page alongside RSA.

### Step sequence

| # | Slug | Kind | Behavior |
|---|---|---|---|
| 1 | `intro` | `info` | Motivates the hybrid pattern: RSA can't fit big things; we wrap a *key* with RSA and use a fast symmetric cipher for the data. Three actors named: RSA keypair, random symmetric key, symmetric cipher. |
| 2 | `meet-symmetric` | `info` | Introduces AES. Copy: *"Real systems use AES — see the AES lesson for the algorithm itself. Here we use a tiny XOR-based cipher so you can do every step by hand. The pattern (random key + symmetric cipher + RSA wraps the key) is identical."* Link to `/algorithms/aes/` (404 acceptable until that lesson exists). |
| 3 | `pick-sym-key` | `input-numeric` | "Pick any number from 0 to 127 — that's your symmetric key." Stored as `h_sym_key`. |
| 4 | `wrap-key` | `input-numeric` | Compute `c_key = sym_key^e mod n` with canonical keys (e=7, n=143). Stored as `h_wrapped_key`. Prompt notes: *"These RSA keys are given; if you want to see them derived, that's the RSA lesson."* |
| 5 | `type-message` | `input-text` | Textarea, ≤500 printable ASCII chars. Stored as `h_message` plus `h_first_char`, `h_first_code`. |
| 6 | `xor-encrypt` | `input-numeric` | User computes `first_char_ASCII XOR sym_key` for the first character. On Check, validator confirms and auto-fills `h_ciphertext = [c_i XOR sym_key for c_i in message]`. |
| 7 | `unwrap-key` | `input-numeric` | Receiver-side: compute `m_key = c_key^d mod n` with d=103. Stored as `h_recovered_key`. |
| 8 | `xor-decrypt` | `input-numeric` | User computes `ciphertext[0] XOR recovered_key` for the first byte. On Check, validator confirms and auto-fills `h_recovered_message`. |
| 9 | `done` | `info` | Roundtrip display + full Python script + back-links + KEK forward-link. |

### Canonical RSA keys

Hard-coded into the lesson: **p=11, q=13, n=143, φ=120, e=7, d=103.**

- Max sym key (127) fits in `n` (143). ✓
- e=7 is coprime to φ=120 (`gcd(7, 120) = 1`). ✓
- d=103 because `7·103 = 721 = 6·120 + 1`, so `7d ≡ 1 (mod 120)`. ✓
- Small enough for the user to compute `m^e mod n` by hand for a small number.

The lesson does not require the learner to derive these — the prompts state them as given, with a link back to the RSA lesson for the derivation.

### Roundtrip display panel

Mirrors the RSA lesson's `messageRoundtrip` pattern. Rendered on steps 6, 7, 8, 9:

> **Wrapped key (RSA):** `81`
> **Ciphertext (XOR):** `66, 67`
> **Recovered:** `'hi'` ✓ matches *(only after step 8)*

## Architecture

### New algorithm record

Added to a new `algorithms/hybrid/fixtures.json` (mirrors the shape of `algorithms/rsa/fixtures.json`):

```json
{ "model": "core.algorithm", "pk": 2, "fields": {
    "slug": "hybrid", "name": "Hybrid Encryption", "family": "asymmetric",
    "status": "live", "order": 2, "intro_template": ""
}}
```

Algorithm slug `hybrid` chosen for URL brevity (`/algorithms/hybrid/`). Family `asymmetric` because RSA is the keystone operation.

### New lesson + 9 steps

Same fixture file. Lesson `wrap-and-send` with PK 2 (RSA's lesson is PK 1). Step PKs use the **21–29 range** to avoid collision with RSA's step PKs (which occupy 1–15). Loaddata replaces by PK, so any overlap with RSA's 1–15 would silently overwrite RSA steps. The 21+ range leaves headroom (16–20) for any future RSA extensions.

### New algorithm module directory: `static/algorithms/hybrid/`

| File | Responsibility |
|---|---|
| `validators.js` | Per-step validators + walkthroughs. ~150 LOC estimated. |
| `codegen.js` | Generates a hybrid-encryption Python script for the "Show full script" panel. |
| `math.js` | `xorBytes(text, key) → number[]`, plus re-exports of `modPow`, `modInv`, `isPrime`, `gcd` from `../rsa/math.js` (so consumers can `import { modPow } from "../hybrid/math.js"` without reaching into another algorithm's directory). |
| `tests/validators.test.js` | Node test coverage for the 6 actionable validators. |
| `tests/codegen.test.js` | Node test that `full_script` produces a valid Python script with expected lines. |
| `tests/math.test.js` | Tests for `xorBytes` (happy + roundtrip) and one re-export sanity check. |

### Validators

| Validator key | Validates | On success, writes |
|---|---|---|
| `pick_sym_key` | integer in `[0, 127]` | `{ h_sym_key }` |
| `wrap_key` | `got === sym_key^7 mod 143` | `{ h_wrapped_key }` |
| `type_message` | length 1–500, all chars in printable ASCII (32–126) | `{ h_message, h_first_char, h_first_code }` |
| `xor_encrypt_head` | `got === h_message[0] XOR h_sym_key` | `{ h_ciphertext: [...] }` (full array) |
| `unwrap_key` | `got === h_wrapped_key^103 mod 143` | `{ h_recovered_key }` |
| `xor_decrypt_head` | `got === h_ciphertext[0] XOR h_recovered_key` | `{ h_recovered_message: "..." }` |
| `info` | always ok | `{}` |

### Walkthroughs ("I don't know how")

For the four actionable RSA/XOR steps (`wrap_key`, `xor_encrypt_head`, `unwrap_key`, `xor_decrypt_head`), each walkthrough has three rungs: method → worked example → answer. Pattern reused verbatim from RSA's `walkthroughs` object.

### State namespace

All keys prefixed with `h_` (e.g. `h_sym_key`, `h_wrapped_key`, `h_message`, `h_ciphertext`, `h_recovered_key`, `h_recovered_message`) to keep this lesson's state visually distinct from RSA's. localStorage already isolates per `(algorithm_slug, lesson_slug)` tuple, so this is purely for code readability.

### What does NOT change

- `static/core/wizard.js` — generic; loads algorithm modules dynamically.
- `core/templates/core/lesson.html` — generic; renders any step kind.
- `core/models.py` — no schema changes (no new step kinds; all are existing `info`, `input-numeric`, `input-text`).
- `core/views.py` — generic URL pattern already supports any algorithm/lesson slug pair.

## Data flow

```
Step 1 (intro)           no input. state = {}
Step 2 (meet-symmetric)  no input. info advance.
Step 3 input             sym_key: 42
  ↓ pick_sym_key
state += { h_sym_key: 42 }

Step 4 input             user computes 42^7 mod 143 = 81
  ↓ wrap_key validator (canonical e=7, n=143)
state += { h_wrapped_key: 81 }

Step 5 input             message: "hi"
  ↓ type_message
state += { h_message: "hi", h_first_char: "h", h_first_code: 104 }

Step 6 input             user computes 104 XOR 42 = 66
  ↓ xor_encrypt_head validator
state += { h_ciphertext: [66, 67] }
  (104^42 = 66; 105^42 = 67)

Step 7 input             user computes 81^103 mod 143 = 42
  ↓ unwrap_key validator (canonical d=103)
state += { h_recovered_key: 42 }

Step 8 input             user computes 66 XOR 42 = 104
  ↓ xor_decrypt_head validator
state += { h_recovered_message: "hi" }

Step 9 (done)            info; show roundtrip + full script + links
```

## Error handling

### Step 3 — `pick_sym_key`
- Non-integer → `"Enter a whole number."`
- < 0 or > 127 → `"Pick a number from 0 to 127 (so it fits in our RSA key, n=143)."`

### Step 4 — `wrap_key`
- Wrong value → `"c = m^e mod n. With m={h_sym_key}, e=7, n=143."`

### Step 5 — `type_message`
- Empty → `"Type at least one character."`
- > 500 → `"Keep it under 500 characters."`
- Non-printable-ASCII char → `"Only printable ASCII for now — no emoji, accents, tabs, or newlines. Found: '<offender>'."`

### Step 6 — `xor_encrypt_head`
- Wrong value → `"Compute first_char XOR sym_key. With first_char = {h_first_code} (ASCII of '{h_first_char}') and sym_key = {h_sym_key}."`
- On success: validator computes `h_ciphertext = [c XOR h_sym_key for c in h_message]` in one shot.

### Step 7 — `unwrap_key`
- Wrong value → `"m = c^d mod n. With c={h_wrapped_key}, d=103, n=143."`

### Step 8 — `xor_decrypt_head`
- Wrong value → `"Compute first_ciphertext_byte XOR recovered_key. With c[0] = {h_ciphertext[0]} and recovered_key = {h_recovered_key}."`
- On success: validator computes `h_recovered_message` and writes it to state.

### Step 9 — `done`
- No input. If `h_recovered_message !== h_message`, render a visible error block ("Key derivation bug — please reload"). Should never fire in practice.

### Resume / stale state
- Same model as RSA: `currentStepOrder` is clamped to `steps.length` on load. Resuming users always land on a consistent step.

### Cross-step invariants
- Steps 6 and 8 are deterministic functions of the head value + state. No randomness; sender and receiver sides produce identical streams.

## Codegen output

`full_script(state)` returns a single Python file the learner can copy/run:

```python
# Hybrid encryption — generated by cloak.moosha.org

# RSA keypair (see RSA lesson for derivation)
p, q = 11, 13
n = p * q                            # 143
phi = (p - 1) * (q - 1)              # 120
e = 7                                # coprime to phi
d = pow(e, -1, phi)                  # 103

# Sender side
sym_key = 42                         # in real life: 32 random bytes for AES-256
wrapped_key = pow(sym_key, e, n)     # RSA wraps the symmetric key
message = "hi"
ciphertext = [ord(ch) ^ sym_key for ch in message]   # XOR stands in for AES

# Send: [wrapped_key, ciphertext]

# Receiver side
recovered_key = pow(wrapped_key, d, n)
recovered = "".join(chr(c ^ recovered_key) for c in ciphertext)
assert recovered == message
```

The script is shown only on step 9 (Done), same trigger as RSA lesson.

## Testing

### JS validator tests
- `pick_sym_key`: happy (42), too low (-1), too high (128), non-integer.
- `wrap_key`: happy (`42^7 mod 143 = 81`), wrong value, hint contains m/e/n.
- `type_message`: happy, empty, > 500, non-ASCII, newline.
- `xor_encrypt_head`: happy ("hi" → asserts `h_ciphertext[0]` and `[1]`), wrong value, hint contains both operands.
- `unwrap_key`: happy (`81^103 mod 143 = 42`), wrong value.
- `xor_decrypt_head`: happy (`h_recovered_message === "hi"`), wrong value.

### JS math tests
- `xorBytes("hi", 42)` → `[66, 67]`.
- Roundtrip: text → `xorBytes(_, k)` → string-of-chars → `xorBytes(_, k)` recovers original text.
- One sanity assertion that `modPow` is correctly re-exported.

### JS codegen test
- `full_script(state)` with full state produces output containing:
  - `sym_key = 42`
  - `wrapped_key = pow(sym_key, e, n)`
  - `ord(ch) ^ sym_key for ch in message`
  - `assert recovered == message`

### Fixture-load test (extends existing `core/tests/test_fixtures.py`)
- After loading `algorithms/hybrid/fixtures.json`:
  - `Algorithm.objects.filter(slug="hybrid").count() == 1`
  - `Lesson.objects.filter(slug="wrap-and-send").count() == 1`
  - 9 steps in expected order with expected slugs.

### Python tests
Skipped — the JS validators are the load-bearing logic and tests cover them. No Python mirror needed for this lesson. (RSA has Python mirrors for historical reasons; we don't have to follow suit.)

### Manual smoke (pre-merge)
- Full happy path: walk all 9 steps with sym_key=42, message="hi" → ends on Done with roundtrip ✓.
- Wrong-input path: enter a wrong wrap value, see the hint, fix, continue.
- Resume: refresh mid-step-6 (after typing message, before encrypting); state restores.
- Cross-lesson isolation: complete RSA lesson 1, then start hybrid lesson — confirm states don't bleed (separate localStorage keys).

## Files touched

| File | Change |
|---|---|
| `algorithms/hybrid/fixtures.json` | **CREATE** — algorithm + lesson + 9 steps. |
| `static/algorithms/hybrid/validators.js` | **CREATE** — 6 validators + walkthroughs. |
| `static/algorithms/hybrid/codegen.js` | **CREATE** — `full_script(state)`. |
| `static/algorithms/hybrid/math.js` | **CREATE** — `xorBytes` + re-exports from `../rsa/math.js`. |
| `static/algorithms/hybrid/tests/validators.test.js` | **CREATE** — node tests. |
| `static/algorithms/hybrid/tests/codegen.test.js` | **CREATE** — node test. |
| `static/algorithms/hybrid/tests/math.test.js` | **CREATE** — node tests. |
| `core/tests/test_fixtures.py` | **MODIFY** — extend with hybrid-lesson assertions. |

No changes to wizard.js, lesson.html, models.py, or views.py. All infrastructure is already algorithm-generic.

## Open questions / deferred

- **AES lesson link**: step 2 links to `/algorithms/aes/`, which will 404 until the AES lesson exists. Acceptable for now — the link communicates intent and becomes live when AES ships.
- **KEK forward-link copy**: the Done step mentions KEK and the future HSM lesson. The exact wording is deferred to implementation; the design just requires the forward-link to exist.
- **Algorithm `intro_template`**: the algorithm intro page (`/algorithms/hybrid/`) needs short copy explaining what hybrid encryption is. Drafted at implementation time, kept under 200 words to match the RSA intro page tone.
