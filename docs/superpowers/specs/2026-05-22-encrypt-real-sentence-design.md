# Encrypt a Real Sentence — RSA Lesson Extension

**Date:** 2026-05-22
**Project:** `cloak`
**Working directory:** /Users/hriday/code/enc_algo

## Goal

Extend the existing RSA lesson so that, after completing the toy single-number example, the learner can choose to encrypt a real ASCII sentence (up to 500 characters). The extension makes the connection between the toy math they just did and how real text becomes ciphertext, walks through the text-to-numbers encoding (with binary shown as an intermediate step), has them encrypt the first character themselves, and ends in a live playground where they can edit the sentence and watch it re-encrypt.

Sequenced pedagogy:

1. **Connect** — same `m^e mod n`, just done many times.
2. **Encode** — text → ASCII → binary is visible per character.
3. **Play** — free-form input, no advancement, live re-encryption.

## Non-goals

- Block-packing (multiple chars into one RSA block).
- Bit-by-bit RSA.
- UTF-8 / emoji / accented characters.
- Hybrid encryption (RSA-wrapping a symmetric key).
- A separate "encrypt-a-sentence" lesson or playground page. This is an extension of the existing `encrypt-decrypt` lesson, not a new lesson.

## User experience

The lesson grows from 10 steps to 15 steps. New steps slot in between current step 9 (`decrypt`) and current step 10 (`done`). The current `done` step is redesigned into a Playground + extended Done. A new "soft done" appears at step 10 that gates entry into the new flow.

### Step-by-step

| # | New/Existing | Slug | Kind | Behavior |
|---|---|---|---|---|
| 1–9 | existing | unchanged | various | toy primes, message=2, encrypt, decrypt |
| **10** | **new** | `toy-complete` | `info-with-fork` (new sub-variant of `info`) | "Toy lesson complete." Shows recap + mini full-script. Two CTAs visible: **"Encrypt a real sentence →"** advances to step 11; **"Back to algorithms" / "My progress"** exits. Lesson is marked complete here even if user exits. |
| **11** | **new** | `pick-big-primes` | `input-multi` | "Pick new primes p ≥ 17 and q ≥ 17 so n ≥ 256." On valid input, the validator also derives n2, φ2, e2, d2 and writes all of them to state. Next step's prompt shows a recap card with the derived values. |
| **12** | **new** | `type-sentence` | `input-text` (new kind) | Textarea, max 500 ASCII chars. Live conversion table (char / binary / ASCII) renders below and updates as the user types. "Continue" locks the sentence in. |
| **13** | **new** | `encrypt-sentence` | `input-numeric` | "Encrypt the first character." Shows the first char's char/binary/ASCII and asks for `c = sentence[0]^e2 mod n2`. On Check, validator confirms and computes the full encrypted array. Table grows a fourth column with the rest filled in automatically. |
| **14** | **new** | `decrypt-sentence` | `info` | Walks the encrypted column back through `c^d2 mod n2`. Shows the assembled decrypted string equals the original. |
| **15** | modified (was step 10) | `done` | `info` | Editable Playground (sentence box that re-encrypts live on each keystroke; ephemeral, no persistence) + the full script (now includes the sentence encoder/decoder block) + existing back-to-algorithms / dashboard links. |

### Opt-out path

A user who clicks "Back to algorithms" at step 10 has `current_step_order = 10` saved. On resume, they land on step 10 with both CTAs still visible — they can change their mind any time.

### Progress bar

Shows `min(currentStepOrder, 10) of 10` until the user opts in at step 10; expands to `N of 15` after. Wizard reads this from a derived getter, not a separate stored value, so resume re-derives correctly.

## Architecture

### State shape additions

```
state.p2, state.q2          // new bigger primes
state.n2, state.phi2          // derived in step 11 validator
state.e2, state.d2            // derived in step 11 validator
state.sentence               // string, locked in at step 12
state.encrypted              // array<int>, locked in at step 13
                              // (omitted from server payload; small enough to keep but recomputable)
```

`state.decrypted` is NOT persisted — recomputed at step 14 / 15 from `encrypted + d2 + n2`.

### New step kinds

**`input-text`** — a new wizard step kind, rendered as a `<textarea>` with a live character counter and a live conversion table panel. Same `Check` and `I don't know how` button pair as numeric steps; `Check` invokes `pick_sentence` validator.

**`info-with-fork`** — implemented as a variant of the existing `info` kind, identified by `step.slug` (no new top-level kind needed). Step 10's template branch renders two CTAs side-by-side instead of the single `Continue` button.

### New validators (mirrored Python + JS)

| Key | Validates | On success, writes |
|---|---|---|
| `pick_pq_big` | `p ≥ 17`, `q ≥ 17`, both prime, `p ≠ q`, `p·q ≥ 256` | `{p2, q2, n2, phi2, e2, d2}` |
| `pick_sentence` | non-empty, ≤ 500 chars, all chars in printable ASCII 32–126 | `{sentence}` |
| `encrypt_sentence_head` | `got == sentence[0]^e2 mod n2` | `{encrypted}` (full array) |

**`e2` selection:** deterministic — smallest integer `e ≥ 3` such that `gcd(e, phi2) == 1`. No randomness so the lesson is reproducible across sessions and across JS/Python.

**`d2` computation:** `modinv(e2, phi2)`, reusing the existing helper.

### New math helpers (`static/algorithms/rsa/math.js` + Python equivalent)

- `textToCodes(s: string) → number[]` — `[s.charCodeAt(i) for i in range(len(s))]`
- `codesToText(arr: number[]) → string`
- `toBinary8(n: number) → string` — 8-bit zero-padded binary (e.g. `72 → "01001000"`)

### Codegen extension

`full_script` is extended so that, when `state.sentence` is present, it appends a small block:

```python
# Encrypt a real sentence
sentence = "Hi"
encrypted = [pow(ord(ch), e2, n2) for ch in sentence]
decrypted = "".join(chr(pow(c, d2, n2)) for c in encrypted)
assert decrypted == sentence
```

A new `encode_sentence` codegen function powers the inline "Python for this step" panel on step 13.

### Walkthroughs (carry the "I don't know how" pattern forward)

- `pick_pq_big`: method → example pair (17, 19) → why this satisfies n ≥ 256
- `encrypt_sentence_head`: method → walked rows for the actual char in question → answer
- `pick_sentence`, info steps: no walkthrough (no "right answer")

## Data flow

```
Step 11 input          { p2: 17, q2: 19 }
  ↓ pick_pq_big validator computes the rest
state grows:           + n2:323, phi2:288, e2:5, d2:173
                       (e2 = smallest int ≥ 3 coprime to 288;
                        d2 = modinv(5, 288))

Step 12 input          sentence: "Hi"
  ↓ pick_sentence validator (length/charset OK)
state grows:           + sentence:"Hi"
  ↓ display side-effect (no state write)
table renders:         [{ch:"H", bin:"01001000", code:72},
                        {ch:"i", bin:"01101001", code:105}]

Step 13 input          first encrypted value (72^5 mod 323 = ?)
  ↓ encrypt_sentence_head validator
state grows:           + encrypted: [encrypt(72), encrypt(105)]
  ↓ table re-renders with 4th column populated

Step 14                no input — info step
  ↓ on render, derive
ephemeral:             decrypted = "Hi"
  ↓ table re-renders showing roundtrip

Step 15 (Done + Playground)
  ↓ user edits sentence box
ephemeral (NOT in state): recomputes encrypted/decrypted on each keystroke,
                          re-renders the table. No persistence.
```

## Error handling

### Step 11 — `pick_pq_big`

- `p` or `q` < 17 → `"For real text, both primes need to be at least 17 so n ≥ 256."`
- `p == q` → `"p and q must be different primes."`
- not prime → `"{value} is not prime."`
- `p·q < 256` → defensive assertion; only trips if the ≥17 check is bypassed.

### Step 12 — `pick_sentence`

- empty → `"Type at least one character."`
- > 500 → `"Keep it under 500 characters."` (live counter in textarea)
- contains non-printable-ASCII → `"Only printable ASCII for now — no emoji, accents, tabs, or newlines. Found: '<offender>'."`

### Step 13 — `encrypt_sentence_head`

- wrong value → reuse `encrypt` hint shape: `"c = m^e mod n. With m={code} (the ASCII of '{char}'), e={e2}, n={n2}."`
- on success, encryption of remaining chars is computed in a tight loop. If any char encrypts to a value outside `[0, n2)` (shouldn't happen with our constraints), abort with a loud error rather than silently writing bad data.

### Step 14 — `decrypt-sentence`

- if `codesToText(decrypted) !== sentence`, render a visible error ("Key derivation bug — please reload") instead of failing silently. This indicates a regression in `e2`/`d2` derivation.

### Step 15 — Playground

- Invalid input shows an inline hint next to the textarea. The table simply doesn't render.
- Playground edits never write to `state.sentence`. Editing in playground does NOT corrupt the lesson record.

### Resume / out-of-date state

- `currentStepOrder` is clamped to `steps.length` on load.
- If a returning user has `state.sentence` from a previous session but the fixture has changed in incompatible ways (e.g. step renamed), they re-enter the flow at step 10 with both CTAs visible.

## Testing

### JS validator tests (`static/algorithms/rsa/tests/validators.test.js`)

- `pick_pq_big` happy: `(17, 19)` → asserts `value.n2 === 323`, `value.phi2 === 288`, `value.e2 === 5` (smallest int ≥ 3 coprime to 288: 3, 4 share factors with 288; 5 is coprime), `value.d2 === 173` (`modinv(5, 288)`).
- `pick_pq_big` rejects p<17, p=q, non-prime, sub-256 product.
- `pick_sentence` happy, length cap, charset rejection, empty.
- `encrypt_sentence_head` happy / wrong / non-integer; asserts `value.encrypted` is the full array.

### JS math tests (`static/algorithms/rsa/tests/math.test.js`)

- `textToCodes("Hi") === [72, 105]`
- `codesToText([72, 105]) === "Hi"`
- Roundtrip: text → codes → encrypt → decrypt → codes → text identity (using `(17, 19)` keypair on `"Hello"`)
- `toBinary8(72) === "01001000"`

### Python validator tests (`algorithms/rsa/tests/`)

- Mirror the JS tests for the same three new validators (pytest).
- Existing 22 tests must keep passing — verified by `make test`.

### Codegen tests (existing `codegen.test.js`)

- `full_script` with sentence state present produces a string that contains `for ch in sentence` and the `assert decrypted == sentence` line.

### Walkthrough tests (new, light)

- For each walkthrough fn, assert: returns array of strings of expected length (3 rungs); last rung contains the correct answer string.

### Manual smoke (pre-merge)

- Full happy path: complete toy lesson → opt in at step 10 → enter `"Hello"` → encrypt first char → decrypt → playground edits live.
- Opt-out path: complete toy lesson → exit at step 10 → reload → still on step 10 with both CTAs.
- Refresh mid-step-13: state restores, table renders correctly, can complete.
- Opt-out user returns and opts in: lands on step 10, clicks "Encrypt a real sentence", proceeds to step 11.

## Files touched

| File | Change |
|---|---|
| `algorithms/rsa/fixtures.json` | +5 step entries, modify existing `done` step. |
| `algorithms/rsa/validators.py` | +3 validators (`pick_pq_big`, `pick_sentence`, `encrypt_sentence_head`). |
| `algorithms/rsa/codegen.py` | Extend `full_script`; add `encode_sentence`. |
| `algorithms/rsa/tests/test_validators.py` | +tests for the 3 new validators. |
| `static/algorithms/rsa/validators.js` | Mirror the 3 new validators + walkthroughs. |
| `static/algorithms/rsa/codegen.js` | Mirror `full_script` extension + `encode_sentence`. |
| `static/algorithms/rsa/math.js` | +`textToCodes`, `codesToText`, `toBinary8`. |
| `static/algorithms/rsa/tests/*.test.js` | +tests for new math helpers, validators, codegen. |
| `static/core/wizard.js` | +`input-text` step kind handling, +`playgroundSentence` field, +playground re-encrypt logic, +progress-bar count derivation. |
| `core/templates/core/lesson.html` | +`input-text` renderer, +`info-with-fork` branch for step 10, +conversion table component, +playground panel on step 15. |

No new files. No database migration — fixtures reload via `make loadalgos` (or equivalent) handles the new step rows.

## Open questions / deferred

- **Larger primes for "feels real" vs. teachable smallness.** Current spec lower-bounds at `p, q ≥ 17` (n ≥ 323). Could raise to `p, q ≥ 131` (n ≈ 18,000) for a "this looks more like real RSA" feel, but encrypted values become 5-digit and less hand-walkable. Deferred unless feedback says the lesson feels too toyish.
- **Streaming encryption for very long sentences.** With 500 chars and n=323, the encryption loop is ~500 fast operations — no perceptible delay. If we later raise n to 5-digit values, the loop is still trivial. No streaming UI needed at this scale.
- **Persistence of `encrypted` array.** Currently spec persists it; alternative is to recompute on load. Trade-off is ~2 KB extra in localStorage vs. a ~10 ms recompute on resume. Kept persistent for simpler resume semantics.
