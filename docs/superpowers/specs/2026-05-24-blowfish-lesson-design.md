# Blowfish Lesson — Design

**Date:** 2026-05-24
**Project:** `cloak`
**Working directory:** /Users/hriday/code/enc_algo

## Goal

Teach Blowfish as a 6-step lesson that introduces the **Feistel cipher** structure (most accessible part of Blowfish's design), walks through one round of the F function on a concrete byte, and ends with a Python codegen using `cryptography.hazmat`'s Blowfish API. Blowfish isn't in Web Crypto; the lesson focuses on understanding the structure and the F function rather than computing 16 rounds end-to-end.

The historical framing — Bruce Schneier's free 1993 alternative to DES, used in OpenBSD's password hashing (`bcrypt`) — makes it concrete for learners who already know AES from the prior lesson.

## Curriculum position

1. RSA ✅
2. Hybrid Encryption ✅
3. AES ✅
4. Triple DES (designed)
5. **Blowfish** (this design)
6. Twofish (designed)
7. HSM (designed)
8. Caesar / Vigenère (future)

Pedagogically: 3DES + Blowfish both predate AES; teaching them after AES gives learners modern context to compare against.

## Non-goals

- Full 16-round Blowfish encryption walked by hand.
- The complete P-array (18 × 32-bit values) and 4 S-boxes (256 × 32-bit values each) initialized from π's hex digits. Mentioned, not enumerated.
- The full key schedule (which iterates Blowfish 521 times on the key — expensive on purpose to make `bcrypt` slow).
- 448-bit max key length corner cases.
- ECB / CBC / CFB / OFB modes.
- `bcrypt` password hashing as a separate teaching arc (a future "password hashing" lesson would cover that).

## User experience

The lesson lives at `/algorithms/blowfish/learn/feistel-rounds/`. Blowfish appears as a new card on the landing page. `family: symmetric`.

### Step sequence

| # | Slug | Kind | Behavior |
|---|---|---|---|
| 1 | `intro` | `info` | Blowfish history (1993, Schneier, free alternative to DES). 64-bit block, variable 32–448 bit key, 16 rounds, Feistel structure. Where it's still used (`bcrypt`, some VPNs, legacy systems). Note: NIST recommends AES for new work — Blowfish is mostly historical now. |
| 2 | `feistel-structure` | `info` | The Feistel construction — the structural pattern Blowfish, DES, and many others share. Block split into two halves L and R; each round computes `L' = R, R' = L XOR F(R, K)`. Key property: every round is reversible if you know K (run backwards with the same F). Diagram included. |
| 3 | `f-function` | `input-numeric` | Blowfish's F function takes a 32-bit input, splits into 4 bytes, looks each byte up in one of 4 S-boxes (8→32-bit each), then combines: `F = ((S1[a] + S2[b]) XOR S3[c]) + S4[d]`. Lesson uses simplified 4-byte input, hand-picked S-box values, asks user to compute one F output. |
| 4 | `one-round` | `info` | Watch one full Blowfish round: input (L, R), apply F to R, XOR with L, swap. Display before/after states with the specific inputs from step 3. Caption: "Blowfish does this 16 times." |
| 5 | `encrypt-a-message` | `input-text` | User types a message. The page renders a Python script using `cryptography.hazmat.primitives.ciphers.algorithms.Blowfish` to encrypt + decrypt. No browser-side encryption (no Web Crypto support). |
| 6 | `done` | `info` | Recap + forward-link to Twofish (Blowfish's successor by the same author) and AES (the winner). |

### Step 3 in detail

The real F function uses 4 S-boxes of 256 × 32-bit values each (~1024 entries). We don't render all 1024 cells. Instead the prompt gives the learner 4 hand-picked S-box values directly:

> Compute Blowfish's F function on the 32-bit input `0x12345678`. Splitting into bytes: a=0x12, b=0x34, c=0x56, d=0x78.
>
> The S-box values for these bytes (for this demo) are:
> - S1[0x12] = 0xD7CABA51
> - S2[0x34] = 0x4BCA8A93
> - S3[0x56] = 0x9A3FE5C1
> - S4[0x78] = 0x1E45EE99
>
> Compute `F = ((S1[a] + S2[b]) XOR S3[c]) + S4[d]` (all arithmetic mod 2³²).
> Enter the result in hex.

Validator: parses the user's hex, compares against the canonical answer (computed once and baked in).

`(0xD7CABA51 + 0x4BCA8A93) mod 2³² = 0x239544E4`
`0x239544E4 XOR 0x9A3FE5C1 = 0xB9AAA125`
`0xB9AAA125 + 0x1E45EE99 mod 2³² = 0xD7F08FBE`

Answer: `0xD7F08FBE`.

## Architecture

### New algorithm record

`algorithms/blowfish/fixtures.json`. PK 6. Lesson PK 6. Steps PKs 61-66.

### New algorithm module directory

`static/algorithms/blowfish/`:

| File | Responsibility |
|---|---|
| `validators.js` | `f_function` validator + `pick_blowfish_message` + `info` + walkthroughs. |
| `codegen.js` | `full_script` emits Python using `cryptography.hazmat`'s Blowfish. |
| `tests/*.test.js` | Validator + codegen tests. |

### Validators

| Key | Validates | Writes |
|---|---|---|
| `f_function` | parses hex/decimal, equals 0xD7F08FBE | `{bf_f_input, bf_f_output}` |
| `pick_blowfish_message` | non-empty, ≤500 chars, printable ASCII | `{bf_message}` |
| `info` | always ok | `{}` |

### State namespace

`bf_` prefix.

## Data flow

```
Step 1, 2 (info)        no input. state empty.
Step 3 (f-function)     input: hex value
  ↓ f_function validator
state += { bf_f_input: 0x12345678, bf_f_output: 0xD7F08FBE }

Step 4 (one-round)      info, no input. Display uses bf_f_output.

Step 5 (encrypt)        input: text
  ↓ pick_blowfish_message
state += { bf_message }

Step 6 (done)           info.
```

## Error handling

### Step 3 — `f_function`
- Not parseable → `"Enter a 32-bit value in hex (0xNNNNNNNN) or decimal."`
- Out of [0, 2³²-1] → `"F outputs a 32-bit value (0 to 0xFFFFFFFF)."`
- Wrong value → `"Compute ((0xD7CABA51 + 0x4BCA8A93) XOR 0x9A3FE5C1) + 0x1E45EE99 mod 2³². All additions are mod 2³² — overflow wraps. Answer: 0xD7F08FBE."`

### Step 5 — `pick_blowfish_message`
- Standard `pick_sentence`-style rejections.

## Testing

### JS validator tests
- `f_function` happy (accepts `0xD7F08FBE`, decimal equivalent, lowercase `0xd7f08fbe`).
- `f_function` wrong / out of range / unparseable.
- `pick_blowfish_message` standard rejections.

### JS codegen tests
- `full_script({bf_message: "hi"})` contains `algorithms.Blowfish`, `Cipher(`, the message literal, and a roundtrip assert.

### Fixture-load test
- Extend test_fixtures.py.

### Manual smoke
- Walk all 6 steps; verify the F function answer accepts both 0xD7F08FBE and decimal 3623849918.

## Files touched

| File | Change |
|---|---|
| `algorithms/blowfish/fixtures.json` | CREATE |
| `static/algorithms/blowfish/validators.js` | CREATE |
| `static/algorithms/blowfish/codegen.js` | CREATE |
| `static/algorithms/blowfish/tests/validators.test.js` | CREATE |
| `static/algorithms/blowfish/tests/codegen.test.js` | CREATE |
| `core/tests/test_fixtures.py` | MODIFY (extend) |

No changes to wizard.js or lesson.html (no new template branches needed — the F function step is plain input-numeric, and there are no large data structures to display).

## Open questions / deferred

- **Diagram for step 2** (the Feistel structure) — could be inline SVG. Spec leaves it as a description; if Hriday wants a real diagram, it's a follow-up.
- **`bcrypt` story** — mentioned but not taught. Could be its own lesson.
- **Key schedule** — described but not walked. Adding a "watch the P-array initialize from π" step would be possible but slow and feels like trivia.
