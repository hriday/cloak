# SHA-256 Lesson — Design

**Date:** 2026-05-25
**Project:** `cloak`
**Working directory:** /Users/hriday/code/enc_algo

## Goal

Teach SHA-256 as an 8-step lesson that introduces **cryptographic hashing** as a separate primitive from encryption, walks the preprocessing + compression structure at a conceptual level, and lets the learner compute real hashes in the browser via Web Crypto. This is the first hashing lesson on the site and the foundation for upcoming HMAC, Ed25519, and X25519 lessons.

Unlike the cipher lessons (RSA, AES, Blowfish), there is no "ciphertext" to recover — hashes are one-way. The lesson leans on three pedagogical moves: (1) showing the properties (determinism, avalanche, one-wayness) directly via interactive Web Crypto, (2) walking the *structure* of compression rather than hand-computing 64 rounds (computationally infeasible by hand), and (3) closing with Python `hashlib.sha256` codegen.

## Curriculum position

1. RSA ✅
2. Hybrid Encryption ✅
3. AES ✅
4. Triple DES (designed)
5. Blowfish (designed)
6. Twofish (designed)
7. HSM (designed)
8. **SHA-256** (this design) — first hashing primitive, gateway to MACs and signatures
9. HMAC (future) — references this lesson's `sha_empty_hex` framing
10. Ed25519 / X25519 (future) — reference SHA-256/SHA-512 internally

Pedagogically: hashes are introduced before HMAC and signatures because both build on top of a hash function. SHA-2 is the workhorse; SHA-1 is mentioned as deprecated, SHA-3 as a different construction (sponge, not Merkle-Damgård), but neither is taught here.

## Non-goals

- SHA-1, SHA-3 (Keccak), BLAKE2, BLAKE3 — mentioned but not taught.
- Full message-schedule derivation `W[0..63]` with the `σ0` / `σ1` mixing — cited but not walked round-by-round.
- Hand-computing SHA-256 of any non-trivial message — computationally infeasible to walk; the empty-string vector is computed via Web Crypto, not by hand.
- Length-extension attack — that's a teaser for the HMAC lesson, not this one.
- The full 64-round compression on a real block (proposed deferral; see Open questions).
- Merkle-Damgård vs sponge construction comparison — surface-level mention only.
- Password hashing as a separate arc — PBKDF2 / Argon2 are name-dropped in step 1 but belong in a future "password hashing" lesson.

## User experience

The lesson lives at `/algorithms/sha256/learn/walk-the-hash/`. SHA-256 appears as a new card on the landing page with `family: hash` (a new family value — see Architecture).

### Step sequence

| # | Slug | Kind | Behavior |
|---|---|---|---|
| 1 | `intro` | `info` | What hashing is + how it differs from encryption (no key, no decryption). Five properties: deterministic, fixed 256-bit output, one-way (preimage-resistant), collision-resistant, avalanche. Uses: TLS cert fingerprints, Bitcoin proof-of-work, Git object addressing, password hashing via PBKDF2/Argon2, file integrity, HMAC. Note: SHA-1 deprecated (SHAttered, 2017); SHA-3 exists but SHA-2 is the workhorse. |
| 2 | `preprocessing` | `info` | Message preparation: append a single `1` bit, then `0` bits, then the original message length as a 64-bit big-endian integer — padded so the total length is a multiple of 512 bits. Worked example: `"abc"` (24 bits) → `01100001 01100010 01100011 1 [423 zeros] 00...011000` (length=24 as a 64-bit big-endian field). Total: exactly 512 bits, one block. |
| 3 | `init-state` | `info` | The 8 initial hash values `H0..H7` — first 32 bits of the fractional parts of the square roots of the first 8 primes (2, 3, 5, 7, 11, 13, 17, 19). The 64 round constants `K0..K63` — first 32 bits of the fractional parts of the cube roots of the first 64 primes. Why these are "nothing up my sleeve" numbers: anyone can re-derive them; no room for a hidden backdoor. Display `H0..H7` and the first/last few `K` values. |
| 4 | `compression` | `info` | The compression function for one 512-bit block: 64 rounds, each round updates working variables `a, b, c, d, e, f, g, h` using `Ch`, `Maj`, `Σ0`, `Σ1` (and the message-schedule mixers `σ0`, `σ1`). Formulas shown. Walk ONE round on a concrete byte-aligned state: given `(a..h)` and `K[0]`, `W[0]`, compute `T1 = h + Σ1(e) + Ch(e,f,g) + K[0] + W[0]`, `T2 = Σ0(a) + Maj(a,b,c)`, then shift. The full `W` schedule is cited, not derived. |
| 5 | `walk-empty` | `input-text` | Canonical first hash. Prompt: "Compute SHA-256 of the empty string." A **Compute** button calls `crypto.subtle.digest("SHA-256", new Uint8Array(0))`. Page displays the result. Validator confirms the user pressed Compute and the browser returned `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`. Writes `{sha_empty_hex}`. |
| 6 | `avalanche` | `info` (with interactive widget) | Avalanche demo. Page renders SHA-256(`"hello"`) and SHA-256(`"Hello"`) side-by-side as 256-bit binary strings with differing bits highlighted. Counter shows "~50% of bits flipped" (~128 of 256). Demonstrates the avalanche property: a 1-bit change in the input flips roughly half the output bits. No user input; both hashes computed once on page load via Web Crypto. |
| 7 | `hash-a-sentence` | `input-text` | User types any sentence (≤500 ASCII). On Continue, browser computes SHA-256 via Web Crypto. Display shows the message, the hex digest, and the binary digest. A small table accumulates the last few `(message, hex)` pairs so re-submitting the same message visibly produces the same hash — concretizing determinism. Writes `{sha_message, sha_message_hex}`. |
| 8 | `done` | `info` | Recap of the 5 properties, observed in the lesson. Show the Python codegen output (`hashlib.sha256`). Forward-link: "You've got a hash. But a hash alone can't prove a message came from someone who knows a secret. That's the next lesson — HMAC." |

### Step 4 in detail

The compression-function walk doesn't compute a full round on a real `W[0]` (that would require running the schedule first). Instead the prompt gives the learner ready-made values:

> One round of the compression function. Working variables: `(a, b, c, d, e, f, g, h) = (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)` — the initial `H0..H7`. Round constant `K[0] = 0x428a2f98`. First message-schedule word `W[0] = 0x61626380` (the first 32 bits of "abc" padded).
>
> Apply:
> - `T1 = h + Σ1(e) + Ch(e,f,g) + K[0] + W[0]`
> - `T2 = Σ0(a) + Maj(a,b,c)`
> - new `(a..h) = (T1+T2, a, b, c, d+T1, e, f, g)` (all arithmetic mod 2³²)
>
> The new `a` is `0x5d6aebcd` (presented as a worked result, not asked).

Step 4 stays `info` rather than `input-numeric` — the Σ and Maj functions are too tedious to compute by hand, and we already have hands-on interaction in steps 5–7.

### Step 6 in detail (interactive widget)

The avalanche widget renders two 256-bit hashes as 16×16 grids of bits (matches the AES S-box display idiom). Bits that differ between the two hashes get a `.diff` class (color-highlighted). A caption summarizes: "`hello` vs `Hello`: N of 256 bits differ (~50%)." All values computed on page load via two `crypto.subtle.digest` calls; no user input. Async hydration: an inline placeholder renders first, then JS swaps in the bit grid once the digests resolve.

## Architecture

### Model change (FIRST implementation task)

`core/models.py` — extend `Algorithm.FAMILY_CHOICES` with a new entry:

```python
FAMILY_CHOICES = [
    ("asymmetric", "Asymmetric"),
    ("symmetric", "Symmetric"),
    ("hash", "Hash & MAC"),          # NEW
    ("pq", "Post-Quantum"),
    ("hsm", "HSM"),
]
```

This requires a Django migration (`makemigrations core` → `0NNN_add_hash_family.py`). The choice list is metadata only — no schema column change — but Django still emits a migration for choice updates. Future HMAC and Ed25519 lessons reuse this family.

### New algorithm record

`algorithms/sha256/fixtures.json`. Algorithm PK **8**. Lesson PK **8**. Steps PKs **81–88**.

```json
{ "model": "core.algorithm", "pk": 8, "fields": {
    "slug": "sha256", "name": "SHA-256", "family": "hash",
    "status": "live", "order": 8, "intro_template": "..."
}}
```

`intro_template` stays under 200 chars (the model's `max_length`).

### New algorithm module directory

`static/algorithms/sha256/`:

| File | Responsibility |
|---|---|
| `validators.js` | `walk_empty_hash` + `pick_sha_sentence` + `info` + `walkthroughs` object. |
| `codegen.js` | `full_script(state)` emits a Python `hashlib.sha256` demo. Per-step stubs return `""`. |
| `sha_demo.js` | Thin async wrapper around `crypto.subtle.digest("SHA-256", ...)`. Exports `hashHex(text) → Promise<{hex, binary}>` and `hashEmpty() → Promise<string>`. |
| `tests/validators.test.js` | Validator tests. |
| `tests/codegen.test.js` | Codegen output assertions. |

`sha_demo.js` isn't unit-tested in Node (`node:test` has no Web Crypto). Verified manually in the smoke check, same as `aes_demo.js`.

### Validators

| Key | Validates | On success, writes |
|---|---|---|
| `walk_empty_hash` | user pressed Compute and the browser returned `e3b0c442...b855` (literal match) | `{sha_empty_hex}` |
| `pick_sha_sentence` | non-empty, ≤500 chars, all printable ASCII (32–126); validator (or wizard wrapper) then runs Web Crypto and stores both message and digest | `{sha_message, sha_message_hex}` |
| `info` | always ok | `{}` |

### Web Crypto integration

`sha_demo.hashHex(text)`:

```js
async function hashHex(text) {
  const bytes = new TextEncoder().encode(text);
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  const hex = bytesToHex(new Uint8Array(buf));
  const binary = hexToBinary(hex);  // for the bit display in steps 6, 7
  return { hex, binary };
}
```

- **Step 5** (`walk-empty`): the page renders a **Compute** button. Click → `hashEmpty()` → result stored to `state.sha_empty_hex`. The Continue button only enables once the hash matches the expected value. Validator is then trivially "is `sha_empty_hex` set and correct?"
- **Step 6** (`avalanche`): two `hashHex` calls fire on step load; the rendered bit grid updates when both promises resolve. No state writes.
- **Step 7** (`hash-a-sentence`): on Continue, `pick_sha_sentence` first validates the text; then the wizard (or validator wrapper) calls `hashHex(sha_message)` and writes `sha_message_hex`. Subsequent submits of the same text re-display the same digest in the accumulating table.

### State namespace

All keys prefixed `sha_` (e.g., `sha_empty_hex`, `sha_message`, `sha_message_hex`) to stay visually distinct from RSA's, hybrid's, AES's (`a_`), and Blowfish's (`bf_`).

### Template changes

`core/templates/core/lesson.html` gets new slug-keyed branches under the `info` step renderer for:
- `init-state` — render the `H0..H7` table and the first/last `K` values
- `compression` — render the formula card + the one-round worked example
- `avalanche` — render the dual bit-grid widget (its own template branch; **not** piggybacked on `hash-a-sentence`'s simpler hex display, because the bit-diff highlighting needs its own DOM)
- `done` — recap card + codegen pane

Plus a new branch for `walk-empty` (an `input-text` step with a custom Compute button + readonly result display).

Pattern mirrors AES's `mix-columns` / `one-real-round` slug-keyed branches.

### What does NOT change

- `static/core/wizard.js` — the wizard is generic; loads `algorithms/sha256/` modules dynamically by `family`+`slug`.
- `core/views.py` — URL pattern `/algorithms/<slug>/learn/<lesson_slug>/` already matches.
- Existing algorithm modules (RSA, hybrid, AES, blowfish, etc.) — untouched.

## Data flow

```
Step 1, 2, 3, 4 (info)     no input. state empty.

Step 5 (walk-empty)        click Compute → Web Crypto SHA-256("")
  ↓ walk_empty_hash validator
state += { sha_empty_hex: "e3b0c442...b855" }

Step 6 (avalanche)         info — no input, no state writes.
                           Widget renders on page load via Web Crypto.

Step 7 (hash-a-sentence)   input: text
  ↓ pick_sha_sentence + async hashHex
state += { sha_message: "...", sha_message_hex: "..." }

Step 8 (done)              info. Codegen pane uses sha_message.
```

**Key property:** steps 5 and 7 are independent. The empty-string vector is canonical; the user's sentence is arbitrary. A failure in one doesn't block the other.

## Error handling

### Step 5 — `walk_empty_hash`
- Compute not yet pressed → `"Press the Compute button first."`
- Web Crypto unavailable → `"Your browser doesn't expose crypto.subtle.digest. Use a modern browser over HTTPS."`
- Returned hex doesn't match the canonical value → `"Unexpected result. The SHA-256 of the empty string is a fixed, well-known value: e3b0c442...b855."` (shouldn't happen unless the browser is broken)

### Step 7 — `pick_sha_sentence`
- Empty → `"Type a sentence (any printable ASCII)."`
- >500 chars → `"Keep it under 500 characters."`
- Non-ASCII → `"Stick to printable ASCII for the demo."` (Web Crypto handles UTF-8 fine; the limit is for display consistency, matching `pick_aes_message`.)
- Web Crypto rejects (rare) → `state.sha_hash_error` set, panel renders the error instead of the digest.

### Cross-step
- Steps 5, 6, 7 each handle their own Web Crypto failure independently.
- `currentStepOrder` clamps to `steps.length` on load (same as other lessons).

## Testing

### JS validator tests (`static/algorithms/sha256/tests/validators.test.js`)
- `walk_empty_hash`: happy (state has the canonical hex), missing, wrong hex.
- `pick_sha_sentence`: happy, empty, >500, non-ASCII rejection.

### JS codegen tests (`static/algorithms/sha256/tests/codegen.test.js`)
- `full_script({sha_message: "hi"})` contains:
  - `import hashlib`
  - `hashlib.sha256(`
  - the `"hi"` literal
  - `.hexdigest()`
  - the one-liner example `hashlib.sha256(b"hello").hexdigest()`

### Fixture-load test (`core/tests/test_fixtures.py` — extend)
- After loading `algorithms/sha256/fixtures.json`:
  - `Algorithm.objects.filter(slug="sha256").count() == 1`
  - `Algorithm.objects.get(slug="sha256").family == "hash"`
  - `Lesson.objects.filter(slug="walk-the-hash").count() == 1`
  - 8 steps in expected order with expected slugs (`intro`, `preprocessing`, `init-state`, `compression`, `walk-empty`, `avalanche`, `hash-a-sentence`, `done`)

### Manual smoke (post-implementation)
- Walk all 8 steps. Step 5: confirm Compute renders `e3b0c442...b855`. Step 6: confirm the bit-diff widget hydrates and highlights ~128 differing bits between `hello` and `Hello`. Step 7: type `"hello"`, confirm `2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824`.
- Cross-browser sanity: confirm in the browser you're using.

No Python tests beyond fixture-load — same rationale as AES and Blowfish.

## Files touched

| File | Change |
|---|---|
| `core/models.py` | **MODIFY** — add `("hash", "Hash & MAC")` to `FAMILY_CHOICES` |
| `core/migrations/0NNN_add_hash_family.py` | **CREATE** — auto-generated by `makemigrations` |
| `algorithms/sha256/fixtures.json` | **CREATE** — algorithm + lesson + 8 steps |
| `static/algorithms/sha256/validators.js` | **CREATE** |
| `static/algorithms/sha256/codegen.js` | **CREATE** |
| `static/algorithms/sha256/sha_demo.js` | **CREATE** — Web Crypto wrapper |
| `static/algorithms/sha256/tests/validators.test.js` | **CREATE** |
| `static/algorithms/sha256/tests/codegen.test.js` | **CREATE** |
| `core/templates/core/lesson.html` | **MODIFY** — slug-keyed branches for `init-state`, `compression`, `walk-empty`, `avalanche`, `done` |
| `core/tests/test_fixtures.py` | **MODIFY** — extend with SHA-256 fixture assertions |

No changes to: `static/core/wizard.js`, `core/views.py`, existing algorithm modules.

## Open questions / deferred

- **Full 64-round compression walk** (step 4.5?). Pedagogically complete but tedious — would inflate the lesson by 2–3 steps and most learners zone out by round 8. **Proposed: defer.** Re-add only if Hriday or learners explicitly ask.
- **Padding visualizer for step 2.** Could render the `"abc"` padding as a 512-bit grid (bytes → bits → padding `1` → zeros → length field). Adds interactivity but step 2 already has a worked example in prose. Defer.
- **SHA-512 / SHA-224 / SHA-384 mention.** The SHA-2 family has six variants; step 1 currently only names SHA-256. Adding a one-line "the others are similar with different word sizes and outputs" could prevent confusion. Decide at copy time.
- **Length-extension teaser.** Tempting to drop a one-liner in step 8 ("Merkle-Damgård hashes leak state — that's why naive `hash(secret || msg)` is unsafe, and why HMAC exists"). Spec leaves this to the HMAC lesson to keep this one focused on the primitive itself.
