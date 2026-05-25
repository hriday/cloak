# Password Hashing Lesson — Design

**Date:** 2026-05-25
**Project:** `cloak`
**Working directory:** /Users/hriday/code/enc_algo

## Goal

Teach password hashing as an 8-step lesson that answers the question every developer eventually asks: "how do I store my users' passwords?" The lesson starts from the threat model (database leak, GPU cracking, rainbow tables), explains **why plain SHA-256 is wrong** (no salt, not slow), and walks the three industry-standard alternatives — **PBKDF2**, **bcrypt**, and **Argon2id** — with their tradeoffs and a side-by-side timing comparison.

Pedagogically the lesson leans on three moves: (1) interactive PBKDF2 in the browser via Web Crypto so the learner *feels* the linear iteration-count cost, (2) cited timing numbers for bcrypt + Argon2 (real JS implementations are too heavy to ship), and (3) a closing recommendation matrix the learner can apply at their day job.

## Curriculum position

1. RSA ✅
2. Hybrid Encryption ✅
3. AES ✅
4. Triple DES (designed)
5. Blowfish (designed) — forward-referenced in step 4 (bcrypt is built on Blowfish)
6. Twofish (designed)
7. HSM (designed)
8. SHA-256 (designed) — referenced in step 2 (the naive failure)
9. HMAC (designed) — PBKDF2 uses HMAC-SHA256 underneath
10. **Password Hashing** (this design) — first applied-cryptography lesson
11. HKDF (future) — forward-linked from step 8 (KDF from a key, different beast)

Pedagogically: password hashing depends on SHA-256 (for the naive-failure framing) and HMAC (PBKDF2's inner primitive). It is the natural home for the "slow on purpose" idea introduced in passing by the bcrypt note in the Blowfish lesson.

## Non-goals

- **scrypt** — name-dropped in step 7 as an older memory-hard option; Argon2 won the PHC so it gets the spotlight. No dedicated step.
- **Pepper** (a server-side secret separate from per-user salt) — operationally important but a sidebar at most. Out of scope.
- **Blake2b internals** — Argon2 uses Blake2b as its compression primitive; described in one sentence, not unpacked.
- **Implementing bcrypt or Argon2 in JS** — real implementations are 30+ KB and slow. Treated conceptually with cited timing numbers. See Open Questions.
- **Real attacker rigs** — GPU cracking speeds cited from published benchmarks; no in-browser cracker.
- **Authentication flow design** — session tokens, MFA, account recovery. This lesson is about the hash primitive only.
- **Rate limiting, lockouts, breach detection** — defenses adjacent to password hashing, not part of it.

## User experience

The lesson lives at `/algorithms/password-hashing/learn/slow-on-purpose/`. Password Hashing appears as a new card on the landing page under the existing `hash` family (no model migration — the SHA-256 spec already added `hash` to `FAMILY_CHOICES`).

### Step sequence

| # | Slug | Kind | Behavior |
|---|---|---|---|
| 1 | `intro` | `info` | The threat model. Database leaks happen (LinkedIn 2012, Adobe 2013, etc.). If passwords are stored as plaintext or fast hashes, attackers GPU-crack them in seconds. Rainbow tables precompute hashes for common passwords. Three defenses: per-user **salt** (defeats rainbow tables), deliberate **slowness** (caps guess rate), and **memory-hardness** (defeats GPU/ASIC parallelism). |
| 2 | `naive-sha256-failure` | `info` (with widget) | Demo: compute SHA-256 of `"password123"` in the browser — instant. Caption: "A GPU farm tries ~10 billion SHA-256 guesses per second. Your user's password falls in milliseconds." Establishes the gap between hashing-for-integrity (fast is good) and hashing-for-passwords (slow is good). |
| 3 | `pbkdf2` | `input-text` (with widget) | PBKDF2 (RFC 8018): HMAC-SHA256 iterated N times over (password, salt). NIST-approved, FIPS-compliant. Configurable cost via iteration count; NIST SP 800-132 recommends ≥10,000, OWASP recommends 600,000+ for SHA-256 in 2023. Interactive: user enters a password, picks iteration count from a dropdown (1k / 10k / 100k / 1M), page computes via Web Crypto, shows hex + wall-clock time. Demonstrates the linear time-vs-cost relationship. |
| 4 | `bcrypt` | `info` (with widget) | bcrypt (1999, Provos + Mazières, OpenBSD). Built on **Blowfish**'s expensive key schedule — forward-linked to the Blowfish lesson the learner has already done. Cost factor `c` controls work *exponentially* (cost 12 = 2^12 = 4096 iterations of the Blowfish key schedule). Widely deployed (Ruby on Rails default, many PHP frameworks). Limitations: 72-byte password truncation, no memory-hardness. Widget: conceptual diagram + cited timing card (cost 10 ≈ 65ms, cost 12 ≈ 250ms, cost 14 ≈ 1s on commodity hardware). No live bcrypt in browser — see Open Questions. |
| 5 | `argon2-construction` | `info` | Argon2 (2015 winner of the Password Hashing Competition). **Memory-hard**: tunable via memory `m`, parallelism `p`, time `t`. Memory hardness defeats GPU/ASIC acceleration — an attacker needs *megabytes per guess*, not microseconds of compute. Three variants: **Argon2d** (max GPU resistance, vulnerable to side-channel), **Argon2i** (side-channel-resistant, weaker against tradeoff attacks), **Argon2id** (hybrid, the default for new systems). Uses Blake2b as its compression primitive (one-sentence mention). |
| 6 | `compare-hashes` | `info` (with widget) | Side-by-side timing comparison. Page hashes the same demo password (`"correct horse battery staple"`) under five settings: SHA-256, PBKDF2-1k, PBKDF2-100k, bcrypt-12 (cited), Argon2id-default (cited). Renders a bar chart of wall-clock times. Expected: SHA-256 ~μs, PBKDF2-1k ~1ms, PBKDF2-100k ~100ms, bcrypt-12 ~250ms (cited), Argon2id ~500ms (cited). Real numbers for the PBKDF2 rows, cited numbers for bcrypt + Argon2id with a clear "measured on a typical 2024 laptop" caption. |
| 7 | `which-to-use` | `info` | Recommendation matrix. **New systems**: Argon2id with `m=64MB, t=3, p=4` (RFC 9106 recommendation). **Existing bcrypt deployments**: stay on bcrypt at cost 12+. **PBKDF2-only environments** (FIPS, no native Argon2/bcrypt support): PBKDF2-HMAC-SHA256 at ≥600,000 iterations. **Never**: plain SHA-256, MD5, plaintext, custom homebrew. Brief mention of scrypt as an older memory-hard option superseded by Argon2. `help_template` sidebar on constant-time comparison (`hmac.compare_digest` for verification — timing attacks apply to hash comparison too). |
| 8 | `done` | `info` | Recap of the three defenses (salt, slow, memory-hard) seen across the lesson. Codegen renders a Python script using `argon2-cffi` (Argon2id hash + verify roundtrip + wrong-password failure) and `bcrypt` (same roundtrip with `bcrypt.hashpw` + `bcrypt.checkpw`). Comments call out `pip install argon2-cffi bcrypt` and name-drop `passlib` as the multi-algorithm option. Forward-link to HKDF: "PBKDF2 stretches a password into a key. HKDF does the same starting from an already-strong key — different threat model, different construction." |

### Step 2 in detail (the naive-failure widget)

A single-shot widget. On step load, the page renders an input pre-filled with `"password123"`, hashes it via `crypto.subtle.digest("SHA-256", ...)`, displays the hex + the wall-clock `performance.now()` delta (typically <1ms on any modern machine). Caption table cites GPU cracking rates:

> SHA-256 single-hash time (your browser): **0.2 ms**
> Estimated cost on a single RTX 4090: **~10 billion guesses/second**
> Time to crack a 6-char lowercase password: **~30 seconds**

No state writes — the widget is illustrative.

### Step 3 in detail (the PBKDF2 widget)

A `input-text` step with a custom widget. User types a password, picks iteration count from a dropdown (`1,000` / `10,000` / `100,000` / `1,000,000`). On submit, the page calls `crypto.subtle.deriveBits` with `{name: "PBKDF2", hash: "SHA-256", salt: <16 random bytes>, iterations: N}` for a 32-byte output. The validator parses the result, measures wall-clock time via `performance.now()`, and writes `{pw_pbkdf2_password, pw_pbkdf2_iter, pw_pbkdf2_hex, pw_pbkdf2_ms}`. A small accumulating table shows previous (iter, ms) pairs so the learner can re-submit at different costs and watch the time scale linearly.

### Step 4 in detail (the bcrypt widget — conceptual)

No live computation. The widget renders three things:
- A schematic showing Blowfish key schedule iterated `2^cost` times.
- A cost-vs-time table with cited numbers (cost 10 / 12 / 14 on a typical 2024 laptop).
- A pull-quote: "bcrypt's cost factor is exponential — every +1 doubles the work. Cost 14 is 4× slower than cost 12."

Lesson copy explicitly notes: "We don't run bcrypt live in the browser — a real JS implementation is ~30 KB of code and would block the page for seconds. The timing numbers come from `bcrypt` benchmarks on commodity hardware."

### Step 6 in detail (the comparison widget)

On step load, the page hashes `"correct horse battery staple"` under SHA-256 and PBKDF2 (1k and 100k) via Web Crypto, capturing real wall-clock times. The bcrypt + Argon2id rows render with cited numbers and a `(cited)` badge. A horizontal bar chart visualizes all five timings on a **log scale** (otherwise SHA-256 is invisible next to Argon2id). No state writes — the widget is illustrative.

## Architecture

### New algorithm record

`algorithms/password-hashing/fixtures.json`. Algorithm PK **15**. Lesson PK **15**. Steps PKs **151–158**. Algorithm `family = hash` (already in `FAMILY_CHOICES` per the SHA-256 spec).

```json
{ "model": "core.algorithm", "pk": 15, "fields": {
    "slug": "password-hashing", "name": "Password Hashing", "family": "hash",
    "status": "live", "order": 15, "intro_template": "..."
}}
```

`intro_template` stays under 200 chars. Draft: `"Storing passwords: salt them, slow the hash way down. PBKDF2, bcrypt, and Argon2id are the three industry standards. Argon2id is the modern default."` (~152 chars, fits.)

### New algorithm module directory

`static/algorithms/password-hashing/`:

| File | Responsibility |
|---|---|
| `validators.js` | `pbkdf2_compute`, `compare_all`, `info` validators. Async (Web Crypto). |
| `codegen.js` | `full_script(state)` emits a Python script using `argon2-cffi` and `bcrypt`. Per-step stubs return `""`. |
| `pw_demo.js` | Thin async Web Crypto wrapper. Exports `pbkdf2(password, salt, iter)` and `sha256Quick(text)` and `nowMs()` helpers. |
| `tests/validators.test.js` | Validator tests (Web-Crypto-dependent paths skipped in Node, same convention as AES/SHA-256/HMAC). |
| `tests/codegen.test.js` | Codegen output assertions. |

### Validators

| Key | Validates | Writes |
|---|---|---|
| `pbkdf2_compute` | password non-empty + ≤200 ASCII chars, iter is one of the allowed values; runs PBKDF2 via Web Crypto and captures wall-clock time | `{pw_pbkdf2_password, pw_pbkdf2_iter, pw_pbkdf2_hex, pw_pbkdf2_ms}` |
| `compare_all` | step 6 widget completed (all five timings present in the rendered widget result) | `{pw_compare_results: [{algo, hex, ms, cited: bool}]}` |
| `info` | always ok | `{}` |

### State namespace

All keys prefixed `pw_` (e.g., `pw_pbkdf2_password`, `pw_pbkdf2_iter`, `pw_pbkdf2_hex`, `pw_pbkdf2_ms`, `pw_compare_results`). Stays visually distinct from `sha_` (SHA-256), `hm_` (HMAC), `bf_` (Blowfish), `a_` (AES).

### Template changes

`core/templates/core/lesson.html` gets slug-keyed branches for:
- `naive-sha256-failure` — pre-filled input + hex output + GPU-rate caption card.
- `pbkdf2` — password input + iteration dropdown + result panel + accumulating-runs table.
- `bcrypt` — static schematic + cited-timing table (no input).
- `compare-hashes` — bar chart (log scale) of five timings with `(cited)` badges where applicable.
- `done` — recap card + Python codegen pane.

Pattern mirrors HMAC's shared-template approach for steps 5–6.

### What does NOT change

- `core/models.py` — `hash` family already exists.
- `core/migrations/` — no migration needed.
- `static/core/wizard.js` — generic.
- `core/views.py` — URL pattern already matches.
- Existing algorithm modules — untouched.

## Data flow

```
Step 1 (info)                     no input. state empty.

Step 2 (naive-sha256-failure)     info + widget. Widget hashes
                                   "password123" on load; nothing written.

Step 3 (pbkdf2)                   input: password + iter dropdown
  ↓ pbkdf2_compute (async)
state += { pw_pbkdf2_password, pw_pbkdf2_iter,
           pw_pbkdf2_hex, pw_pbkdf2_ms }

Step 4 (bcrypt)                   info + static widget. state unchanged.

Step 5 (argon2-construction)      info. state unchanged.

Step 6 (compare-hashes)           info + widget. On load: hash demo password
                                   under SHA-256 + PBKDF2-1k + PBKDF2-100k
                                   via Web Crypto; emit bcrypt+Argon2id rows
                                   from cited numbers.
  ↓ compare_all validator
state += { pw_compare_results }

Step 7 (which-to-use)             info. state unchanged.
Step 8 (done)                     info. Codegen pane is static (no state
                                   needed — sample script doesn't depend on
                                   user input).
```

## Error handling

### Step 3 — `pbkdf2_compute`
- Empty password → `"Type a password (any string)."`
- >200 chars → `"Keep it under 200 characters for the demo."`
- Non-ASCII → `"Stick to printable ASCII for the demo."`
- Iter not in allowed set → `"Pick an iteration count from the dropdown."`
- Web Crypto error → `"PBKDF2 failed. This step requires a modern browser over HTTPS."`

### Step 6 — `compare_all`
- Widget hasn't finished hashing → `"Wait for the comparison to finish — PBKDF2-100k takes ~100 ms."`
- Web Crypto error in any row → `"One of the timing rows failed. Refresh and retry."`

### Cross-step
- Steps 2, 3, 6 each handle their own Web Crypto failure independently.
- `currentStepOrder` clamps to `steps.length` on load (same as other lessons).

## Testing

### JS validator tests (`static/algorithms/password-hashing/tests/validators.test.js`)
- `pbkdf2_compute`: happy (state has all four keys), missing password, non-ASCII, oversized, bad iter value. Web-Crypto-dependent happy path mocked or skipped in Node.
- `compare_all`: happy (state has 5 entries), missing rows.
- `info`: trivially passes.

### JS codegen tests (`static/algorithms/password-hashing/tests/codegen.test.js`)
- `full_script({})` contains:
  - `import argon2` and `from argon2 import PasswordHasher`
  - `import bcrypt`
  - `PasswordHasher().hash(`
  - `bcrypt.hashpw(`
  - `bcrypt.gensalt(rounds=12)`
  - both verify-roundtrip blocks
  - a wrong-password assertion for each algorithm
  - the `pip install argon2-cffi bcrypt` comment
  - the `passlib` mention

### Fixture-load test (`core/tests/test_fixtures.py` — extend)
- After loading `algorithms/password-hashing/fixtures.json`:
  - `Algorithm.objects.filter(slug="password-hashing").count() == 1`
  - `Algorithm.objects.get(slug="password-hashing").family == "hash"`
  - `Lesson.objects.filter(slug="slow-on-purpose").count() == 1`
  - 8 steps in expected order with expected slugs (`intro`, `naive-sha256-failure`, `pbkdf2`, `bcrypt`, `argon2-construction`, `compare-hashes`, `which-to-use`, `done`).

### Manual smoke (post-implementation)
- Walk all 8 steps. Step 2: confirm `"password123"` hashes in <1ms. Step 3: run at 1k, 10k, 100k, 1M iterations; confirm time scales roughly linearly. Step 6: confirm the bar chart renders five rows and log scale makes SHA-256 visible. Step 8: copy the codegen script, `pip install argon2-cffi bcrypt`, run it, confirm both roundtrips succeed.
- Cross-browser sanity: Chrome + Firefox + Safari.

No Python tests beyond fixture-load — same rationale as AES, SHA-256, HMAC.

## Files touched

| File | Change |
|---|---|
| `algorithms/password-hashing/fixtures.json` | CREATE — algorithm + lesson + 8 steps |
| `static/algorithms/password-hashing/validators.js` | CREATE |
| `static/algorithms/password-hashing/codegen.js` | CREATE |
| `static/algorithms/password-hashing/pw_demo.js` | CREATE — Web Crypto wrapper |
| `static/algorithms/password-hashing/tests/validators.test.js` | CREATE |
| `static/algorithms/password-hashing/tests/codegen.test.js` | CREATE |
| `core/templates/core/lesson.html` | MODIFY — slug-keyed branches for `naive-sha256-failure`, `pbkdf2`, `bcrypt`, `compare-hashes`, `done` |
| `core/tests/test_fixtures.py` | MODIFY (extend) |

No model or migration changes — `hash` family was added by the SHA-256 spec.

## Open questions / deferred

- **bcrypt live in browser.** A real JS bcrypt implementation (`bcryptjs`, etc.) is ~30 KB and blocks the main thread for hundreds of ms per hash. **Decision: cited, not live.** Step 4 renders a schematic + a cited-timing table with an explicit "we don't run this live because…" caption. Pedagogical payoff (felt cost) is preserved by the live PBKDF2 demo in step 3 and the comparison chart in step 6.
- **Argon2 live in browser.** Same problem (WASM build is ~150 KB, runtime memory-hard by definition makes it heavy). **Decision: cited, not live.** Argon2id appears in the step-6 chart with a `(cited)` badge.
- **Constant-time comparison sidebar.** Timing attacks apply to hash *verification* too (`==` on bcrypt hashes leaks length info via early exit). **Decision: include as a `help_template` block on step 7**, ~80 words, naming `hmac.compare_digest` (Python) and `crypto.subtle.timingSafeEqual` (Node). Not its own step — too narrow.
- **Pepper.** A site-wide secret XOR'd or concatenated with the password before hashing, stored outside the database. Operationally valuable (defeats DB-only leaks) but adds key-management complexity. **Decision: out of scope** for v1; could be added as a `help_template` sidebar later.
- **Real cracking-rate citations.** Step 1 + step 2 cite "~10 billion SHA-256/s on an RTX 4090" — published in many places but worth refreshing closer to ship. Decide at copy time.
- **Salt visibility.** PBKDF2 in step 3 generates a random 16-byte salt per submission; we could show it alongside the hash output to drive home that the salt is stored publicly. **Recommendation: yes**, display the salt in the result panel with a one-line caption ("the salt is not a secret — it's stored alongside the hash in your DB"). Cheap and pedagogically valuable.
- **Output-length parameter for PBKDF2.** Hardcoded at 32 bytes (256 bits) in the widget. Mention in copy but don't expose as a knob — keeps the UI focused on iteration count.
