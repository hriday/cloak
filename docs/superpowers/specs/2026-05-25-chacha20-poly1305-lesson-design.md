# ChaCha20-Poly1305 Lesson — Design

**Date:** 2026-05-25
**Project:** `cloak`
**Working directory:** /Users/hriday/code/enc_algo

## Goal

Teach **ChaCha20-Poly1305** (RFC 8439) as a 7-step lesson that introduces the **ARX design** (Add / Rotate / XOR — no S-boxes, no MixColumns), walks the learner through one quarter-round by hand, then composes it conceptually into the full block function, introduces Poly1305 as the one-time MAC, and finishes with a real AEAD encrypt-then-tamper demo in the browser. The pedagogical hook is that ChaCha20's internals are dramatically simpler than AES — three primitive ops on 32-bit words — yet it's fast, constant-time, and the dominant AES-GCM alternative in TLS 1.3, WireGuard, and SSH.

Like the AES lesson, the full cipher (20 rounds × 8 quarter-rounds = 160 quarter-rounds per block) is intractable by hand, so we go interactive on the quarter-round itself and describe the rest in info steps. The final step is a real AEAD encrypt + decrypt + tamper-then-fail demo so the learner sees authenticated encryption in action.

## Curriculum position

1. RSA ✅
2. Hybrid Encryption ✅
3. AES ✅
4. Triple DES (designed)
5. Blowfish (designed)
6. Twofish (designed)
7. HSM (designed)
8. **ChaCha20-Poly1305** (this design)
9. Caesar / Vigenère (future)

Pedagogically: ChaCha20-Poly1305 follows AES so learners have a modern symmetric reference point. The "ARX vs S-box-and-permutation" contrast with AES is the central teaching frame. It also closes the AEAD loop — AES step 7 used AES-GCM under the hood without unpacking the MAC; here we open it up.

## Non-goals

- **XChaCha20** (extended 192-bit nonce variant) — mentioned, not taught.
- **ChaCha8 / ChaCha12** (reduced-round variants) — mentioned for context only.
- **Salsa20** (the predecessor) — historical name-drop, not walked.
- The full 20-round block function walked by hand — only the quarter-round is interactive; the block function is described.
- The complete Poly1305 polynomial evaluation by hand (130-bit modular arithmetic is infeasible) — described, not computed.
- **AES-GCM as a separate lesson** — could be a sibling lesson later; here we just compare in the intro.
- The TLS 1.3 record layer and AEAD nonce-derivation details — forward-linked in `done`, not taught.

## User experience

The lesson lives at `/algorithms/chacha20-poly1305/learn/arx-aead/`. ChaCha20-Poly1305 appears as a new card on the landing page. `family: symmetric`.

### Step sequence

| # | Slug | Kind | Behavior |
|---|---|---|---|
| 1 | `intro` | `info` | Why a modern stream cipher: AES is great with AES-NI hardware, but on mobile/embedded CPUs without it, AES is slow and timing-vulnerable. ChaCha20 (Bernstein, 2008) was designed for software speed and constant-time everywhere. ChaCha20-Poly1305 (RFC 8439) bundles it with a one-time MAC into an AEAD. Used in TLS 1.3, WireGuard, `chacha20-poly1305@openssh.com`, `age`. Direct compare to AES-GCM: same role, different internals, AES-GCM wins on AES-NI hardware, ChaCha20-Poly1305 wins on mobile/embedded. |
| 2 | `arx-design` | `info` | **ARX = Add (mod 2³²) / Rotate / XOR.** No S-boxes, no MixColumns. All ops on 32-bit words. The cipher state is a 4×4 matrix of 32-bit words = 512 bits = 64 bytes. Initialized from: 4 constants (`"expa"`, `"nd 3"`, `"2-by"`, `"te k"`), 8 words of key (256-bit), 1 word of block counter, 3 words of nonce (96-bit). Diagram shows the 4×4 grid with each cell labelled by source. |
| 3 | `quarter-round` | `input-numeric` | The core building block: `quarter_round(a, b, c, d)` updates 4 of the 16 state words via 4 ARX lines: <br>`a += b; d ^= a; d <<<= 16`<br>`c += d; b ^= c; b <<<= 12`<br>`a += b; d ^= a; d <<<= 8`<br>`c += d; b ^= c; b <<<= 7`<br>Interactive: given concrete starting values for (a, b, c, d), compute **just the first line** — `a + b mod 2³²` and the new `d` after `d XOR a` rotated left 16. To keep cognitive load low we ask only for the value of `a` after `a += b`. Help template walks all 4 lines. |
| 4 | `block-function` | `info` | The full ChaCha20 block function: initialize the 4×4 state, apply 20 rounds (10 "double-rounds" each = 4 column quarter-rounds + 4 diagonal quarter-rounds), then add the original state back at the end (this defeats round-inversion attacks). Output: a 512-bit keystream block. To encrypt: XOR keystream with plaintext (stream cipher). Block counter increments per block. Diagram shows column rounds vs diagonal rounds on the 4×4 grid. |
| 5 | `poly1305-construction` | `info` | Poly1305 is a **one-time MAC**. Take a 256-bit key → split into 128-bit `r` and 128-bit `s`. Clamp `r` (clear specific bits per RFC). Evaluate `(c₁·rⁿ + c₂·rⁿ⁻¹ + … + cₙ·r) mod (2¹³⁰ − 5)`, where `cᵢ` are 128-bit message chunks. Add `s` mod 2¹²⁸. That's the 16-byte tag. **Critical security property:** the (r, s) key must NEVER be reused — one (key, nonce) pair = one MAC. In ChaCha20-Poly1305 AEAD, the Poly1305 key is derived per-message from ChaCha20 with counter=0, so uniqueness is automatic. |
| 6 | `encrypt-a-message` | `input-text` | Interactive AEAD. Page generates a random 32-byte key + 12-byte nonce. User types a message (≤500 ASCII) + optional 200-char "associated data" (think: an unencrypted header that's still authenticated). Page encrypts via a small JS ChaCha20-Poly1305 implementation (see "Open questions"), displays key hex, nonce hex, ciphertext hex, 16-byte tag hex. A second "Verify tamper" action flips a single byte of ciphertext and re-decrypts → tag check fails → loud "AUTHENTICATION FAILED" panel. Demonstrates both halves of AEAD. |
| 7 | `done` | `info` | Recap + Python codegen using `cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305`. Forward-link: with this you can now read the TLS 1.3 RFC and understand ~80% of it (X25519 for KEX + Ed25519/RSA for cert signatures + ChaCha20-Poly1305 or AES-GCM for record encryption). Mention XChaCha20 as a "next step" if you need bigger nonces. |

### Step 3 in detail

The real quarter-round has 4 lines; we ask for one to keep the cognitive load manageable. Prompt:

> The ChaCha20 quarter-round updates 4 state words (a, b, c, d). Starting from:
>
> - a = 0x11111111
> - b = 0x01020304
> - c = 0x9b8d6f43
> - d = 0x01234567
>
> Compute the **first line**: `a = a + b mod 2³²`. Enter the new `a` in hex.

Validator parses hex/decimal, compares against `(0x11111111 + 0x01020304) mod 2³² = 0x12131415`.

The help_template walks all 4 lines on the same starting values so the learner can see the whole quarter-round even if they only have to compute one line.

## Architecture

### New algorithm record

`algorithms/chacha20-poly1305/fixtures.json`:

```json
{ "model": "core.algorithm", "pk": 12, "fields": {
    "slug": "chacha20-poly1305", "name": "ChaCha20-Poly1305", "family": "symmetric",
    "status": "live", "order": 12, "intro_template": "..."  // ≤200 chars
}}
```

`intro_template` is bounded by `Algorithm.intro_template` `max_length=200` — keep it tight (one sentence).

### New lesson + 7 steps

Same fixture file. Lesson `arx-aead`, PK 12. Step PKs **121–127**.

### New algorithm module directory `static/algorithms/chacha20-poly1305/`

| File | Responsibility |
|---|---|
| `chacha20.js` | Pure-JS ChaCha20 implementation: `quarterRound(state, a, b, c, d)`, `block(key, counter, nonce) → Uint8Array(64)`, `encrypt(key, nonce, plaintext) → Uint8Array`. ARX ops only; ~100 lines. |
| `poly1305.js` | Pure-JS Poly1305: `mac(key, message) → Uint8Array(16)`. Uses BigInt for the 130-bit polynomial. ~80 lines. |
| `aead.js` | Composes the two per RFC 8439 §2.8: derive Poly1305 key from ChaCha20(key, 0, nonce), encrypt with counter=1, build the auth-tag input `aad ‖ pad ‖ ct ‖ pad ‖ len(aad) ‖ len(ct)`, run Poly1305. Exports `encrypt(key, nonce, plaintext, aad) → {ct, tag}` and `decrypt(key, nonce, ct, tag, aad) → plaintext | throws`. |
| `validators.js` | `quarter_round_line` + `encrypt_aead` (async) + `info` + walkthroughs. |
| `codegen.js` | `full_script(state)` emits a runnable Python AEAD demo using `cryptography.hazmat`. |
| `tests/chacha20.test.js` | RFC 8439 §2.1.1 quarter-round test vector + §2.3.2 block function test vector. |
| `tests/poly1305.test.js` | RFC 8439 §2.5.2 Poly1305 test vector. |
| `tests/aead.test.js` | RFC 8439 §2.8.2 full AEAD test vector (key, nonce, aad, plaintext → ciphertext, tag). |
| `tests/validators.test.js` | Validator tests. |
| `tests/codegen.test.js` | Codegen output test. |

### Validators

| Key | Validates | On success, writes |
|---|---|---|
| `quarter_round_line` | parses 32-bit hex or decimal, integer in [0, 2³²−1], equals `(0x11111111 + 0x01020304) mod 2³² = 0x12131415` | `{chap_qr_input, chap_qr_output}` |
| `encrypt_aead` | message non-empty, ≤500 chars, printable ASCII; optional aad ≤200 chars; on success runs `aead.encrypt`, `aead.decrypt`, then tamper test | `{chap_message, chap_aad, chap_key_hex, chap_nonce_hex, chap_ciphertext_hex, chap_tag_hex, chap_decrypted, chap_tamper_failed}` |
| `info` | always ok | `{}` |

### State namespace

All keys prefixed `chap_` (e.g., `chap_qr_input`, `chap_qr_output`, `chap_message`, `chap_aad`, `chap_key_hex`, `chap_nonce_hex`, `chap_ciphertext_hex`, `chap_tag_hex`, `chap_decrypted`, `chap_tamper_failed`).

### Template changes

`core/templates/core/lesson.html` gets new slug-keyed branches:

- `arx-design` — info step rendering the 4×4 state diagram with cell labels (constants / key / counter / nonce).
- `block-function` — info step rendering the column-vs-diagonal round diagram.
- `poly1305-construction` — info step rendering the polynomial schematic.
- `encrypt-a-message` — interactive panel with: message textarea, optional AAD input, "Encrypt" button (triggers `encrypt_aead` validator), result panel (key hex, nonce hex, ciphertext hex, tag hex), "Verify tamper" button (re-runs decryption against a flipped byte, renders the failure).
- `done` — recap roundtrip panel (Message / AAD / Key / Nonce / Ciphertext / Tag / Decrypted ✓ / Tamper rejected ✓) and forward-links.

Pattern mirrors AES step 7 / 8.

### What does NOT change

- `static/core/wizard.js` — generic.
- `core/models.py` — no schema changes (all step kinds already exist).
- `core/views.py` — generic.
- `algorithms/{rsa,hybrid,aes,...}` — untouched.

## Data flow

```
Step 1, 2 (info)                  no input. state = {}

Step 3 (quarter-round)            input: hex value
  ↓ quarter_round_line validator
state += { chap_qr_input: 0x11111111, chap_qr_output: 0x12131415 }

Step 4, 5 (info)                  no input. Diagrams render.

Step 6 (encrypt-a-message)        input: message + optional aad
  ↓ encrypt_aead validator (async)
  ↓   aead.encrypt(random key, random nonce, message, aad)
  ↓   aead.decrypt(...)              → chap_decrypted
  ↓   tamper a ct byte, attempt decrypt → throws → chap_tamper_failed: true
state += { chap_message, chap_aad, chap_key_hex, chap_nonce_hex,
           chap_ciphertext_hex, chap_tag_hex, chap_decrypted,
           chap_tamper_failed }

Step 7 (done)                     info. Recap from state.
```

**Key property:** steps 3 and 6 are independent. A learner who skips the quarter-round still gets the real AEAD demo. Steps 4 and 5 are explanatory bridges; they don't write state.

## Error handling

### Step 3 — `quarter_round_line`
- Not parseable → `"Enter a 32-bit value in hex (0xNNNNNNNN) or decimal."`
- Out of [0, 2³²−1] → `"Quarter-round words are 32-bit (0 to 0xFFFFFFFF)."`
- Wrong value → `"Compute 0x11111111 + 0x01020304 mod 2³² = 0x12131415. Additions wrap at 2³²."`

Accepts: decimal, uppercase/lowercase hex, with or without `0x`.

### Step 6 — `encrypt_aead`
- Empty / too long / non-ASCII message → mirror `pick_sentence` errors.
- AAD too long (>200) → `"Associated data must be ≤200 characters."`
- AEAD library exception (shouldn't happen): caught, sets `chap_encrypt_error`. The panel renders the error instead of the roundtrip.
- Decryption mismatch (`chap_decrypted !== chap_message`): impossible barring a bug — loud `"implementation bug — please reload"` message.
- Tamper test unexpectedly succeeds (decryption returns plaintext for tampered ciphertext): also impossible — loud bug message.

### Cross-step
- Step 3 and step 6 are independent. A failure on one doesn't block the other.
- `currentStepOrder` clamps to `steps.length` on load.

## Testing

### JS chacha20 tests (`static/algorithms/chacha20-poly1305/tests/chacha20.test.js`)
- RFC 8439 §2.1.1: `quarterRound([0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567])` after all 4 lines → `[0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb]`.
- RFC 8439 §2.3.2: full block function test vector (key = `00…1f`, nonce = `00:00:00:09:00:00:00:4a:00:00:00:00`, counter = 1) → expected 64-byte keystream.

### JS poly1305 tests
- RFC 8439 §2.5.2 test vector: key = `85d6be78…`, message = `"Cryptographic Forum Research Group"` → tag = `a8061dc1305136c6c22b8baf0c0127a9`.

### JS aead tests
- RFC 8439 §2.8.2 full AEAD test vector (key, nonce, aad, plaintext from the RFC) → exact ciphertext + tag match.
- Decrypt roundtrip succeeds.
- Tamper one ciphertext byte → decrypt throws.
- Tamper one tag byte → decrypt throws.

### JS validator tests
- `quarter_round_line`: happy (`"0x12131415"` and decimal equivalent both succeed), wrong, out of range, unparseable.
- `encrypt_aead`: happy (message only); happy with aad; rejects empty / >500 / non-ASCII; rejects aad >200.

### JS codegen test
- `full_script({chap_message: "hi", chap_aad: ""})` contains:
  - `from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305`
  - `key = ChaCha20Poly1305.generate_key()`
  - `nonce = os.urandom(12)`
  - `aead = ChaCha20Poly1305(key)`
  - `ct = aead.encrypt(nonce, message, aad)`
  - `pt = aead.decrypt(nonce, ct, aad)`
  - tamper-then-decrypt-fails block with `except InvalidTag`

### Fixture-load test (`core/tests/test_fixtures.py` — extend)
- After loading `algorithms/chacha20-poly1305/fixtures.json`:
  - `Algorithm.objects.filter(slug="chacha20-poly1305").count() == 1`
  - `Lesson.objects.filter(slug="arx-aead").count() == 1`
  - 7 steps in expected order with expected slugs

### Manual smoke
- Walk all 7 steps. Verify `0x12131415` (and `303108117` decimal) both accepted on step 3.
- Step 6: encrypt "hello world" + AAD "v1"; verify hex panels render, decrypted matches, tamper button produces auth-failure panel.

## Files touched

| File | Change |
|---|---|
| `algorithms/chacha20-poly1305/fixtures.json` | **CREATE** — algorithm + lesson + 7 steps |
| `static/algorithms/chacha20-poly1305/chacha20.js` | **CREATE** — ARX block function |
| `static/algorithms/chacha20-poly1305/poly1305.js` | **CREATE** — one-time MAC |
| `static/algorithms/chacha20-poly1305/aead.js` | **CREATE** — RFC 8439 AEAD composition |
| `static/algorithms/chacha20-poly1305/validators.js` | **CREATE** — 2 validators + walkthroughs |
| `static/algorithms/chacha20-poly1305/codegen.js` | **CREATE** — full_script |
| `static/algorithms/chacha20-poly1305/tests/chacha20.test.js` | **CREATE** |
| `static/algorithms/chacha20-poly1305/tests/poly1305.test.js` | **CREATE** |
| `static/algorithms/chacha20-poly1305/tests/aead.test.js` | **CREATE** |
| `static/algorithms/chacha20-poly1305/tests/validators.test.js` | **CREATE** |
| `static/algorithms/chacha20-poly1305/tests/codegen.test.js` | **CREATE** |
| `core/templates/core/lesson.html` | **MODIFY** — add slug-keyed branches for diagrams + AEAD panel |
| `core/tests/test_fixtures.py` | **MODIFY** — extend with ChaCha20-Poly1305 fixture assertions |

No changes to: `static/core/wizard.js`, `core/models.py`, `core/views.py`, other `algorithms/*`.

## Open questions / deferred

- **Web Crypto ChaCha20-Poly1305 support.** As of mid-2026, Web Crypto API still does NOT expose ChaCha20-Poly1305 — AES-GCM is the only built-in AEAD. Three options for step 6:
  1. **Real JS implementation** of ChaCha20 + Poly1305 + AEAD composition (~250 lines total, no dependencies, ARX ops are trivial in JS, Poly1305 uses BigInt for 130-bit math). **Recommended.** Lets us validate against RFC 8439 test vectors and gives learners a faithful demo.
  2. **AES-GCM mock** in the browser while showing ChaCha20-Poly1305 in the codegen. Cheap but dishonest — the displayed hex wouldn't be real ChaCha20-Poly1305 output, and the lesson loses credibility.
  3. **No interactive step 6** — codegen-only. Worst learner experience.

  Spec assumes option 1.
- **Multi-line quarter-round.** Spec asks for only the first line (`a += b`) to keep cognitive load low. A future iteration could promote to `input-multi` and ask for all 4 of (a, b, c, d) after the full quarter-round; the help_template already walks the full sequence.
- **Diagrams.** The 4×4 state diagram and the column/diagonal round diagram are described but not yet drawn. Inline SVG would be ideal; HTML/CSS grid with cell labels is the pragmatic fallback.
- **XChaCha20.** Could be a sibling lesson (`/algorithms/chacha20-poly1305/learn/xchacha20-extended-nonce/`) once the base lesson lands. Not in scope here.
