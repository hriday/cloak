# Block Cipher Modes Lesson — Design

**Date:** 2026-05-25
**Project:** `cloak`
**Working directory:** /Users/hriday/code/enc_algo

## Goal

Teach **block cipher modes** — ECB, CBC, CTR, GCM — as an 8-step lesson framed as "the recipes you compose with AES." The user has already done the AES lesson and knows what one block is. This lesson explains why a raw block cipher is not enough: real data is bigger than one block, and naively repeating the cipher leaks patterns (the ECB penguin), so we need a *mode* — a construction around the block cipher — to handle chaining, randomization, padding, and authentication.

The lesson is structurally a tour: four modes, each with a short conceptual page, plus two interactive steps (a CBC walk-through and a "pick a mode for this scenario" multi-select) and a final Python codegen page. ECB gets the visual treatment (the famous bitmap demo) because it is the most pedagogically clarifying anti-pattern in modern crypto.

## Curriculum position

1. RSA ✅
2. Hybrid Encryption ✅
3. AES ✅
4. Triple DES (designed)
5. Blowfish (designed)
6. Twofish (designed)
7. HSM (designed)
8. **Block cipher modes** (this design)
9. Padding-oracle attack (future — forward-linked from this lesson)
10. Caesar / Vigenère (future)

Pedagogically: this lesson is the immediate sequel to AES. The AES lesson ends with a Web Crypto AES-GCM demo but does not unpack what "GCM" means — that gap is what this lesson fills.

## Non-goals

- Other modes (CFB, OFB, XTS, CCM, EAX, SIV, OCB) — mentioned in passing in step 8, not taught.
- Length-preserving / format-preserving encryption (FF1, FF3).
- Disk-encryption-specific modes (XTS) — called out as worth a future lesson.
- Implementing GHASH by hand. The lesson explains it as "polynomial MAC keyed by AES(0)" and stops.
- Padding-oracle attack against CBC — teased on step 3 as a help_template only, deferred to its own lesson.
- Nonce-misuse-resistant constructions (SIV, GCM-SIV).
- Per-mode performance benchmarks.
- AEAD-vs-MAC-then-encrypt taxonomy. GCM is shown as the AEAD answer; the broader composition discussion is deferred.

## User experience

The lesson lives at `/algorithms/cipher-modes/learn/modes-around-aes/`. A new "Block Cipher Modes" card appears on the landing page next to AES. `family: symmetric`.

### Step sequence

| # | Slug | Kind | Behavior |
|---|---|---|---|
| 1 | `intro` | `info` | Why modes exist. A block cipher encrypts ONE block (16 bytes for AES). Real data is bigger. A mode is the recipe for stitching blocks together — handling non-aligned lengths (padding), randomizing identical plaintexts (chaining/nonces), and (sometimes) authenticating. Lists the four modes the lesson covers. |
| 2 | `ecb-penguin` | `info` (with visual widget) | THE classic anti-pattern. Side-by-side: a procedurally drawn 32×32 two-tone pattern (the "penguin") rendered to a `<canvas>`, encrypted block-by-block with AES-ECB (simulated via Web Crypto AES-CBC with a zero IV, one block at a time). The outline is preserved because identical plaintext blocks → identical ciphertext blocks. Conclusion: ECB hides byte values, not patterns. Never use ECB. |
| 3 | `cbc-construction` | `info` | CBC: XOR each plaintext block with the previous ciphertext block before encrypting. First block uses an IV (random 16 bytes, transmitted alongside the ciphertext). Properties: identical blocks now encrypt to different ciphertexts; bit-flipping a ciphertext byte corrupts the next plaintext block in a predictable way. `help_template` teases that this last property is the padding-oracle attack surface — forward-linked to a future lesson. |
| 4 | `cbc-walk` | `input-text` (button-driven) | Interactive. Displays a 3-block plaintext (`"YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE"`, 48 bytes) and a random IV. User clicks "Encrypt" — the widget walks through three block encryptions in order, showing the `IV ⊕ P₁`, `C₁ ⊕ P₂`, `C₂ ⊕ P₃` XOR patterns and the resulting ciphertext blocks. Validator accepts any non-empty token (the button writes a sentinel `"run"` into the input). |
| 5 | `ctr-construction` | `info` | CTR: turn a block cipher into a stream cipher. Generate keystream by encrypting `(nonce ‖ counter)`, XOR the keystream with the plaintext. Properties: parallelizable (each block independent), no padding (XOR exactly `len(plaintext)` bytes), random access (jump to block `i` by encrypting counter `i`). The catastrophic failure mode: reusing a `(key, nonce)` pair gives a classic two-time-pad — both messages leak. |
| 6 | `gcm-construction` | `info` | GCM: CTR + GHASH for authentication. The cipher half is CTR. The authentication half is a polynomial MAC (GHASH) over the ciphertext (+ optional AAD), keyed by `H = AES(K, 0¹²⁸)`. Output is `(ciphertext, 16-byte tag)`. The user has already met the AEAD shape: this is AES's answer to ChaCha20-Poly1305. Same nonce-reuse caveat as CTR, but worse — reuse breaks authentication entirely. |
| 7 | `pick-a-mode` | `choose-from-list` (multi) | Interactive. Page asks "What mode should this scenario use?" — three scenarios, each with three choices (ECB / CBC / CTR / GCM, varying per scenario). Scenarios: (a) "Sending an HTTP request body over an untrusted network." → **GCM** (need confidentiality + integrity). (b) "Encrypting a database column where two rows with the same plaintext must look different." → **CBC** or **GCM** (anything-but-ECB; CBC is the canonical answer). (c) "Per-record disk encryption where random access matters and integrity is handled elsewhere." → **CTR**. Validator checks all three picks. |
| 8 | `done` | `info` | Recap. Codegen renders Python using `cryptography.hazmat.primitives.ciphers` showing AES-128 in CBC (with PKCS7), CTR, and GCM. Forward-links: padding-oracle lesson ("CBC's bit-flipping property opens an attack — next lesson"), AES-modes-for-disk lesson (XTS), and a brief mention of CFB/OFB/CCM/SIV as "modes we did not cover." |

### Canonical values

- **ECB penguin (step 2):** procedurally generated 32×32 image, 1024 pixels, each pixel 1 byte (grayscale), packed into 64 AES blocks of 16 bytes each. Pattern is a stylized two-tone silhouette (see "ECB visual" under Open questions). Key and zero-IV are generated once per page load via Web Crypto.
- **CBC walk (step 4):** plaintext `"YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE"` (48 bytes = 3 blocks). IV: 16 random bytes per page load. Key: 16 random bytes per page load. The three ciphertext blocks are computed client-side via Web Crypto AES-CBC.
- **Pick-a-mode (step 7):** answer key is `{s1: "GCM", s2: "CBC", s3: "CTR"}`. Scenario (b) accepts either `CBC` or `GCM` — both are correct. Scenario (a) rejects CBC because no integrity.

## Architecture

### New algorithm record

`algorithms/cipher-modes/fixtures.json` follows the existing shape:

```json
{ "model": "core.algorithm", "pk": 13, "fields": {
    "slug": "cipher-modes", "name": "Block Cipher Modes", "family": "symmetric",
    "status": "live", "order": 13, "intro_template": "..."
}}
```

`intro_template` capped at 200 chars per `Algorithm.intro_template` `max_length=200`.

### New lesson + 8 steps

Same fixture file. Lesson `modes-around-aes`, PK 13. Step PKs **131–138**.

### New algorithm module directory `static/algorithms/cipher-modes/`

| File | Responsibility |
|---|---|
| `validators.js` | `cbc_walk` (sentinel), `pick_a_mode` (multi-input), `info` + `walkthroughs`. |
| `codegen.js` | `full_script(state)` emits Python showing AES-128 in CBC + CTR + GCM. |
| `ecb_demo.js` | Builds the 32×32 bitmap, encrypts each 16-byte block under AES-ECB (via Web Crypto AES-CBC with zero IV, one block at a time), renders both bitmaps to canvases. |
| `cbc_demo.js` | Runs the 3-block CBC walk via Web Crypto, returns `{iv_hex, key_hex, ct_blocks_hex: [c1, c2, c3]}`. |
| `tests/validators.test.js` | Node tests for validators. |
| `tests/codegen.test.js` | Node test for `full_script`. |

`ecb_demo.js` and `cbc_demo.js` aren't unit-tested (Node `node:test` lacks Web Crypto). Verified via Playwright in the smoke check.

### Validators

| Key | Validates | On success, writes |
|---|---|---|
| `cbc_walk` | non-empty string sentinel (`"run"`) | `{mode_iv_hex, mode_plaintext, mode_ct_blocks: [hex, hex, hex]}` (written by the demo wrapper, not the validator) |
| `pick_a_mode` | multi-input `{s1, s2, s3}`; `s1 === "GCM"`, `s2 ∈ {"CBC", "GCM"}`, `s3 === "CTR"` | `{mode_scenario_1, mode_scenario_2, mode_scenario_3}` |
| `info` | always ok | `{}` |

### State namespace

All keys prefixed `mode_` (e.g., `mode_iv_hex`, `mode_ct_blocks`, `mode_scenario_1`, `mode_scenario_2`, `mode_scenario_3`).

### Template changes

`core/templates/core/lesson.html` gets new slug-keyed branches:

- `ecb-penguin` — renders two `<canvas>` elements side by side + a button to re-roll the key.
- `cbc-walk` — renders the 3-block plaintext + IV display + "Encrypt" button + a stepped XOR walk showing `IV ⊕ P₁` → `E_K → C₁`, `C₁ ⊕ P₂` → `E_K → C₂`, etc.
- `pick-a-mode` — renders three scenario blocks, each with three radio buttons; single submit posts all three picks.
- `done` — recap panel showing the chosen scenario answers and the codegen Python.

### What does NOT change

- `static/core/wizard.js` — generic, loads algorithm modules dynamically.
- `core/models.py` — no schema changes.
- `core/views.py` — URL pattern already supports any algorithm/lesson slug pair.
- All prior algorithm modules — untouched.

## Data flow

```
Step 1 (intro)            info. state = {}

Step 2 (ecb-penguin)      info. ECB demo runs client-side on mount.
                          No state writes (visual only).

Step 3 (cbc-construction) info. help_template hints at padding-oracle.

Step 4 (cbc-walk)         input-text (button-driven, sentinel "run")
  ↓ cbc_demo.runWalk()
state += { mode_iv_hex, mode_plaintext, mode_ct_blocks }

Step 5 (ctr-construction) info.

Step 6 (gcm-construction) info.

Step 7 (pick-a-mode)      multi-input {s1, s2, s3}
  ↓ pick_a_mode validator
state += { mode_scenario_1, mode_scenario_2, mode_scenario_3 }

Step 8 (done)             info. Recap panel + Python codegen.
```

**Key property:** steps are mostly independent. The CBC walk's state is displayed on the done page but not required by any later step's validator.

## Error handling

### Step 2 — ECB demo
- Web Crypto unavailable → render plain-text fallback message ("ECB demo requires a modern browser") and let the user continue.
- Encryption rejection (extremely rare) → catch, log, render fallback.

### Step 4 — `cbc_walk`
- Empty input → `"Click the Encrypt button to run the walk-through."` (the button auto-fills the sentinel).
- Web Crypto failure → same fallback story as ECB.

### Step 7 — `pick_a_mode`
- Missing pick on any scenario → `"Pick a mode for each scenario."`
- Wrong pick on s1 → `"Sending data over an untrusted network needs integrity. CBC and CTR provide confidentiality but not authentication — anyone can flip bits undetected. GCM provides both."`
- Wrong pick on s2 — accepts CBC or GCM; ECB rejected with `"ECB encrypts identical plaintext blocks to identical ciphertext — exactly what this scenario forbids."`; CTR rejected with `"CTR is fine for confidentiality but database fields are short, often fit in one block, and rarely need streaming. CBC or GCM is more idiomatic here."`
- Wrong pick on s3 → `"CTR allows random access (jump to block i by encrypting counter i). CBC requires reading all prior blocks. GCM is fine but adds an authentication tag this scenario does not need."`

### Cross-step
- Steps are independent; a failure on step 4 does not block step 7.
- `currentStepOrder` clamps to `steps.length` on load.

## Testing

### JS validator tests (`static/algorithms/cipher-modes/tests/validators.test.js`)
- `cbc_walk`: accepts `"run"`, rejects empty.
- `pick_a_mode`: happy (`{s1:"GCM", s2:"CBC", s3:"CTR"}`), accepts `s2:"GCM"`, rejects `s1:"CBC"`, rejects `s2:"ECB"`, rejects missing scenarios.
- `info`: always ok.

### JS codegen test (`static/algorithms/cipher-modes/tests/codegen.test.js`)
- `full_script({})` contains:
  - `from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes`
  - `modes.CBC(iv)`
  - `modes.CTR(nonce)`
  - `from cryptography.hazmat.primitives.ciphers.aead import AESGCM`
  - PKCS7 padding usage on the CBC branch
  - Roundtrip assertion per mode

### Fixture-load test (`core/tests/test_fixtures.py` — extend)
- After loading `algorithms/cipher-modes/fixtures.json`:
  - `Algorithm.objects.filter(slug="cipher-modes").count() == 1`
  - `Lesson.objects.filter(slug="modes-around-aes").count() == 1`
  - 8 steps in expected order with expected slugs

### Manual smoke (post-implementation)
- Walk all 8 steps. Re-roll the ECB key, confirm outline persists.
- CBC walk: hit "Encrypt", confirm three distinct ciphertext blocks render.
- Pick-a-mode: verify both `CBC` and `GCM` pass for scenario 2; verify ECB fails for scenario 2 with the targeted error.
- Cross-browser sanity: Firefox + Chrome at minimum.

No Python tests — JS validators are load-bearing; fixture loading is covered by the test_fixtures extension.

## Files touched

| File | Change |
|---|---|
| `algorithms/cipher-modes/fixtures.json` | **CREATE** — algorithm + lesson + 8 steps |
| `static/algorithms/cipher-modes/validators.js` | **CREATE** — 2 validators + walkthroughs |
| `static/algorithms/cipher-modes/codegen.js` | **CREATE** — full_script (CBC + CTR + GCM) |
| `static/algorithms/cipher-modes/ecb_demo.js` | **CREATE** — bitmap generator + per-block ECB simulation |
| `static/algorithms/cipher-modes/cbc_demo.js` | **CREATE** — 3-block CBC walk |
| `static/algorithms/cipher-modes/tests/validators.test.js` | **CREATE** |
| `static/algorithms/cipher-modes/tests/codegen.test.js` | **CREATE** |
| `core/templates/core/lesson.html` | **MODIFY** — add slug-keyed branches for `ecb-penguin`, `cbc-walk`, `pick-a-mode`, `done` |
| `core/tests/test_fixtures.py` | **MODIFY** — extend with cipher-modes fixture assertions |

No changes to: `static/core/wizard.js`, `core/models.py`, `core/views.py`, prior algorithm modules.

## Open questions / deferred

- **ECB visual.** A real Tux bitmap is licensed (Creative Commons, fine) but loading a remote image complicates the demo and obscures the point. Recommendation: procedurally draw a stylized 32×32 two-tone silhouette in `ecb_demo.js` — a simple filled oval body + smaller filled circle head + two contrasting "feet" rectangles, rendered as grayscale bytes. 1024 pixels = 64 AES blocks. The encrypted version will preserve the silhouette outline because each repeated 16-byte run (long horizontal strokes of the same color) encrypts identically. If the procedural drawing looks weak, the fallback is a 32×32 checkerboard of 8×8 super-pixels — visually less iconic but the "outline preserved" point lands cleanly.
- **Padding-oracle teaser** on step 3. Recommendation: include as `help_template` ("Curious: what happens if you flip one bit of C₁?"). Keep the body short — three sentences explaining the cascade — and forward-link to a future padding-oracle lesson.
- **XTS / CCM / SIV** — called out on step 8 as not covered; XTS specifically as "the disk-encryption mode" with a stub link to a future lesson.
- **Nonce-reuse demo for CTR/GCM.** Tempting to add an interactive "watch a two-time-pad leak" step. Deferred — it would balloon the lesson past 8 steps and the conceptual point lands in the prose on steps 5 and 6.
- **Why no AES-XTS in codegen.** Intentional. The Python `cryptography` library exposes XTS but it requires a 32-byte key for AES-128-XTS (two halves) and the disk-block tweak — too much new vocabulary for this lesson's codegen target.
