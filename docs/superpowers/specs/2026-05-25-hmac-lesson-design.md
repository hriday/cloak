# HMAC Lesson — Design

**Date:** 2026-05-25
**Project:** `cloak`
**Working directory:** /Users/hriday/code/enc_algo

## Goal

Teach HMAC (RFC 2104) as a 7-step lesson whose pedagogical centerpiece is the **length-extension attack** against the naive construction `H(key || message)`. Once the learner *feels* why the naive MAC is broken, the nested HMAC construction `H((K' XOR opad) || H((K' XOR ipad) || m))` lands as an obvious fix instead of arbitrary ceremony. The lesson ends with Python codegen using stdlib `hmac.new(key, msg, hashlib.sha256)`.

HMAC is shorter than the SHA-256 lesson it depends on — the construction is small, and the bulk of the learning is conceptual (what a MAC is, why naive concatenation fails, what HMAC's nesting buys).

## Curriculum position

1. RSA ✅
2. Hybrid Encryption ✅
3. AES ✅
4. Triple DES (designed)
5. Blowfish (designed)
6. Twofish (designed)
7. HSM (designed)
8. SHA-256 (designed, ships just before this one)
9. **HMAC** (this design)
10. X25519 / Ed25519 (future — forward-linked from step 7)
11. Caesar / Vigenère (future)

Pedagogically: SHA-256 must precede HMAC because HMAC is parameterized by an underlying hash, and the length-extension attack only makes sense once Merkle–Damgård is on the table.

## Non-goals

- KMAC, CMAC, GMAC, Poly1305 — mentioned in the recap as alternatives, not taught.
- A faithful in-browser Merkle–Damgård length-extension exploit. Web Crypto doesn't expose SHA-256's intermediate state, and shipping a hand-rolled SHA-256 just to demo the attack is too much weight for the pedagogical payoff. Spec proposes a **simulation** — see Open Questions.
- HMAC-SHA1 / HMAC-MD5 deep dives — both noted as legacy in step 7.
- Timing-safe MAC comparison implementation — mentioned in a `help_template` sidebar on step 6, not its own step.
- Key derivation from HMAC (HKDF) — its own future lesson.
- The full SHA-256 compression function — covered in the SHA-256 lesson, referenced here.

## User experience

The lesson lives at `/algorithms/hmac/learn/mac-the-message/`. HMAC appears as a new card on the landing page under the `hash` family (shared with SHA-256; the family migration is handled by the SHA-256 spec — this spec depends on it but does not redo it).

### Step sequence

| # | Slug | Kind | Behavior |
|---|---|---|---|
| 1 | `intro` | `info` | What a MAC is. Hash answers "did this change?"; MAC answers "did someone with the key produce this?" Where HMAC is used: TLS record auth, JWT (`HS256`), AWS SigV4 request signing, OAuth 1.0a, webhook signatures (Stripe, GitHub). |
| 2 | `naive-mac` | `info` | The obvious-looking construction: `MAC = H(key || message)`. Looks fine. Sets up step 3. |
| 3 | `length-extension` | `info` (with interactive widget) | The length-extension attack. Given `H(key‖m)` plus `len(key‖m)`, an attacker computes `H(key‖m‖pad‖ext)` *without* the key. Explained via the Merkle–Damgård internal-state-equals-output property. Interactive widget below. **Pedagogical highlight of the lesson.** |
| 4 | `hmac-construction` | `info` | The fix: `HMAC(K, m) = H((K' XOR opad) ‖ H((K' XOR ipad) ‖ m))`. Two nested hashes. `opad = 0x5C × blocksize`, `ipad = 0x36 × blocksize`, `K'` is K zero-padded (or hashed-then-padded if too long). Why nesting defeats length extension: the *outer* hash sees only the inner hash's **output**, not its internal state. |
| 5 | `compute-hmac` | `input-text` | User enters a key and a message. Page computes `HMAC-SHA256` via Web Crypto (`crypto.subtle.importKey` + `crypto.subtle.sign({name: "HMAC"}, ...)`). Hex output displayed. Validator confirms a MAC was produced and writes it to state. |
| 6 | `verify-and-tamper` | `input-text` | Page shows a message + MAC the wizard generated under a key it holds. User clicks **Verify** (valid). User edits a single character of the message, clicks **Verify** again (invalid). Drives integrity home. Sidebar `help_template` covers timing-safe comparison. |
| 7 | `done` | `info` | Recap. Codegen using `hmac.new(key, msg, hashlib.sha256)`. Forward-links: X25519 ("HMAC needs a shared key — what if you don't have one?") and Ed25519 ("what if you want PUBLIC verification?"). Legacy note on HMAC-SHA1 / HMAC-MD5. |

### Step 3 in detail (the length-extension widget)

A two-panel widget. Left panel shows the **defender's view**:

> Secret key: `(hidden — 16 bytes)`
> Message: `transfer=100&to=alice`
> `naive_MAC = SHA256(key ‖ message) = a3f1...c8e2`

Right panel shows the **attacker's view**:

> Known: `naive_MAC = a3f1...c8e2`, `len(key‖message) = 37 bytes`
> Append: `&account=evil`
> [**Run length-extension attack**] button
> After click: `forged_MAC = 7b4d...09af` (matches what the server would compute on the extended message)

A "Verify forged MAC on server" button at the bottom: runs the defender's verification logic on the extended message + forged MAC. It returns **valid**. Caption: "The attacker forged a MAC without ever seeing the key."

**Implementation note (see Open Questions):** the widget *simulates* the attack rather than mounting a real Merkle–Damgård extension. The wizard internally already knows the key; when the user clicks "run attack" it computes the *real* `SHA256(key ‖ message ‖ padding ‖ extension)` and presents it as the forged MAC. The learner sees a true forged-MAC outcome; the mechanics under the hood are fudged. Lesson copy explicitly calls this out: "In a real attack the forger only needs the original MAC and the length — we're simulating the outcome here because the browser's SHA-256 doesn't expose the internal state a real attack needs."

### Steps 5 and 6 — template sharing

Steps 5 and 6 share a `lesson.html` slug-keyed branch for HMAC-flavored interactivity: a key field, a message field, and a result panel. Step 5's branch hides the verify controls; step 6's branch shows them and seeds the message/key from state. Single template branch with conditional regions, keyed off step slug.

## Architecture

### New algorithm record

`algorithms/hmac/fixtures.json`. Algorithm PK 9. Lesson PK 9. Steps PKs 91–97. Algorithm `family = hash` (already added by SHA-256's migration — this spec asserts the dependency but does not duplicate it).

### New algorithm module directory

`static/algorithms/hmac/`:

| File | Responsibility |
|---|---|
| `validators.js` | `compute_hmac`, `verify_hmac`, `info` validators. Async (Web Crypto). |
| `codegen.js` | `full_script` emits Python using `hmac.new(...)` + `hashlib.sha256`. Includes a tamper-fails roundtrip. |
| `length_extension_sim.js` | The step-3 widget logic. Simulates the attack via real `crypto.subtle.digest('SHA-256', key‖m‖pad‖ext)`. |
| `tests/*.test.js` | Validator + codegen tests. Web-Crypto-dependent paths skipped in Node, same convention as AES/SHA-256. |

### Validators

| Key | Validates | Writes |
|---|---|---|
| `compute_hmac` | both key and message non-empty + ≤500 chars printable ASCII; computes HMAC-SHA256 via Web Crypto | `{hm_key, hm_message, hm_mac_hex}` |
| `verify_hmac` | state already holds `hm_key` + `hm_mac_hex`; input shape is `{action: "verify" | "tamper", message: string}`; recomputes HMAC on `message` and compares | `{hm_verify_result: bool, hm_tampered: bool}` |
| `info` | always ok | `{}` |

### State namespace

`hm_` prefix (`hm_key`, `hm_message`, `hm_mac_hex`, `hm_verify_result`, `hm_tampered`).

### Template changes

`core/templates/core/lesson.html` gets:
- A slug-keyed branch for `length-extension` (the two-panel attack widget).
- A slug-keyed branch shared by `compute-hmac` and `verify-and-tamper` (key + message + verify panel; verify region gated by step slug).

## Data flow

```
Step 1, 2 (info)              no input. state empty.
Step 3 (length-extension)     info + widget. Widget reads a hardcoded
                              demo key+message from the template; user
                              clicks Run-Attack; widget displays a forged
                              MAC. Nothing written to persisted state.

Step 4 (hmac-construction)    info. state unchanged.

Step 5 (compute-hmac)         input: key + message
  ↓ compute_hmac validator (async, Web Crypto)
state += { hm_key, hm_message, hm_mac_hex }

Step 6 (verify-and-tamper)    input: action + possibly-edited message
  ↓ verify_hmac validator (async, Web Crypto, recomputes)
state += { hm_verify_result, hm_tampered }

Step 7 (done)                 info. Recap uses hm_key + hm_message + hm_mac_hex
                              to render the codegen script body.
```

## Error handling

### Step 5 — `compute_hmac`
- Empty key → `"Type a secret key. Any non-empty string works for the demo."`
- Empty message → `"Type a message to MAC."`
- Non-ASCII or >500 chars → `"Keep key and message under 500 printable ASCII characters."`
- Web Crypto error → `"HMAC computation failed. This step requires a modern browser with Web Crypto."`

### Step 6 — `verify_hmac`
- Missing `hm_key`/`hm_mac_hex` in state (user jumped here) → `"Complete step 5 first — we need a key and MAC to verify against."`
- Unknown action → `"Click Verify or Tamper."`
- Web Crypto error → `"Verification failed to run; refresh and retry."`

### Step 3 — length-extension widget
- No validator; widget is pure display + state-free interaction. If `crypto.subtle.digest` throws, the panel shows "This demo requires Web Crypto."

## Testing

### JS validator tests
- `compute_hmac` happy path (mock `crypto.subtle` or skip in Node — same pattern as AES tests).
- `compute_hmac` empty / oversized / non-ASCII rejections.
- `verify_hmac` rejects when state lacks `hm_key` / `hm_mac_hex`.
- `verify_hmac` returns true for unchanged message, false after tamper (Playwright-side, not Node).

### JS codegen tests
- `full_script({hm_key: "k", hm_message: "m", hm_mac_hex: "..."})` contains `import hmac`, `import hashlib`, `hmac.new(`, `hashlib.sha256`, the message literal, and a tamper-fails assertion.

### Fixture-load test
- Extend `core/tests/test_fixtures.py`.

### Manual smoke
- Walk all 7 steps. Step 3: click "Run attack", confirm forged MAC verifies on server panel. Step 5: enter key+message, see hex. Step 6: verify clean (valid), tamper one char (invalid).

## Files touched

| File | Change |
|---|---|
| `algorithms/hmac/fixtures.json` | CREATE |
| `static/algorithms/hmac/validators.js` | CREATE |
| `static/algorithms/hmac/codegen.js` | CREATE |
| `static/algorithms/hmac/length_extension_sim.js` | CREATE |
| `static/algorithms/hmac/tests/validators.test.js` | CREATE |
| `static/algorithms/hmac/tests/codegen.test.js` | CREATE |
| `core/templates/core/lesson.html` | MODIFY — slug-keyed branches for `length-extension` and shared `compute-hmac` / `verify-and-tamper` |
| `core/tests/test_fixtures.py` | MODIFY (extend) |

No model or migration changes — `hash` family is added by the SHA-256 spec.

## Open questions / deferred

- **Length-extension widget: real vs simulated.** Two options.
  - (a) **Real attack** — ship a hand-rolled JS SHA-256 we can stop mid-compression to recover and resume from the chaining state. Heavy (~300 lines of careful crypto code), but pedagogically honest.
  - (b) **Simulated** — wizard secretly knows the key; "attack" computes the real extended hash with the key. Light, but the attacker-view narration is a lie.
  - **Recommendation: (b)**, with explicit lesson copy on step 3 disclosing the simplification ("In a real attack you wouldn't need the key — we're showing you the *outcome* because the browser's SHA-256 doesn't expose the chaining state a real exploit needs. Curious? See [external write-up].") The pedagogical payoff (felt impact of the forgery) lands either way; (a) is a budget sink for ~95% of learners who'd believe the demo anyway.
- **Timing-attack sidebar on step 6.** Recommend a `help_template` block explaining that `==` on MACs leaks information via early-exit comparisons, and that production code should use `hmac.compare_digest` / `crypto.subtle.timingSafeEqual` etc. Short — ~80 words — not a full step.
- **JWT example in step 1 intro_template.** The 200-char limit on `Algorithm.intro_template` is tight. Draft: "MACs prove a message came from someone with the shared key. HMAC is the standard MAC, used by TLS, JWT, AWS SigV4, and webhook signatures." (~165 chars, fits.)
- **Step 3 widget UI polish.** Specced as a side-by-side panel with one button; if it feels crowded a future iteration could add a "step through the attack" expandable trace. Out of scope for v1.
- **Persisting step 3 widget state.** None planned — the widget is exploratory and writes nothing to `state`. If we later want to gate progress on "user clicked the attack button," add a trivial `length_extension_seen` validator.
