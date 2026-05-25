# Padding Oracle Attack Lesson — Design

**Date:** 2026-05-25
**Project:** `cloak`
**Working directory:** /Users/hriday/code/enc_algo

## Goal

Teach the **padding oracle attack** as a 7-step lesson that turns "PKCS7 padding seems harmless" into "padding leaks the whole plaintext." This is the site's first dedicated *attack* lesson — every prior lesson taught a primitive; this one mounts an attack against a simulated AES-CBC server that distinguishes "bad padding" from "internal error." Through ~256 chosen-ciphertext queries per byte, the user decrypts a full ciphertext **without ever knowing the key**.

The lesson is pedagogically the most memorable on the site: it shows how a *single bit of side-channel information* (padding valid vs not) cascades into full plaintext recovery. References Vaudenay (Eurocrypt 2002), BEAST (2011), and Lucky 13 (2013) as real-world incarnations and motivates the industry's shift to AEAD modes (GCM, ChaCha20-Poly1305).

## Curriculum position

1. RSA ✅
2. Hybrid Encryption ✅
3. AES ✅
4. Triple DES (designed)
5. Blowfish (designed)
6. Twofish (designed)
7. HSM (designed)
8. X25519 (designed)
9. Ed25519 (future)
10. **Padding Oracle Attack** (this design)
11. Kyber / ML-KEM (future)
12. Caesar / Vigenère (future)

Pedagogically: comes after AES so learners already understand CBC mode, IVs, and PKCS7 padding. Naturally pairs with a future "cipher modes deep dive" and an eventual Bleichenbacher (RSA PKCS#1 v1.5) lesson — same attack flavor, different primitive.

## Non-goals

- Real network timing attacks (Lucky 13's compress-the-MAC-check side channel). Mentioned, not exploited — the in-browser simulator returns explicit `"bad_padding"` / `"internal_error"` strings.
- Multi-block attacks beyond a single block. The attack on block N is architecturally identical to block 1; the lesson decrypts a single 16-byte block to keep the visualization legible.
- BEAST (CBC predictable-IV chosen-plaintext attack on TLS 1.0). Different attack, mentioned only.
- Bleichenbacher's RSA PKCS#1 v1.5 padding-oracle attack. Same flavor, different primitive — deferred to its own lesson.
- Full Vaudenay paper walk. The lesson teaches the core trick (CBC bit-flipping into PKCS7 validation) and skips the formal analysis.
- A real network oracle. Everything happens in-browser against a simulated server.

## User experience

The lesson lives at `/algorithms/padding-oracle/learn/decrypt-without-the-key/`. Padding Oracle appears as a new card on the landing page. `family: symmetric` — it's an attack *on* a symmetric mode; reusing the existing family value avoids a model change. (Considered adding an `attacks` family; see open questions.)

### Step sequence

| # | Slug | Kind | Behavior |
|---|---|---|---|
| 1 | `intro` | `info` | The scenario: an AES-CBC server decrypts incoming ciphertexts. If padding is malformed, it returns `"bad padding"`; if the MAC fails, `"bad MAC"`; if everything passes, the request is processed. The attacker can distinguish those responses (or learn them via timing). That's the entire oracle. Names the attack — Vaudenay (Eurocrypt 2002) — and the real-world incarnations: BEAST (2011), Lucky 13 (2013), POODLE (2014, SSLv3). |
| 2 | `pkcs7-recap` | `info` | PKCS7 padding rules. To pad N bytes (1–16), append N copies of the byte `N`. To unpad, read the last byte and remove that many. Validation: every padding byte must equal the count. Worked examples: `"hi"` (14 bytes pad → 14 copies of `0x0E`), `"abc..."` of length 16 (full block of `0x10`). The validation rule is the load-bearing detail for the next step. |
| 3 | `bit-flipping` | `info` | The CBC bit-flipping property. Plaintext block N is `P_n = D(C_n) XOR C_{n-1}`. The decryption result `D(C_n)` is fixed by the key, but the attacker fully controls `C_{n-1}`. Flipping bit X of `C_{n-1}` flips bit X of `P_n`. Worked example: choose any `C'_{n-1}`, the resulting plaintext is `D(C_n) XOR C'_{n-1}`. Sets up the attack: if the attacker can force the last byte of the decrypted plaintext to equal `0x01`, the padding check passes, and they've learned one byte of `D(C_n)`. |
| 4 | `attack-one-byte` | `input-text` (button-driven) | **THE INTERACTIVE STEP.** Page presents a simulated oracle (Web Crypto AES-CBC + a PKCS7 validator in JS) holding a fixed key + a fixed two-block ciphertext `IV || C_1`. User goal: recover the **last byte** of plaintext block 1. Page has a "Run attack" button that auto-iterates the 256 candidate values for the last byte of a *forged* IV, sends each to the oracle, and watches for the one response that isn't `"bad_padding"`. Live counter: `"Query 47 of 256... candidate byte = 0x6c"`. On hit, the page derives the actual plaintext byte from the forged IV and the known target byte (`0x01`). Validator runs the demo and writes `{po_recovered_byte_hex, po_queries_made, po_target_block_hex}`. |
| 5 | `attack-full-block` | `info` (with widget) | Extend to the whole block. Once you have the last byte, force the last byte of the plaintext to `0x02` (XOR the forged IV byte appropriately), then iterate the *second-to-last* byte's 256 candidates looking for valid `0x02 0x02` padding. Repeat with `0x03 0x03 0x03`, then `0x04 0x04 0x04 0x04`, etc. 16 bytes × 256 queries ≈ 4096 queries to decrypt one block. Page auto-runs the full-block attack and reveals plaintext bytes one-by-one (animated; Alpine + setTimeout). Caption: "no key, no problem." |
| 6 | `defenses` | `info` | How the industry recovered. **Encrypt-then-MAC** instead of MAC-then-encrypt (TLS 1.0–1.1 did the wrong order: decrypt → unpad → check MAC, which exposes the padding oracle before the MAC check fires). **AEAD modes** — GCM, ChaCha20-Poly1305 — combine encryption and authentication so any ciphertext tampering is caught *before* decryption produces any observable side channel. Constant-time padding validation as a stopgap (Lucky 13's mitigation in TLS 1.0/1.1). The fix the industry settled on: AEAD, full stop. |
| 7 | `done` | `info` | Recap. Codegen renders a Python script with **both** the vulnerable mock server (CBC + naive padding check) **and** a simplified attack that decrypts a sample ciphertext via the mock oracle. Comments warn: for learning only, never deploy unauthenticated CBC. Forward-links: cipher-modes lesson (when it exists), AES-GCM as the defense, Bleichenbacher (RSA PKCS#1 v1.5) as the same trick on a different primitive. |

### Step 4 in detail — `attack-one-byte`

Page state on enter:

1. The static module's `po_simulator.js` has, baked in: a fixed 16-byte AES key `K`, a fixed two-block plaintext (e.g., `"attack at dawn!!"` — exactly 16 bytes, padded with one block of `0x10` to keep things clean), and the resulting ciphertext `IV || C_1`.
2. Page exposes `oracle.query(iv, c)` → `"bad_padding" | "ok" | "internal_error"`. Implementation: AES-CBC decrypt with `K`, then run a strict PKCS7 validator. `"ok"` only fires when both the padding is valid AND the resulting plaintext starts with a particular fixed sentinel (so the attacker can't just see `"ok"` on every padding-valid result — they have to distinguish `"bad_padding"` from everything else, which is the real attack model).
3. Page shows: the ciphertext as hex, the goal ("recover the last byte of plaintext block 1"), and a "Run attack" button.

On click:

1. For `candidate = 0x00` to `0xFF`: build a forged `IV'` that is the real IV with its last byte replaced by `candidate`. Call `oracle.query(IV', C_1)`. Display a live counter.
2. When the oracle returns anything other than `"bad_padding"`, that means the decrypted plaintext's last byte was a valid padding value — most likely `0x01`. Derived plaintext byte: `P_last = D(C_1)_last XOR IV_last = (candidate XOR 0x01) XOR IV_real_last`. (Derivation: `D(C_1)_last = candidate XOR 0x01`, and `P_real_last = D(C_1)_last XOR IV_real_last`.)
3. Edge case: `candidate` might cause `0x02 0x02` (false positive — last two bytes both decrypt to 2). Handled by *also* perturbing the second-to-last byte of the forged IV and re-querying; if response is still not `"bad_padding"`, the byte is `0x01`. Two-query confirmation. Mentioned in the prompt.
4. Reveal the recovered byte; populate state.

Validator `recover_byte`: confirms the page-side attack ran to completion and writes the result to state. No "correct answer" the user types — the page is the demo.

### Step 5 in detail — `attack-full-block`

The widget calls a `po_attacker.runFullBlockAttack(ciphertext)` function from the static module. The function loops byte index `i` from 15 down to 0; for each `i`, target padding length is `16 - i`; iterate 256 candidates; when a valid response comes back, derive the plaintext byte and update the displayed plaintext (`???????????????c` → `??????????????nc` → ...). Animation paces each byte at ~150ms after the (synchronous) attack completes; the entire visualization runs to completion in ~3 seconds. The actual oracle queries (~4096 of them) run in a tight loop because the simulator is in-process — no real network.

Final state shown: `"attack at dawn!!"` revealed in plain text, plus a counter `Total queries: 3847` (slightly under 4096 due to the early-exit on each byte).

## Architecture

### New algorithm record

`algorithms/padding-oracle/fixtures.json`. Algorithm PK 14, slug `padding-oracle`, name `Padding Oracle Attack`, family `symmetric`. Lesson PK 14, slug `decrypt-without-the-key`, title `"Padding oracle: decrypt without the key"`. Steps PKs 141–147.

### New algorithm module directory

`static/algorithms/padding-oracle/`:

| File | Responsibility |
|---|---|
| `validators.js` | `recover_byte`, `info`, walkthrough hints. |
| `codegen.js` | `full_script` emits Python: mock vulnerable server + simplified attack script. |
| `po_simulator.js` | Holds the fixed AES key + ciphertext. Exports `oracle.query(iv, ct_block)` → response string. Web Crypto AES-CBC under the hood. |
| `po_attacker.js` | The attack orchestration: `runByteAttack()` and `runFullBlockAttack()`. Emits progress events (counter, candidate, current plaintext) for the Alpine widget to consume. |
| `tests/*.test.js` | Validator + codegen + simulator tests. |

### Validators

| Key | Validates | Writes |
|---|---|---|
| `recover_byte` | confirms the page's byte-recovery demo ran and produced a result | `{po_recovered_byte_hex, po_queries_made, po_target_block_hex}` |
| `info` | always ok | `{}` |

### State namespace

`po_` prefix.

## Data flow

```
Step 1, 2, 3 (info)        no input. state empty.

Step 4 (attack-one-byte)   side effect: on "Run attack" click, po_attacker
                           runs ~256 oracle queries against po_simulator.
                           input: implicit (button click completes the demo)
  ↓ recover_byte validator
state += { po_recovered_byte_hex, po_queries_made, po_target_block_hex }

Step 5 (attack-full-block) side effect: full-block attack runs (~4096 queries),
                           animated reveal. No new state writes; consumes
                           po_target_block_hex from step 4.

Step 6 (defenses)          info. no input.

Step 7 (done)              info. Codegen uses po_target_block_hex (and the
                           known mock plaintext) in the final Python script.
```

## Codegen

Final `full_script` (step 7) target:

```python
"""
Padding-oracle attack demo. For learning only — never deploy unauthenticated CBC.
The "server" here is a function in this file; in the real Vaudenay attack,
it's a network endpoint that distinguishes "bad padding" from other errors.
"""
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY = bytes.fromhex("00112233445566778899aabbccddeeff")
IV  = bytes.fromhex("0f0e0d0c0b0a09080706050403020100")

def encrypt(pt: bytes) -> bytes:
    pad = 16 - (len(pt) % 16)
    pt_padded = pt + bytes([pad] * pad)
    c = Cipher(algorithms.AES(KEY), modes.CBC(IV)).encryptor()
    return c.update(pt_padded) + c.finalize()

def decrypt_or_error(iv: bytes, ct: bytes) -> str:
    """The vulnerable oracle. Returns 'bad_padding' or 'ok'."""
    d = Cipher(algorithms.AES(KEY), modes.CBC(iv)).decryptor()
    pt = d.update(ct) + d.finalize()
    pad = pt[-1]
    if pad < 1 or pad > 16 or pt[-pad:] != bytes([pad]) * pad:
        return "bad_padding"
    return "ok"

def attack_last_byte(iv: bytes, ct_block: bytes) -> int:
    """Recover the last plaintext byte using ~256 oracle queries."""
    for candidate in range(256):
        forged_iv = iv[:15] + bytes([candidate])
        if decrypt_or_error(forged_iv, ct_block) == "ok":
            # D(ct_block)[-1] = candidate XOR 0x01
            # plaintext[-1]   = D(ct_block)[-1] XOR iv[-1]
            return (candidate ^ 0x01) ^ iv[-1]
    raise RuntimeError("no valid padding found")

if __name__ == "__main__":
    ct = encrypt(b"attack at dawn!!")
    recovered = attack_last_byte(IV, ct[:16])
    print(f"Recovered last byte: {recovered:#04x} = {chr(recovered)!r}")
```

The codegen module emits this script with the live `po_target_block_hex` value from state inlined as a comment so the script the learner downloads cross-references the page they saw. A full-block attack function is also included with comments noting the inductive step (extend last-byte logic to bytes N-2, N-3, ...).

## Error handling

### Step 4 — `recover_byte`
- Page hasn't run the attack yet → `"Click 'Run attack' to launch the 256-query byte recovery."`
- Attack ran but didn't find a non-`bad_padding` response (impossible with correct simulator config — defensive only) → `"Oracle returned bad_padding for all 256 candidates. Refresh and retry."`
- Web Crypto unavailable → `"This step needs a modern browser with Web Crypto. Try Chrome / Firefox / Safari."`

### Step 5 — widget (non-blocking)
- If the auto-attack fails mid-stream, show a red banner and stop the animation. State already populated from step 4 so the lesson can still advance via the standard "next" affordance.

## Template branches

Steps 4 and 5 need lesson-template additions. Steps 1, 2, 3, 6, 7 are plain `info` and reuse the existing template.

- **Step 4 (`attack-one-byte`)** — partial `partials/step_padding_oracle_byte.html`. Renders: ciphertext hex blob, "Run attack" button, live query counter, candidate byte under test, final recovered byte. Alpine component `paddingOracleBytePanel` wired to `static/algorithms/padding-oracle/po_attacker.js`.
- **Step 5 (`attack-full-block`)** — partial `partials/step_padding_oracle_block.html`. Renders: target ciphertext block, plaintext skeleton (`????????????????`) that fills in as bytes recover, total-query counter, final recovered plaintext. Same Alpine component family; uses setTimeout pacing for the byte-reveal animation.

Mechanism mirrors the X25519 `step_exchange.html` pattern: per-step partial selected via a small switch in `lesson.html`. No model change.

## Testing

### JS validator tests
- `recover_byte` happy (panel reports success + non-empty hex) and rejections (panel hasn't run; missing hex).

### JS simulator tests
- `oracle.query(real_iv, real_ct)` returns `"ok"`.
- `oracle.query(bad_iv, real_ct)` returns `"bad_padding"` for most random IVs (statistical check: ≥240 of 256 random last-byte perturbations return `"bad_padding"`; the rare exceptions are valid-padding false positives).

### JS attacker tests
- `runByteAttack` against the simulator recovers the known plaintext last byte (`"!"` = `0x21`).
- `runFullBlockAttack` recovers the full known plaintext (`"attack at dawn!!"`).
- Query counter is bounded above by 256 × 16 = 4096 and above 256 × 16 × 0.9 = ~3686 (typical).

### JS codegen tests
- `full_script({po_target_block_hex: "..."})` contains `algorithms.AES`, `modes.CBC`, `decrypt_or_error`, `attack_last_byte`, and the target hex literal.

### Fixture-load test
- Extend `core/tests/test_fixtures.py` to assert 1 Algorithm + 1 Lesson + 7 Step rows with the expected slugs and orders.

### Manual smoke
- Walk all 7 steps in Chrome. Step 4: confirm counter animates 0 → 256 in well under a second, recovered byte matches `"!"` (0x21). Step 5: confirm full plaintext reveals one byte at a time and final string is `"attack at dawn!!"`. Verify the downloaded Python script runs in a venv with `cryptography` installed and prints the expected recovered byte.

## Files touched

| File | Change |
|---|---|
| `algorithms/padding-oracle/fixtures.json` | CREATE |
| `static/algorithms/padding-oracle/validators.js` | CREATE |
| `static/algorithms/padding-oracle/codegen.js` | CREATE |
| `static/algorithms/padding-oracle/po_simulator.js` | CREATE |
| `static/algorithms/padding-oracle/po_attacker.js` | CREATE |
| `static/algorithms/padding-oracle/tests/validators.test.js` | CREATE |
| `static/algorithms/padding-oracle/tests/simulator.test.js` | CREATE |
| `static/algorithms/padding-oracle/tests/attacker.test.js` | CREATE |
| `static/algorithms/padding-oracle/tests/codegen.test.js` | CREATE |
| `core/templates/core/partials/step_padding_oracle_byte.html` | CREATE |
| `core/templates/core/partials/step_padding_oracle_block.html` | CREATE |
| `core/templates/core/lesson.html` | MODIFY (route to new partials by step slug) |
| `core/tests/test_fixtures.py` | MODIFY (extend) |

No `core/models.py` change. `family: symmetric` reuses the existing choice; `kind: input-text` for step 4 reuses the existing kind (the button-driven UX lives in the partial, not the model).

## Open questions / deferred

- **Attack pacing.** Recommended: **auto-run with a visible counter** (`"Query 47 of 256... candidate byte = 0x6c"`) at ~5ms per query so 256 queries finish in roughly 1.3 seconds. The user sees the attack happen but isn't asked to click 256 buttons. Step-by-step pacing was considered and rejected — it makes the attack feel artificial. The Alpine pattern: a `requestAnimationFrame` loop that issues one query per frame and updates the visible counter, then on completion fires the validator. For step 5's full-block attack, the same approach but with a slower per-byte reveal (~150ms post-query pause) so the recovered plaintext appears legibly one byte at a time.
- **Early exit per byte.** Faithful Vaudenay attack queries up to 256 candidates per byte but can exit as soon as the oracle returns anything other than `"bad_padding"`. The simulator + attacker honor this — average queries per byte is ~128, so the full-block attack finishes in ~2048 queries on average rather than the worst-case 4096. Counter shows the actual number, not the worst case.
- **`attacks` family.** Considered adding `("attacks", "Attacks")` to `Algorithm.FAMILY_CHOICES` since this is structurally an attack, not an algorithm. **Recommendation: don't add it for v1.** Padding oracle is reasonably classified as a symmetric-mode topic; a separate `attacks` family is only worth introducing once a second attack lesson lands (Bleichenbacher would be the natural second, at which point we revisit). Reviewer (Hriday) can override in the morning.
- **`0x02 0x02` false positive in step 4.** The single-byte demo uses two-query confirmation (perturb the second-to-last forged-IV byte and re-query) to disambiguate. Mentioned in the step-4 prompt; not made the user's problem. The full-block attack in step 5 needs the same handling — already baked into `po_attacker.js`.
- **Realistic timing side channel.** Out of scope. Lucky 13 is the canonical timing-based padding oracle (the MAC-then-encrypt order in TLS 1.0/1.1 made the timing of the MAC check correlate with padding length). A future "timing attacks" lesson could revisit this; today's lesson stays with explicit `"bad_padding"` responses for clarity.
- **AEAD as the recap closer.** Step 6 mentions GCM and ChaCha20-Poly1305 as the fix; if a dedicated AEAD lesson lands later, this step gets a forward-link. For now the recap stops at "use authenticated encryption."
