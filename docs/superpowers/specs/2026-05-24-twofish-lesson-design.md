# Twofish Lesson — Design

**Date:** 2026-05-24
**Project:** `cloak`
**Working directory:** /Users/hriday/code/enc_algo

## Goal

Teach Twofish as a 6-step **comparison lesson** that frames Twofish against AES (both were AES competition finalists; AES won), introduces the design choices that distinguish them (Feistel-like vs SP-network, key-dependent vs fixed S-boxes, whitening), and ends with a Python codegen using `pycryptodome`'s Twofish implementation (`cryptography.hazmat` doesn't ship it).

This is the lightest-interactivity lesson in the symmetric-cipher track. There's no compute-along for the cipher itself — the algorithm is too complex (16 Feistel-like rounds, MDS matrix, PHT, whitening). Instead the lesson teaches the *architectural ideas* Twofish brought to the competition and the reasons AES (Rijndael) was chosen over it.

## Curriculum position

1. RSA ✅
2. Hybrid Encryption ✅
3. AES ✅
4. Triple DES (designed)
5. Blowfish (designed)
6. **Twofish** (this design)
7. HSM (designed)
8. Caesar / Vigenère (future)

Twofish is taught AFTER AES (so learners have AES as the reference) and AFTER Blowfish (so the "Schneier wrote both" lineage makes sense).

## Non-goals

- Walking the 16 Twofish rounds by hand.
- Implementing the MDS (Maximum Distance Separable) matrix in JS.
- Pseudo-Hadamard Transform (PHT) walkthrough.
- Key-dependent S-box derivation (it depends on the key schedule, which depends on a complex Reed-Solomon code).
- Whitening key derivation.
- A full performance benchmark vs AES.
- Why AES won (Rijndael's simpler key schedule, better hardware fit) — mentioned briefly but not deeply argued.

## User experience

The lesson lives at `/algorithms/twofish/learn/aes-finalist/`. Twofish appears as a new card on the landing page. `family: symmetric`.

### Step sequence

| # | Slug | Kind | Behavior |
|---|---|---|---|
| 1 | `intro` | `info` | Twofish history: 1998, Schneier + Kelsey + Whiting + Wagner + Hall + Ferguson. Submitted to the AES competition; one of the 5 finalists (with Rijndael, MARS, RC6, Serpent). Rijndael won; Twofish is still respected, used in some VPN / disk encryption tools. |
| 2 | `vs-aes` | `info` | Side-by-side architecture comparison: |
| | | | • Block size: AES 128, Twofish 128 — tie. |
| | | | • Key size: AES 128/192/256, Twofish 128/192/256 — tie. |
| | | | • Round structure: AES SP-network, Twofish Feistel-like. |
| | | | • S-boxes: AES fixed (FIPS 197 table), Twofish key-dependent. |
| | | | • Rounds: AES 10/12/14 (key-dependent), Twofish 16 (fixed). |
| | | | • Diffusion: AES MixColumns + ShiftRows, Twofish MDS matrix + PHT. |
| | | | • Whitening: AES no, Twofish yes (XOR with extra keys before round 1 and after round 16). |
| 3 | `key-dependent-sboxes` | `info` | What "key-dependent S-boxes" means: instead of a single fixed substitution table, the S-box content is derived from the key. Slower to compute (key schedule is heavier), harder to attack with precomputed tables. Pedagogical example: lesson shows 4 example bytes from a derived S-box, contrasted with AES's fixed bytes for the same inputs. |
| 4 | `whitening` | `input-numeric` | Whitening = XOR input bytes with extra round keys before round 1 (and similarly at the output). The user computes one whitening step: input byte XOR whitening byte. Shows the same XOR pattern they've seen in AES AddRoundKey. |
| 5 | `encrypt-a-message` | `input-text` | User types a message. Codegen renders a Python script using `pycryptodome`'s `Crypto.Cipher.Twofish`. (Requires `pip install pycryptodome` — script comment notes this.) |
| 6 | `done` | `info` | Recap + back-links + a note on why AES was chosen over Twofish (simpler key schedule, better hardware support, broader implementation availability). |

### Step 4 in detail

```
Compute whitening on input byte 0x6A with whitening byte 0x35.

Answer: 0x6A XOR 0x35 = 0x5F
```

Same shape as the AES AddRoundKey step but framed in Twofish terms. Reinforces transferable knowledge.

## Architecture

### Dependency addition

`requirements.txt` adds `pycryptodome>=3.20` — Twofish is in this package, not in `cryptography.hazmat`. Adds ~3MB to the Docker image. Acceptable.

### New algorithm record

`algorithms/twofish/fixtures.json`. PK 7. Lesson PK 7. Steps PKs 71-76.

### New algorithm module directory

`static/algorithms/twofish/`:

| File | Responsibility |
|---|---|
| `validators.js` | `whitening` validator + `pick_twofish_message` + `info` + walkthroughs. |
| `codegen.js` | `full_script` emits Python using `Crypto.Cipher.Twofish`. |
| `tests/*.test.js` | Validator + codegen tests. |

### Validators

| Key | Validates | Writes |
|---|---|---|
| `whitening` | parses byte (decimal or hex), equals 0x5F | `{tf_w_input, tf_w_output}` |
| `pick_twofish_message` | non-empty, ≤500 chars, printable ASCII | `{tf_message}` |
| `info` | always ok | `{}` |

(The `whitening` validator can reuse the byte-parsing pattern from AES's `sub_byte` — same lookup of hex / decimal / bare hex.)

### State namespace

`tf_` prefix.

## Data flow

```
Step 1-3 (info)         no input. state empty.
Step 4 (whitening)      input: byte
  ↓ whitening validator
state += { tf_w_input: 0x6A, tf_w_output: 0x5F }

Step 5 (encrypt)        input: text
  ↓ pick_twofish_message
state += { tf_message }

Step 6 (done)           info.
```

## Error handling

### Step 4 — `whitening`
- Standard byte-parse errors (same as AES sub_byte).
- Wrong value → `"Whitening is byte-wise XOR. With input byte = 0x6A (106) and whitening byte = 0x35 (53), compute 0x6A XOR 0x35 = 0x5F (95)."`

### Step 5 — `pick_twofish_message`
- Standard `pick_sentence`-style.

## Testing

### JS validator tests
- `whitening` happy / wrong / out of range.
- `pick_twofish_message` standard.

### JS codegen tests
- `full_script({tf_message: "hi"})` contains `from Crypto.Cipher import Twofish`, the message literal, and an assertion.

### Fixture-load test
- Extend test_fixtures.py.

### Manual smoke
- Walk all 6 steps; verify whitening accepts hex + decimal.

## Files touched

| File | Change |
|---|---|
| `algorithms/twofish/fixtures.json` | CREATE |
| `static/algorithms/twofish/validators.js` | CREATE |
| `static/algorithms/twofish/codegen.js` | CREATE |
| `static/algorithms/twofish/tests/validators.test.js` | CREATE |
| `static/algorithms/twofish/tests/codegen.test.js` | CREATE |
| `requirements.txt` | MODIFY — add `pycryptodome>=3.20` |
| `core/tests/test_fixtures.py` | MODIFY (extend) |

No changes to wizard.js or lesson.html (no new template branches; step 2's comparison table fits in the prompt markdown).

## Open questions / deferred

- **Should we add a side-by-side diagram for step 2?** Specs leaves it as a markdown table inside the prompt. A real visual would be nicer but is a polish item.
- **Show actual key-dependent S-box derivation?** Could write the Reed-Solomon code in JS (~100 LOC) and let users see real derived S-boxes for their chosen key. Adds depth at cost of complexity. Deferred.
- **`pycryptodome` dependency** — adds ~3 MB to the Docker image. Reasonable for one extra algorithm. Worth a note in `docs/deploy.md` if it ever causes build issues.
