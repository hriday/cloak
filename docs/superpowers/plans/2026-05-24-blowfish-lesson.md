# Blowfish Lesson — Implementation Plan

> Use superpowers:subagent-driven-development.

**Goal:** 6-step Blowfish lesson — Feistel structure overview + F-function single-round walkthrough + Python codegen.

**Architecture:** New `algorithms/blowfish/` + `static/algorithms/blowfish/`. No browser-side encryption (no Web Crypto for Blowfish). Python codegen via `cryptography.hazmat.primitives.ciphers.algorithms.Blowfish`. Spec: `docs/superpowers/specs/2026-05-24-blowfish-lesson-design.md`.

---

## Task 1: Validators + walkthroughs

**Files:** `static/algorithms/blowfish/validators.js` + `tests/validators.test.js`

- [ ] Create directory: `mkdir -p /Users/hriday/code/enc_algo/static/algorithms/blowfish/tests`
- [ ] `f_function` validator: parses hex or decimal 32-bit value, checks equals `0xD7F08FBE`. Wrong-value hint walks through the math.
- [ ] `pick_blowfish_message`: standard `pick_sentence`-style.
- [ ] `info`: pass-through.
- [ ] `walkthroughs.f_function` (3 rungs): method → walked example with all 4 S-box values → answer `0xD7F08FBE`.
- [ ] Tests for happy/wrong/edge cases.
- [ ] Commit `feat(blowfish): validators + walkthroughs`.

## Task 2: Codegen

**Files:** `static/algorithms/blowfish/codegen.js` + `tests/codegen.test.js`

- [ ] `full_script(state)` emits Python: `from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes; algorithms.Blowfish(key); ...` with CBC mode + PKCS7 padding.
- [ ] Per-step stubs return `""`.
- [ ] Tests for the Blowfish import + roundtrip assert in output.
- [ ] Commit `feat(blowfish): codegen.js`.

## Task 3: Fixtures + fixture-load test

**Files:** `algorithms/blowfish/fixtures.json` + extend `core/tests/test_fixtures.py`

- [ ] Algorithm pk=6, lesson pk=6, steps pks=61-66.
- [ ] intro_template under 200 chars.
- [ ] Slugs: `intro, feistel-structure, f-function, one-round, encrypt-a-message, done`.
- [ ] Step 3 prompt includes the 4 S-box values verbatim (`0xD7CABA51`, `0x4BCA8A93`, `0x9A3FE5C1`, `0x1E45EE99`).
- [ ] Step 4 displays `state.bf_f_output` to confirm what the user just computed.
- [ ] Run loaddata; verify 8 objects installed.
- [ ] Append `test_blowfish_fixture_loads` to `test_fixtures.py`.
- [ ] Commit `feat(blowfish): fixtures + fixture-load test`.

## Task 4: Manual smoke

- [ ] Visit `/algorithms/blowfish/learn/feistel-rounds/`.
- [ ] Walk all 6 steps; F-function step accepts both `0xD7F08FBE` and `3623849918`.
- [ ] Fix any issues.

## Verification

- [ ] All tests green.
- [ ] Blowfish card on landing.
- [ ] Lesson walks end-to-end.
